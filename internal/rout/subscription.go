package rout

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Subscriptions: independent, token-protected Base64 share-link lists built from nodes the
// administrator selected by hand. A subscription stores only stable node IDs and the hash of
// its token; links are generated per request from the current state (see subscription_server.go).

const (
	maxSubscriptions     = 100
	maxSubscriptionNodes = 200
	subscriptionTokenLen = 32 // bytes of entropy; 43 base64url characters
)

type Subscription struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Ordered selection of node IDs. Never expanded automatically.
	NodeIDs []string `json:"node_ids"`
	// Authentication uses only this hash. An optional CLI token copy lives in a
	// separate private file, never in State or its backups.
	TokenHash string    `json:"token_hash"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	// Optional shared traffic allowance, reset day and expiry shown to clients.
	// Absent for subscriptions that never configured one, so their output is unchanged.
	Plan *SubscriptionPlan `json:"plan,omitempty"`
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var tokenHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s Subscription) clone() Subscription {
	s.NodeIDs = append([]string(nil), s.NodeIDs...)
	if s.Plan != nil {
		plan := *s.Plan
		s.Plan = &plan
	}
	return s
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// newSubscriptionToken returns a fresh token and its stored hash.
func newSubscriptionToken() (token, hash string, err error) {
	b := make([]byte, subscriptionTokenLen)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

func validSubscriptionName(name string) error {
	if strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 80 || strings.ContainsAny(name, "\r\n\x00\t") {
		return errors.New("订阅名称无效（1–80 个字符，不含换行）")
	}
	return nil
}

func (s State) validateSubscriptions() error {
	if len(s.Subscriptions) > maxSubscriptions {
		return errors.New("订阅数量过多")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, sub := range s.Subscriptions {
		if !idPattern.MatchString(sub.ID) || ids[sub.ID] {
			return errors.New("订阅 ID 无效或重复")
		}
		ids[sub.ID] = true
		if e := validSubscriptionName(sub.Name); e != nil {
			return e
		}
		key := strings.ToLower(strings.TrimSpace(sub.Name))
		if names[key] {
			return errors.New("订阅名称重复")
		}
		names[key] = true
		if !tokenHashPattern.MatchString(sub.TokenHash) {
			return errors.New("订阅令牌校验值无效")
		}
		if len(sub.NodeIDs) > maxSubscriptionNodes {
			return errors.New("订阅包含的节点过多")
		}
		if sub.Plan != nil {
			if e := sub.Plan.Validate(); e != nil {
				return e
			}
			if sub.Plan.LimitBytes > 0 && s.Schema != 2 {
				return errors.New("有限额配置必须使用保护版本，不能降级绕过限额")
			}
		}
		seen := map[string]bool{}
		for _, id := range sub.NodeIDs {
			if !idPattern.MatchString(id) || seen[id] {
				return errors.New("订阅节点列表无效或重复")
			}
			seen[id] = true
		}
	}
	return nil
}

// matchSubscription authenticates a token. Every stored hash is compared in constant time
// and the loop never exits early, so timing does not reveal which subscription was close.
func (s State) matchSubscription(token string) (Subscription, bool) {
	if !tokenPattern.MatchString(token) {
		return Subscription{}, false
	}
	want := hashToken(token)
	var found Subscription
	ok := 0
	for _, sub := range s.Subscriptions {
		if subtle.ConstantTimeCompare([]byte(sub.TokenHash), []byte(want)) == 1 {
			found = sub
			ok = 1
		}
	}
	return found, ok == 1
}

// SubscriptionExport is the result of resolving a subscription against the current state.
type SubscriptionExport struct {
	URIs     []string // valid links in the saved order
	Warnings []string // diagnostics; never contain links or credentials
}

// exportSubscription resolves node IDs against the current profiles. Deleted, disabled and
// link-less entries are left out with a warning. Links come from Profile.URI() only.
func (s State) exportSubscription(sub Subscription) SubscriptionExport {
	var out SubscriptionExport
	byID := make(map[string]Profile, len(s.Profiles))
	for _, p := range s.Profiles {
		byID[p.ID] = p
	}
	for _, id := range sub.NodeIDs {
		p, ok := byID[id]
		switch {
		case !ok:
			out.Warnings = append(out.Warnings, fmt.Sprintf("节点 %s 已删除，已跳过", id))
		case !p.Enabled:
			out.Warnings = append(out.Warnings, fmt.Sprintf("节点 %s 已停用，已跳过", p.Name))
		default:
			uri, e := p.URI()
			if e != nil {
				out.Warnings = append(out.Warnings, fmt.Sprintf("节点 %s 无法生成链接：%s", p.Name, e.Error()))
				continue
			}
			out.URIs = append(out.URIs, uri)
		}
	}
	return out
}

// renderSubscription is the response body: standard Base64 of newline-joined links.
func renderSubscription(uris []string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(uris, "\n")))
}

// SubscriptionCandidates lists the entries a subscription may contain (those that produce a
// valid share link, disabled ones included) and warnings for entries that cannot.
func (s State) SubscriptionCandidates() (ok []Profile, warnings []string) {
	for _, p := range s.Profiles {
		if _, e := p.URI(); e != nil {
			warnings = append(warnings, fmt.Sprintf("%s 不能加入订阅：%s", p.Name, e.Error()))
			continue
		}
		ok = append(ok, p)
	}
	return ok, warnings
}

func findSubscription(s State, id string) (int, error) {
	for i, sub := range s.Subscriptions {
		if sub.ID == id {
			return i, nil
		}
	}
	return -1, errors.New("找不到订阅")
}

// pruneSubscriptionNode removes a deleted node from every subscription so no stale ID lingers.
func pruneSubscriptionNode(s State, id string) State {
	for i, sub := range s.Subscriptions {
		kept := make([]string, 0, len(sub.NodeIDs))
		for _, v := range sub.NodeIDs {
			if v != id {
				kept = append(kept, v)
			}
		}
		s.Subscriptions[i].NodeIDs = kept
	}
	return s
}

// checkSubscriptionNodes validates a selection against the current state: known IDs only, no
// duplicates, at least one node, each able to produce a share link.
func checkSubscriptionNodes(s State, ids []string) error {
	if len(ids) == 0 {
		return errors.New("请至少选择一个节点")
	}
	if len(ids) > maxSubscriptionNodes {
		return errors.New("订阅包含的节点过多")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return errors.New("节点重复选择")
		}
		seen[id] = true
		p, e := Find(s, id)
		if e != nil {
			return e
		}
		if _, e = p.URI(); e != nil {
			return fmt.Errorf("%s 不能加入订阅：%w", p.Name, e)
		}
	}
	return nil
}

func nameTaken(s State, name, except string) bool {
	for _, sub := range s.Subscriptions {
		if sub.ID != except && strings.EqualFold(strings.TrimSpace(sub.Name), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// mutateSubscriptions applies one change under the configuration lock to the freshly loaded
// state, then writes it atomically with the usual backup. Nodes, services and traffic
// accounting are never touched, and a concurrent CLI or monitor write cannot be lost.
func (a *App) mutateSubscriptions(change func(*State) error, tokens ...string) error {
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	old, e := a.Load()
	if e != nil {
		return e
	}
	next := old.Clone()
	if e = change(&next); e != nil {
		return e
	}
	if e = next.Validate(); e != nil {
		return e
	}
	if e = a.writeBackup(old); e != nil {
		return e
	}
	b, e := JSON(next)
	if e != nil {
		return e
	}
	path := filepath.Join(a.Home, "state.json")
	if len(tokens) == 0 {
		return AtomicWrite(path, b, 0600)
	}
	previous, e := snapshotSubscriptionFile(path)
	if e != nil {
		return e
	}
	if e = a.saveSubscriptionTokens(old, tokens); e != nil {
		return e
	}
	if e = AtomicWrite(path, b, 0600); e != nil {
		// AtomicWrite can report an fsync error after rename. Restore the exact
		// previous state, retaining both token copies if rollback fails.
		if rollback := previous.restore(); rollback != nil {
			return fmt.Errorf("订阅状态回滚未完成；请保留 secrets 文件并检查 state.json：%w；%w", e, rollback)
		}
		return e
	}
	return nil
}

// CreateSubscription adds a subscription with the given ordered nodes. Authentication
// remains hash-only; the private token copy lets the local CLI display URLs later.
func (a *App) CreateSubscription(name string, nodeIDs []string) (Subscription, string, error) {
	name = strings.TrimSpace(name)
	if e := validSubscriptionName(name); e != nil {
		return Subscription{}, "", e
	}
	token, hash, e := newSubscriptionToken()
	if e != nil {
		return Subscription{}, "", e
	}
	sub := Subscription{ID: RandomHex(6), Name: name, NodeIDs: append([]string(nil), nodeIDs...), TokenHash: hash, Enabled: true, CreatedAt: time.Now().UTC()}
	e = a.mutateSubscriptions(func(s *State) error {
		if nameTaken(*s, name, "") {
			return errors.New("订阅名称已存在")
		}
		if e := checkSubscriptionNodes(*s, nodeIDs); e != nil {
			return e
		}
		for _, existing := range s.Subscriptions {
			if existing.ID == sub.ID {
				return errors.New("订阅 ID 冲突，请重试")
			}
		}
		s.Subscriptions = append(s.Subscriptions, sub)
		return nil
	}, token)
	if e != nil {
		return Subscription{}, "", e
	}
	return sub, token, nil
}

func (a *App) editSubscription(id string, change func(*State, *Subscription) error, tokens ...string) error {
	return a.mutateSubscriptions(func(s *State) error {
		i, e := findSubscription(*s, id)
		if e != nil {
			return e
		}
		sub := s.Subscriptions[i].clone()
		if e = change(s, &sub); e != nil {
			return e
		}
		s.Subscriptions[i] = sub
		return nil
	}, tokens...)
}

func (a *App) RenameSubscription(id, name string) error {
	name = strings.TrimSpace(name)
	if e := validSubscriptionName(name); e != nil {
		return e
	}
	return a.editSubscription(id, func(s *State, sub *Subscription) error {
		if nameTaken(*s, name, id) {
			return errors.New("订阅名称已存在")
		}
		sub.Name = name
		return nil
	})
}

// SetSubscriptionNodes replaces the ordered selection (add, remove and reorder all use it).
func (a *App) SetSubscriptionNodes(id string, nodeIDs []string) error {
	return a.editSubscription(id, func(s *State, sub *Subscription) error {
		if e := checkSubscriptionNodes(*s, nodeIDs); e != nil {
			return e
		}
		sub.NodeIDs = append([]string(nil), nodeIDs...)
		return nil
	})
}

func (a *App) SetSubscriptionEnabled(id string, enabled bool) error {
	return a.editSubscription(id, func(_ *State, sub *Subscription) error {
		sub.Enabled = enabled
		return nil
	})
}

func (a *App) DeleteSubscription(id string) error {
	return a.mutateSubscriptions(func(s *State) error {
		i, e := findSubscription(*s, id)
		if e != nil {
			return e
		}
		s.Subscriptions = append(s.Subscriptions[:i:i], s.Subscriptions[i+1:]...)
		return nil
	})
}

// RotateSubscriptionToken swaps the token hash in one atomic write; the old token stops
// working the moment the write lands. The new token is saved privately first.
func (a *App) RotateSubscriptionToken(id string) (string, error) {
	token, hash, e := newSubscriptionToken()
	if e != nil {
		return "", e
	}
	e = a.editSubscription(id, func(_ *State, sub *Subscription) error {
		sub.TokenHash = hash
		return nil
	}, token)
	if e != nil {
		return "", e
	}
	return token, nil
}
