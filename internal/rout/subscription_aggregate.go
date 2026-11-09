package rout

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/VAR7IANT/Rout/internal/remote"
)

// Aggregate subscriptions mix Rout's own nodes with nodes imported from third-party sources.
//
// An aggregate only references nodes (SubItem). Everything it outputs is computed at request
// time from the current local state and the last good snapshot of each source, so editing a
// node or refreshing a source is reflected immediately and the originals are never modified.
// A node that cannot be written faithfully in a format is left out of that format and listed
// in the compatibility report; nothing is "approximately" converted.

// remoteLookup returns a source and its last good snapshot.
type remoteLookup func(sourceID string) (RemoteSource, *RemoteSnapshot, error)

// AggNode is the report entry of one item of an aggregate.
type AggNode struct {
	Index    int    `json:"index"`
	Kind     string `json:"kind"`
	NodeID   string `json:"node_id"`
	SourceID string `json:"source_id,omitempty"`
	Source   string `json:"source,omitempty"`
	Name     string `json:"name"`
	Original string `json:"original_name"`
	Protocol string `json:"protocol,omitempty"`
	// Skipped is why the item is in no output at all (deleted, disabled, duplicate...).
	Skipped     string   `json:"skipped,omitempty"`
	Base64OK    bool     `json:"base64_ok"`
	Base64Why   string   `json:"base64_why,omitempty"`
	MihomoOK    bool     `json:"mihomo_ok"`
	MihomoWhy   string   `json:"mihomo_why,omitempty"`
	Notes       []string `json:"notes,omitempty"`
	DuplicateOf int      `json:"duplicate_of,omitempty"`
}

// AggregateExport is everything an aggregate produces.
type AggregateExport struct {
	Nodes    []AggNode
	URIs     []string // Base64 format entries, in order
	Proxies  []M      // Mihomo format entries, in order
	Warnings []string // short diagnostics: IDs and fixed reasons, never links or names
}

type aggCand struct {
	idx      int
	node     AggNode
	local    *Profile
	remote   *remote.Node
	linkKey  string
	unique   string
	baseLink string
}

func mihomoReserved() map[string]bool {
	return map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true,
		mihomoProxyGroup: true, mihomoAutoGroup: true, mihomoFallbackGroup: true, mihomoInfoGroup: true}
}

// exportAggregate resolves an aggregate against the current state and sources.
func (s State) exportAggregate(sub Subscription, lookup remoteLookup) AggregateExport {
	var out AggregateExport
	byID := make(map[string]Profile, len(s.Profiles))
	for _, p := range s.Profiles {
		byID[p.ID] = p
	}
	type srcData struct {
		src   RemoteSource
		snap  *RemoteSnapshot
		err   error
		nodes map[string]*remote.Node
		dis   map[string]bool
	}
	sources := map[string]*srcData{}
	getSource := func(id string) *srcData {
		if d, ok := sources[id]; ok {
			return d
		}
		d := &srcData{}
		sources[id] = d
		if lookup == nil {
			d.err = errors.New("订阅源不可用")
			return d
		}
		d.src, d.snap, d.err = lookup(id)
		if d.err == nil && d.snap != nil {
			d.nodes = make(map[string]*remote.Node, len(d.snap.Nodes))
			for i := range d.snap.Nodes {
				d.nodes[d.snap.Nodes[i].ID] = &d.snap.Nodes[i]
			}
			d.dis = map[string]bool{}
			for _, id := range d.src.DisabledNodes {
				d.dis[id] = true
			}
		}
		return d
	}
	// A provider that rotated credentials produces a new ID for the same endpoint; follow
	// it by (protocol, host, port) when that is unambiguous.
	findLoose := func(d *srcData, loose string) *remote.Node {
		if loose == "" || d.snap == nil {
			return nil
		}
		var hit *remote.Node
		for i := range d.snap.Nodes {
			if d.snap.Nodes[i].Loose() == loose {
				if hit != nil {
					return nil
				}
				hit = &d.snap.Nodes[i]
			}
		}
		return hit
	}

	var cands []*aggCand
	for i, it := range sub.Items {
		c := &aggCand{idx: i}
		c.node = AggNode{Index: i, Kind: it.Kind}
		switch it.Kind {
		case itemLocal:
			c.node.NodeID = it.NodeID
			p, ok := byID[it.NodeID]
			switch {
			case !ok:
				c.node.Skipped = "节点已删除"
			case !p.Enabled:
				c.node.Original, c.node.Name, c.node.Protocol = p.Name, p.Name, p.Protocol
				c.node.Skipped = "节点已停用"
			default:
				pp := p
				c.local = &pp
				c.node.Original, c.node.Protocol = p.Name, p.Protocol
				c.node.Name = p.Name
				if it.Name != "" {
					c.node.Name = it.Name
				}
				if uri, e := p.URI(); e != nil {
					c.node.Base64Why = e.Error()
				} else {
					c.baseLink = uri
					c.linkKey = "link:" + remote.CanonicalLink(uri)
				}
			}
		case itemRemote:
			c.node.SourceID, c.node.NodeID = it.SourceID, it.RemoteID
			d := getSource(it.SourceID)
			if d.err != nil {
				c.node.Skipped = "订阅源已删除或不可读"
				break
			}
			c.node.Source = d.src.Name
			if d.snap == nil || len(d.snap.Nodes) == 0 {
				c.node.Skipped = "订阅源还没有成功导入的节点"
				break
			}
			n := d.nodes[it.RemoteID]
			if n == nil {
				n = findLoose(d, it.Loose)
			}
			switch {
			case n == nil:
				c.node.Skipped = "节点已不在订阅源中"
			case !d.src.Enabled:
				c.node.Original, c.node.Name, c.node.Protocol = n.Name, n.Name, n.Protocol
				c.node.Skipped = "订阅源已停用"
			case d.dis[n.ID] || d.dis[it.RemoteID]:
				c.node.Original, c.node.Name, c.node.Protocol = n.Name, n.Name, n.Protocol
				c.node.Skipped = "节点已在订阅源中停用"
			default:
				c.remote = n
				c.node.NodeID = n.ID
				c.node.Original, c.node.Protocol = n.Name, n.Protocol
				c.node.Name = n.Name
				if it.Name != "" {
					c.node.Name = it.Name
				}
				c.node.Notes = append(c.node.Notes, n.Notes...)
				if n.Link != "" {
					c.baseLink = n.Link
					c.linkKey = "link:" + remote.CanonicalLink(n.Link)
				} else {
					c.linkKey = "fp:" + n.Fingerprint
				}
			}
		}
		cands = append(cands, c)
	}

	active := func(c *aggCand) bool { return c.node.Skipped == "" }
	if sub.Dedupe {
		first := map[string]*aggCand{}
		for _, c := range cands {
			if !active(c) || c.linkKey == "" {
				continue
			}
			if prev, dup := first[c.linkKey]; dup {
				c.node.Skipped = "与前面的节点重复"
				c.node.DuplicateOf = prev.idx + 1
				continue
			}
			first[c.linkKey] = c
		}
	}

	// Unique names. Reserve every original name first so a generated "name [id]" can never
	// equal a literal name; all colliding entries get their ID, so a node's output name does
	// not depend on which of its namesakes comes first.
	reserved := mihomoReserved()
	counts, originals := map[string]int{}, map[string]bool{}
	for _, c := range cands {
		if active(c) {
			counts[c.node.Name]++
			originals[c.node.Name] = true
		}
	}
	used := map[string]bool{}
	for _, c := range cands {
		if !active(c) {
			continue
		}
		name := c.node.Name
		if counts[name] > 1 || reserved[name] {
			id := c.node.NodeID
			name += " [" + id + "]"
			for originals[name] || used[name] || reserved[name] {
				name += " [" + id + "]"
			}
		}
		c.unique = name
		used[name] = true
	}

	for _, c := range cands {
		n := &c.node
		if !active(c) {
			out.Nodes = append(out.Nodes, *n)
			out.Warnings = append(out.Warnings, fmt.Sprintf("订阅项 %d（%s）已跳过：%s", n.Index+1, shortID(n), n.Skipped))
			continue
		}
		n.Name = c.unique
		switch {
		case c.local != nil:
			fillLocal(&out, c, sub)
		default:
			fillRemote(&out, c, sub)
		}
		out.Nodes = append(out.Nodes, *n)
	}
	return out
}

func shortID(n *AggNode) string {
	if n.Kind == itemRemote {
		return "第三方 " + n.NodeID
	}
	return "本机 " + n.NodeID
}

func fillLocal(out *AggregateExport, c *aggCand, sub Subscription) {
	n, p := &c.node, c.local
	if c.baseLink != "" {
		link := c.baseLink
		if n.Name != p.Name {
			link = remote.SetName(link, n.Name)
		}
		out.URIs = append(out.URIs, link)
		n.Base64OK = true
	} else {
		out.Warnings = append(out.Warnings, fmt.Sprintf("订阅项 %d（%s）无法生成 Base64 链接：%s", n.Index+1, shortID(n), n.Base64Why))
	}
	proxy, e := mihomoNode(*p)
	if e != nil {
		n.MihomoWhy = e.Error()
		out.Warnings = append(out.Warnings, fmt.Sprintf("订阅项 %d（%s）无法生成 Mihomo：%s", n.Index+1, shortID(n), e.Error()))
		return
	}
	proxy["name"] = n.Name
	out.Proxies = append(out.Proxies, proxy)
	n.MihomoOK = true
}

func fillRemote(out *AggregateExport, c *aggCand, sub Subscription) {
	n, rn := &c.node, c.remote
	if rn.Link != "" && linkInsecure(rn.Link) && !sub.AllowInsecure {
		// The same policy as the Mihomo output: no unverified TLS unless the subscription allows it.
		n.Base64Why = "节点关闭了证书验证（allowInsecure），默认不导出；可在订阅设置中允许"
		out.Warnings = append(out.Warnings, fmt.Sprintf("订阅项 %d（%s）无法生成 Base64 链接：%s", n.Index+1, shortID(n), n.Base64Why))
	} else if link, ok := rn.LinkNamed(n.Name); ok {
		if n.Name == rn.Name {
			link = rn.Link
		}
		out.URIs = append(out.URIs, link)
		n.Base64OK = true
	} else {
		n.Base64Why = rn.LinkIssue
		if n.Base64Why == "" {
			n.Base64Why = "该节点没有可用的分享链接"
		}
		out.Warnings = append(out.Warnings, fmt.Sprintf("订阅项 %d（%s）无法生成 Base64 链接：%s", n.Index+1, shortID(n), n.Base64Why))
	}
	proxy, e := mihomoRemote(*rn, n.Name, sub.AllowInsecure)
	if e != nil {
		n.MihomoWhy = e.Error()
		out.Warnings = append(out.Warnings, fmt.Sprintf("订阅项 %d（%s）无法生成 Mihomo：%s", n.Index+1, shortID(n), e.Error()))
		return
	}
	out.Proxies = append(out.Proxies, proxy)
	n.MihomoOK = true
}

// mihomoRemote converts an imported node to a Mihomo proxy. A node that came from a Clash
// file is passed through exactly as the provider wrote it (only the name changes), since that
// is the most faithful form; a node that came from a share link goes through the same strict
// converter Rout uses for its own relays.
func mihomoRemote(n remote.Node, name string, allowInsecure bool) (M, error) {
	if m, ok := n.ClashNamed(name); ok {
		if clashInsecure(m) && !allowInsecure {
			return nil, errors.New("节点关闭了证书验证（skip-cert-verify），默认不导出；可在订阅设置中允许")
		}
		return M(m), nil
	}
	if n.Link == "" {
		why := n.LinkIssue
		if why == "" {
			why = "没有可转换的分享链接"
		}
		return nil, errors.New(why)
	}
	proxy, e := mihomoFromLink(n.Link, []string{"tcp", "udp"}, "", true, allowInsecure)
	if e != nil {
		return nil, errors.New(strings.ReplaceAll(e.Error(), "中转", "节点"))
	}
	proxy["name"] = name
	return proxy, nil
}

// linkInsecure reports a share link that turns certificate verification off without pinning
// the certificate (Reality does not verify certificates, so it is not affected).
func linkInsecure(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil {
		return false
	}
	q := u.Query()
	if q.Get("insecure") != "1" && q.Get("allowInsecure") != "1" {
		return false
	}
	if !pinnedCertificate(q.Get("pinSHA256")) && !(q.Get("security") == "reality" && strings.TrimSpace(q.Get("pbk")) != "") {
		return true
	}
	return false
}

// pinnedCertificate accepts a usable SHA-256 certificate pin (64 hex digits, optionally
// colon-separated); an empty or malformed value pins nothing.
func pinnedCertificate(v any) bool {
	str, ok := v.(string)
	if !ok {
		return false
	}
	str = strings.ReplaceAll(strings.TrimSpace(str), ":", "")
	if len(str) != 64 {
		return false
	}
	_, e := hex.DecodeString(str)
	return e == nil
}

// clashInsecure reports a proxy that turns certificate verification off without pinning the
// certificate. Reality does not use certificate verification, so it is not affected.
func clashInsecure(m map[string]any) bool {
	skip, _ := m["skip-cert-verify"].(bool)
	if !skip {
		return false
	}
	if pinnedCertificate(m["fingerprint"]) {
		return false
	}
	if opts, ok := m["reality-opts"].(map[string]any); ok {
		// Reality replaces certificate verification only with a real key; an empty or null
		// block is ordinary TLS with verification turned off.
		if pk, _ := opts["public-key"].(string); strings.TrimSpace(pk) != "" {
			return false
		}
	}
	return true
}

// ---- reading sources -------------------------------------------------------------------

// remoteLookup reads sources straight from disk. It is used by the CLI and the web panel,
// where one extra read per request does not matter.
func (a *App) remoteLookup() remoteLookup {
	var cfg remoteConfig
	var cfgErr error
	loaded := false
	return func(id string) (RemoteSource, *RemoteSnapshot, error) {
		if !loaded {
			cfg, cfgErr = a.loadRemoteConfig()
			loaded = true
		}
		if cfgErr != nil {
			return RemoteSource{}, nil, cfgErr
		}
		i, ok := cfg.find(id)
		if !ok {
			return RemoteSource{}, nil, errors.New("找不到订阅源")
		}
		snap, e := a.loadRemoteSnapshot(id)
		if e != nil {
			return RemoteSource{}, nil, e
		}
		return cfg.Sources[i], snap, nil
	}
}

// ExportAggregate resolves an aggregate subscription now.
func (a *App) ExportAggregate(s State, sub Subscription) AggregateExport {
	return s.exportAggregate(sub, a.remoteLookup())
}

// remoteCache is the subscription server's view of the sources: files are re-read only when
// they changed, and a failure to read one source never affects another or the local nodes.
type remoteCache struct {
	a      *App
	mu     sync.Mutex
	cfgKey [3]int64
	cfgSet bool
	cfg    remoteConfig
	cfgErr error
	snaps  map[string]snapEntry
}

type snapEntry struct {
	key  [3]int64
	snap *RemoteSnapshot
	err  error
}

func fileKey(path string) ([3]int64, bool, error) {
	fi, e := os.Stat(path)
	if os.IsNotExist(e) {
		return [3]int64{}, false, nil
	}
	if e != nil {
		return [3]int64{}, false, e
	}
	return [3]int64{int64(fi.Sys().(*syscall.Stat_t).Ino), fi.ModTime().UnixNano(), fi.Size()}, true, nil
}

func newRemoteCache(a *App) *remoteCache { return &remoteCache{a: a, snaps: map[string]snapEntry{}} }

func (c *remoteCache) lookup(id string) (RemoteSource, *RemoteSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, exists, e := fileKey(c.a.remoteConfigPath())
	if e != nil {
		return RemoteSource{}, nil, e
	}
	if !c.cfgSet || key != c.cfgKey {
		if exists {
			c.cfg, c.cfgErr = c.a.loadRemoteConfig()
		} else {
			c.cfg, c.cfgErr = remoteConfig{Schema: remoteSchema}, nil
		}
		c.cfgKey, c.cfgSet = key, true
	}
	if c.cfgErr != nil {
		return RemoteSource{}, nil, c.cfgErr
	}
	i, ok := c.cfg.find(id)
	if !ok {
		return RemoteSource{}, nil, errors.New("找不到订阅源")
	}
	skey, sexists, e := fileKey(c.a.remoteSnapshotPath(id))
	if e != nil {
		return RemoteSource{}, nil, e
	}
	if !sexists {
		return c.cfg.Sources[i], nil, nil
	}
	if ent, ok := c.snaps[id]; ok && ent.key == skey {
		return c.cfg.Sources[i], ent.snap, ent.err
	}
	snap, e := c.a.loadRemoteSnapshot(id)
	c.snaps[id] = snapEntry{key: skey, snap: snap, err: e}
	if len(c.snaps) > maxRemoteSources*2 {
		for k := range c.snaps {
			if _, ok := c.cfg.find(k); !ok {
				delete(c.snaps, k)
			}
		}
	}
	return c.cfg.Sources[i], snap, e
}

// ---- editing aggregates ----------------------------------------------------------------

// AggregateSpec is the editable part of an aggregate subscription.
type AggregateSpec struct {
	Items         []SubItem `json:"items"`
	Dedupe        bool      `json:"dedupe"`
	AllowInsecure bool      `json:"allow_insecure"`
}

// checkAggregate validates items against the current state and sources and fills in the
// identity fields the client cannot be trusted to supply.
func (a *App) checkAggregate(s State, items []SubItem) ([]SubItem, error) {
	if len(items) == 0 {
		return nil, errors.New("请至少选择一个节点")
	}
	if e := checkItems(items); e != nil {
		return nil, e
	}
	lookup := a.remoteLookup()
	out := make([]SubItem, 0, len(items))
	locals := 0
	for _, it := range items {
		switch it.Kind {
		case itemLocal:
			p, e := Find(s, it.NodeID)
			if e != nil {
				return nil, e
			}
			if _, e = p.Share(); e != nil {
				return nil, fmt.Errorf("%s 不能加入订阅：%w", p.Name, e)
			}
			if locals++; locals > maxSubscriptionNodes {
				return nil, errors.New("订阅包含的本机节点过多")
			}
			out = append(out, SubItem{Kind: itemLocal, NodeID: it.NodeID, Name: it.Name})
		case itemRemote:
			_, snap, e := lookup(it.SourceID)
			if e != nil {
				return nil, errors.New("订阅源不存在")
			}
			var found *remote.Node
			if snap != nil {
				for i := range snap.Nodes {
					if snap.Nodes[i].ID == it.RemoteID {
						found = &snap.Nodes[i]
						break
					}
				}
			}
			if found == nil {
				return nil, errors.New("所选第三方节点不在订阅源中")
			}
			out = append(out, SubItem{Kind: itemRemote, SourceID: it.SourceID, RemoteID: found.ID, Loose: found.Loose(), Name: it.Name})
		}
	}
	return out, nil
}

// CreateAggregateSubscription adds a subscription made of mixed items.
func (a *App) CreateAggregateSubscription(name string, spec AggregateSpec) (Subscription, string, error) {
	name = strings.TrimSpace(name)
	if e := validSubscriptionName(name); e != nil {
		return Subscription{}, "", e
	}
	token, hash, e := newSubscriptionToken()
	if e != nil {
		return Subscription{}, "", e
	}
	sub := Subscription{ID: RandomHex(6), Name: name, TokenHash: hash, Enabled: true, CreatedAt: time.Now().UTC(), Dedupe: spec.Dedupe, AllowInsecure: spec.AllowInsecure}
	e = a.mutateSubscriptions(func(s *State) error {
		if nameTaken(*s, name, "") {
			return errors.New("订阅名称已存在")
		}
		items, e := a.checkAggregate(*s, spec.Items)
		if e != nil {
			return e
		}
		sub.Items = items
		sub.syncNodeIDs()
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

// SetSubscriptionItems replaces the items and options of a subscription. A legacy
// subscription becomes an aggregate the first time this is used on it.
func (a *App) SetSubscriptionItems(id string, spec AggregateSpec) error {
	return a.editSubscription(id, func(s *State, sub *Subscription) error {
		items, e := a.checkAggregate(*s, spec.Items)
		if e != nil {
			return e
		}
		sub.Items, sub.Dedupe, sub.AllowInsecure = items, spec.Dedupe, spec.AllowInsecure
		sub.syncNodeIDs()
		return nil
	})
}
