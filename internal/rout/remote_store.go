package rout

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/VAR7IANT/Rout/internal/remote"
)

// Third-party subscription sources.
//
// Sources and the nodes imported from them live in their own files under <home>/remote/
// (directory 0700, files 0600), never in state.json: they are somebody else's nodes, they may
// carry credentials of their own, and a failing or hostile source must not be able to damage
// the configuration that runs this server. state.json only holds references to them (the Items
// of an aggregate subscription).

const (
	remoteDirName         = "remote"
	remoteSchema          = 1
	maxRemoteSources      = 50
	remoteMinIntervalMin  = 15
	remoteMaxIntervalMin  = 7 * 24 * 60
	remoteDefaultInterval = 6 * 60
	maxRemoteIssues       = 100
	maxRemoteContent      = 2 << 20
	// maxRemoteConfigBytes bounds the serialized sources.json. The same limit gates every
	// write and every normal read, so an accepted change can always be read back.
	maxRemoteConfigBytes = 8 << 20
	// remoteRecoverBytes is the most mutateRemote will parse from a file that is already over
	// the limit (written by an earlier build), so that deleting or shortening sources works.
	remoteRecoverBytes = 64 << 20
	remoteLockWait     = 10 * time.Second
	sourceKindURL      = "url"
	sourceKindStatic   = "static"
)

// RemoteSource is the stored definition of one source. URL and Content are secrets: a
// provider URL usually embeds the account token.
type RemoteSource struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Note        string    `json:"note,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Kind        string    `json:"kind"`
	URL         string    `json:"url,omitempty"`
	Content     string    `json:"content,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Enabled     bool      `json:"enabled"`
	IntervalMin int       `json:"interval_min"`
	CreatedAt   time.Time `json:"created_at"`
	// DisabledNodes are node IDs the administrator excluded from every output.
	DisabledNodes []string `json:"disabled_nodes,omitempty"`
}

type remoteConfig struct {
	Schema  int            `json:"schema"`
	Sources []RemoteSource `json:"sources"`
}

// RemoteStatus records how refreshing is going. It never contains the URL.
type RemoteStatus struct {
	State       string    `json:"state"` // never, ok, error
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures,omitempty"`
}

// RemoteSnapshot is the last successfully imported state of a source. A failed refresh
// changes only Status; the nodes stay as they were.
type RemoteSnapshot struct {
	Schema     int              `json:"schema"`
	SourceID   string           `json:"source_id"`
	Format     string           `json:"format,omitempty"`
	Nodes      []remote.Node    `json:"nodes"`
	Issues     []remote.Issue   `json:"issues,omitempty"`
	Entries    int              `json:"entries"`
	Duplicates int              `json:"duplicates,omitempty"`
	UserInfo   *remote.UserInfo `json:"user_info,omitempty"`
	Title      string           `json:"title,omitempty"`
	Status     RemoteStatus     `json:"status"`
}

func (a *App) remotePath(parts ...string) string {
	return filepath.Join(append([]string{a.Home, remoteDirName}, parts...)...)
}
func (a *App) remoteConfigPath() string { return a.remotePath("sources.json") }
func (a *App) remoteSnapshotPath(id string) string {
	return a.remotePath("data", id+".json")
}

func validTag(t string) bool {
	return strings.TrimSpace(t) != "" && utf8.RuneCountInString(t) <= 24 && !strings.ContainsAny(t, "\r\n\x00\t,")
}

func (src RemoteSource) validate() error {
	if !idPattern.MatchString(src.ID) {
		return errors.New("订阅源 ID 无效")
	}
	if e := validSubscriptionName(src.Name); e != nil {
		return errors.New("订阅源名称无效（1–80 个字符，不含换行）")
	}
	if utf8.RuneCountInString(src.Note) > 200 || strings.ContainsAny(src.Note, "\x00") {
		return errors.New("备注过长（最多 200 个字符）")
	}
	if len(src.Tags) > 8 {
		return errors.New("标签最多 8 个")
	}
	for _, t := range src.Tags {
		if !validTag(t) {
			return errors.New("标签无效（1–24 个字符，不含逗号和换行）")
		}
	}
	if len(src.UserAgent) > 200 || strings.ContainsAny(src.UserAgent, "\r\n\x00") {
		return errors.New("User-Agent 无效")
	}
	switch src.Kind {
	case sourceKindURL:
		if _, e := remote.ValidateURL(src.URL); e != nil {
			return e
		}
		if src.Content != "" {
			return errors.New("订阅源配置无效")
		}
		if src.IntervalMin != 0 && (src.IntervalMin < remoteMinIntervalMin || src.IntervalMin > remoteMaxIntervalMin) {
			return fmt.Errorf("刷新间隔应为 %d 分钟到 7 天，或 0 表示仅手动刷新", remoteMinIntervalMin)
		}
	case sourceKindStatic:
		if src.URL != "" || src.IntervalMin != 0 {
			return errors.New("订阅源配置无效")
		}
		if len(src.Content) > maxRemoteContent {
			return errors.New("粘贴的内容过大")
		}
	default:
		return errors.New("订阅源类型无效")
	}
	for _, id := range src.DisabledNodes {
		if !idPattern.MatchString(id) {
			return errors.New("订阅源的节点列表无效")
		}
	}
	return nil
}

func (c remoteConfig) validate() error {
	if c.Schema != remoteSchema {
		return errors.New("不支持的第三方订阅配置版本")
	}
	if len(c.Sources) > maxRemoteSources {
		return errors.New("订阅源数量过多")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, s := range c.Sources {
		if e := s.validate(); e != nil {
			return e
		}
		key := strings.ToLower(strings.TrimSpace(s.Name))
		if ids[s.ID] || names[key] {
			return errors.New("订阅源 ID 或名称重复")
		}
		ids[s.ID], names[key] = true, true
	}
	return nil
}

func (c remoteConfig) find(id string) (int, bool) {
	for i, s := range c.Sources {
		if s.ID == id {
			return i, true
		}
	}
	return -1, false
}

// errRemoteConfigTooLarge explains the limit and the way out.
func errRemoteConfigTooLarge(n int) error {
	return fmt.Errorf("第三方订阅配置为 %d 字节，超过 %d 字节上限；请删除不用的订阅源或缩短粘贴内容（删除操作仍然可用）", n, maxRemoteConfigBytes)
}

// readRemoteConfig parses sources.json, refusing files above limit bytes.
func (a *App) readRemoteConfig(limit int) (remoteConfig, error) {
	f, e := os.Open(a.remoteConfigPath())
	if os.IsNotExist(e) {
		return remoteConfig{Schema: remoteSchema, Sources: []RemoteSource{}}, nil
	}
	if e != nil {
		return remoteConfig{}, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return remoteConfig{}, e
	}
	if len(b) > limit {
		if limit >= remoteRecoverBytes {
			return remoteConfig{}, errors.New("第三方订阅配置文件异常过大，无法自动恢复，请手动检查 remote/sources.json")
		}
		return remoteConfig{}, errRemoteConfigTooLarge(len(b))
	}
	var c remoteConfig
	if e = json.Unmarshal(b, &c); e != nil {
		return remoteConfig{}, errors.New("第三方订阅配置无效")
	}
	if e = c.validate(); e != nil {
		return remoteConfig{}, e
	}
	return c, nil
}

func (a *App) loadRemoteConfig() (remoteConfig, error) {
	return a.readRemoteConfig(maxRemoteConfigBytes)
}

// encodeRemoteConfig serializes c and refuses a result that loadRemoteConfig could not read.
// shrinkingFrom is the size of an already oversized file being replaced (0 otherwise): a
// change that makes such a file smaller is accepted as a step towards the limit, so a
// configuration left over the limit by an earlier build can always be reduced.
func encodeRemoteConfig(c remoteConfig, shrinkingFrom int) ([]byte, error) {
	b, e := JSON(c)
	if e != nil {
		return nil, e
	}
	if len(b) > maxRemoteConfigBytes && !(shrinkingFrom > maxRemoteConfigBytes && len(b) < shrinkingFrom) {
		return nil, errRemoteConfigTooLarge(len(b))
	}
	return b, nil
}

// mutateRemote applies one change under the remote lock to a freshly loaded configuration.
// The result is validated and size-checked before anything is written, and written atomically,
// so a refused or failed change leaves the previous file untouched. A file that an earlier
// build left over the limit can still be loaded here, so the change that shrinks it works.
func (a *App) mutateRemote(change func(*remoteConfig) error) error {
	unlock, e := lockFile(a.remotePath(".lock"), remoteLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	c, e := a.readRemoteConfig(remoteRecoverBytes)
	if e != nil {
		return e
	}
	current := 0
	if st, er := os.Stat(a.remoteConfigPath()); er == nil {
		current = int(st.Size())
	}
	if e = change(&c); e != nil {
		return e
	}
	if e = c.validate(); e != nil {
		return e
	}
	b, e := encodeRemoteConfig(c, current)
	if e != nil {
		return e
	}
	return AtomicWrite(a.remoteConfigPath(), b, 0600)
}

func (a *App) loadRemoteSnapshot(id string) (*RemoteSnapshot, error) {
	if !idPattern.MatchString(id) {
		return nil, errors.New("订阅源 ID 无效")
	}
	b, e := os.ReadFile(a.remoteSnapshotPath(id))
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var s RemoteSnapshot
	if e = json.Unmarshal(b, &s); e != nil || s.SourceID != id {
		return nil, errors.New("第三方订阅数据无效")
	}
	return &s, nil
}

func (a *App) saveRemoteSnapshot(s *RemoteSnapshot) error {
	s.Schema = remoteSchema
	b, e := JSON(s)
	if e != nil {
		return e
	}
	return AtomicWrite(a.remoteSnapshotPath(s.SourceID), b, 0600)
}

// RemoteSourceSpec is what the administrator supplies when adding a source.
type RemoteSourceSpec struct {
	Name        string   `json:"name"`
	Note        string   `json:"note"`
	Tags        []string `json:"tags"`
	URL         string   `json:"url"`
	Content     string   `json:"content"`
	UserAgent   string   `json:"user_agent"`
	IntervalMin int      `json:"interval_min"`
	Enabled     bool     `json:"enabled"`
}

func normaliseTags(tags []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" && !seen[strings.ToLower(t)] {
			seen[strings.ToLower(t)] = true
			out = append(out, t)
		}
	}
	return out
}

// AddRemoteSource stores a new source. A static source (pasted links or content) is parsed
// immediately and rejected if it holds no node; a URL source is fetched by the caller.
func (a *App) AddRemoteSource(spec RemoteSourceSpec) (RemoteSource, error) {
	if strings.TrimSpace(spec.URL) != "" && strings.TrimSpace(spec.Content) != "" {
		return RemoteSource{}, errors.New("请只提供订阅地址或粘贴内容之一")
	}
	src := RemoteSource{
		ID: RandomHex(6), Name: strings.TrimSpace(spec.Name), Note: strings.TrimSpace(spec.Note), Tags: normaliseTags(spec.Tags),
		UserAgent: strings.TrimSpace(spec.UserAgent), Enabled: spec.Enabled, CreatedAt: time.Now().UTC(),
	}
	if strings.TrimSpace(spec.URL) != "" {
		src.Kind, src.URL, src.IntervalMin = sourceKindURL, strings.TrimSpace(spec.URL), spec.IntervalMin
		if src.IntervalMin == 0 && spec.IntervalMin == 0 {
			src.IntervalMin = 0
		}
	} else {
		src.Kind, src.Content = sourceKindStatic, strings.TrimSpace(spec.Content)
	}
	if e := src.validate(); e != nil {
		return RemoteSource{}, e
	}
	var parsed *remote.Parsed
	if src.Kind == sourceKindStatic {
		p, e := remote.Parse([]byte(src.Content))
		if e != nil {
			return RemoteSource{}, e
		}
		if len(p.Nodes) == 0 {
			return RemoteSource{}, errors.New("没有找到可导入的节点")
		}
		parsed = &p
	}
	e := a.mutateRemote(func(c *remoteConfig) error {
		src.ID = uniqueSourceID(*c, src.ID)
		c.Sources = append(c.Sources, src)
		return nil
	})
	if e != nil {
		return RemoteSource{}, e
	}
	snap := &RemoteSnapshot{SourceID: src.ID, Nodes: []remote.Node{}, Status: RemoteStatus{State: "never"}}
	if parsed != nil {
		now := time.Now().UTC()
		snap = snapshotFrom(src.ID, *parsed, nil, "", now)
	}
	if e = a.saveRemoteSnapshot(snap); e != nil {
		_ = a.mutateRemote(func(c *remoteConfig) error {
			if i, ok := c.find(src.ID); ok {
				c.Sources = append(c.Sources[:i:i], c.Sources[i+1:]...)
			}
			return nil
		})
		return RemoteSource{}, e
	}
	return src, nil
}

func uniqueSourceID(c remoteConfig, id string) string {
	for {
		if _, taken := c.find(id); !taken {
			return id
		}
		id = RandomHex(6)
	}
}

func snapshotFrom(id string, p remote.Parsed, ui *remote.UserInfo, title string, now time.Time) *RemoteSnapshot {
	issues := p.Issues
	if len(issues) > maxRemoteIssues {
		issues = issues[:maxRemoteIssues]
	}
	nodes := p.Nodes
	if nodes == nil {
		nodes = []remote.Node{}
	}
	return &RemoteSnapshot{
		SourceID: id, Format: p.Format, Nodes: nodes, Issues: issues, Entries: p.Entries, Duplicates: p.Duplicates,
		UserInfo: ui, Title: title, Status: RemoteStatus{State: "ok", LastAttempt: now, LastSuccess: now},
	}
}

// RemoteSourcePatch lists the fields that may change; nil means "leave as is".
type RemoteSourcePatch struct {
	Name          *string   `json:"name"`
	Note          *string   `json:"note"`
	Tags          *[]string `json:"tags"`
	URL           *string   `json:"url"` // empty/nil keeps the stored URL
	UserAgent     *string   `json:"user_agent"`
	Enabled       *bool     `json:"enabled"`
	IntervalMin   *int      `json:"interval_min"`
	DisabledNodes *[]string `json:"disabled_nodes"`
}

// UpdateRemoteSource changes a source and reports whether its URL changed (the caller then
// refreshes it).
func (a *App) UpdateRemoteSource(id string, patch RemoteSourcePatch) (urlChanged bool, err error) {
	err = a.mutateRemote(func(c *remoteConfig) error {
		i, ok := c.find(id)
		if !ok {
			return errors.New("找不到订阅源")
		}
		s := c.Sources[i]
		if patch.Name != nil {
			s.Name = strings.TrimSpace(*patch.Name)
		}
		if patch.Note != nil {
			s.Note = strings.TrimSpace(*patch.Note)
		}
		if patch.Tags != nil {
			s.Tags = normaliseTags(*patch.Tags)
		}
		if patch.UserAgent != nil {
			s.UserAgent = strings.TrimSpace(*patch.UserAgent)
		}
		if patch.Enabled != nil {
			s.Enabled = *patch.Enabled
		}
		if patch.IntervalMin != nil {
			if s.Kind != sourceKindURL {
				return errors.New("固定内容的订阅源没有刷新间隔")
			}
			s.IntervalMin = *patch.IntervalMin
		}
		if patch.URL != nil && strings.TrimSpace(*patch.URL) != "" {
			if s.Kind != sourceKindURL {
				return errors.New("固定内容的订阅源没有地址")
			}
			if nu := strings.TrimSpace(*patch.URL); nu != s.URL {
				s.URL, urlChanged = nu, true
			}
		}
		if patch.DisabledNodes != nil {
			snap, e := a.loadRemoteSnapshot(id)
			if e != nil {
				return e
			}
			known := map[string]bool{}
			if snap != nil {
				for _, n := range snap.Nodes {
					known[n.ID] = true
				}
			}
			dis := []string{}
			seen := map[string]bool{}
			for _, nid := range *patch.DisabledNodes {
				if !known[nid] {
					return errors.New("包含不属于该订阅源的节点")
				}
				if !seen[nid] {
					seen[nid] = true
					dis = append(dis, nid)
				}
			}
			sort.Strings(dis)
			s.DisabledNodes = dis
		}
		c.Sources[i] = s
		return nil
	})
	return urlChanged, err
}

// RemoteSourceReferences names the subscriptions that use a source.
func (a *App) RemoteSourceReferences(id string) ([]string, error) {
	st, e := a.Load()
	if e != nil {
		return nil, e
	}
	var names []string
	for _, sub := range st.Subscriptions {
		for _, it := range sub.Items {
			if it.Kind == itemRemote && it.SourceID == id {
				names = append(names, sub.Name)
				break
			}
		}
	}
	return names, nil
}

// DeleteRemoteSource removes a source and its imported data. While subscriptions still use
// it the deletion is refused, unless detach is set, which first removes those entries.
func (a *App) DeleteRemoteSource(id string, detach bool) error {
	refs, e := a.RemoteSourceReferences(id)
	if e != nil {
		return e
	}
	if len(refs) > 0 {
		if !detach {
			return fmt.Errorf("订阅源仍被聚合订阅使用：%s", strings.Join(refs, "、"))
		}
		if e = a.mutateSubscriptions(func(s *State) error {
			for i, sub := range s.Subscriptions {
				kept := make([]SubItem, 0, len(sub.Items))
				for _, it := range sub.Items {
					if !(it.Kind == itemRemote && it.SourceID == id) {
						kept = append(kept, it)
					}
				}
				if len(kept) != len(sub.Items) {
					s.Subscriptions[i].Items = kept
					s.Subscriptions[i].syncNodeIDs()
				}
			}
			return nil
		}); e != nil {
			return e
		}
	}
	e = a.mutateRemote(func(c *remoteConfig) error {
		i, ok := c.find(id)
		if !ok {
			return errors.New("找不到订阅源")
		}
		c.Sources = append(c.Sources[:i:i], c.Sources[i+1:]...)
		return nil
	})
	if e != nil {
		return e
	}
	_ = os.Remove(a.remoteSnapshotPath(id))
	_ = os.Remove(a.remotePath("data", id+".refresh"))
	return nil
}

// RemoteSourceView is the API form of a source: no URL, no content, no credentials.
type RemoteSourceView struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Note        string       `json:"note,omitempty"`
	Tags        []string     `json:"tags"`
	Kind        string       `json:"kind"`
	URLMasked   string       `json:"url_masked,omitempty"`
	UserAgent   string       `json:"user_agent,omitempty"`
	Enabled     bool         `json:"enabled"`
	IntervalMin int          `json:"interval_min"`
	CreatedAt   time.Time    `json:"created_at"`
	Format      string       `json:"format,omitempty"`
	Status      RemoteStatus `json:"status"`
	NextRefresh *time.Time   `json:"next_refresh,omitempty"`
	// Counts. Entries is what the source listed; Valid the nodes that parsed; Active those
	// not disabled by the administrator.
	Entries    int              `json:"entries"`
	Valid      int              `json:"valid"`
	Active     int              `json:"active"`
	Errors     int              `json:"errors"`
	Skipped    int              `json:"skipped"`
	Duplicates int              `json:"duplicates"`
	Disabled   int              `json:"disabled"`
	UserInfo   *remote.UserInfo `json:"user_info,omitempty"`
	Title      string           `json:"title,omitempty"`
	Refs       []string         `json:"refs"`
}

// maskURL keeps the host (to recognise the provider) and hides everything that can hold a token.
func maskURL(raw string) string {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" {
		return ""
	}
	out := u.Scheme + "://" + u.Host
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		out += "/…"
	}
	return out
}

func (a *App) remoteView(src RemoteSource, snap *RemoteSnapshot, refs []string) RemoteSourceView {
	v := RemoteSourceView{
		ID: src.ID, Name: src.Name, Note: src.Note, Tags: append([]string{}, src.Tags...), Kind: src.Kind,
		UserAgent: src.UserAgent, Enabled: src.Enabled, IntervalMin: src.IntervalMin, CreatedAt: src.CreatedAt,
		Status: RemoteStatus{State: "never"}, Refs: append([]string{}, refs...),
	}
	if src.Kind == sourceKindURL {
		v.URLMasked = maskURL(src.URL)
	}
	if snap != nil {
		v.Format, v.Status, v.Entries, v.Valid = snap.Format, snap.Status, snap.Entries, len(snap.Nodes)
		v.Duplicates, v.UserInfo, v.Title = snap.Duplicates, snap.UserInfo, snap.Title
		v.Status.LastError = a.T(v.Status.LastError)
		dis := map[string]bool{}
		for _, id := range src.DisabledNodes {
			dis[id] = true
		}
		for _, n := range snap.Nodes {
			if dis[n.ID] {
				v.Disabled++
			}
		}
		v.Active = v.Valid - v.Disabled
		for _, is := range snap.Issues {
			if is.Level == "skip" {
				v.Skipped++
			} else {
				v.Errors++
			}
		}
		if v.Entries > 0 && v.Entries < v.Valid+v.Errors+v.Skipped+v.Duplicates {
			v.Entries = v.Valid + v.Errors + v.Skipped + v.Duplicates
		}
	}
	if src.Kind == sourceKindURL && src.Enabled && src.IntervalMin > 0 {
		next := nextRefresh(src, v.Status, time.Now())
		v.NextRefresh = &next
	}
	return v
}

// RemoteSources lists every source with its state.
func (a *App) RemoteSources() ([]RemoteSourceView, error) {
	c, e := a.loadRemoteConfig()
	if e != nil {
		return nil, e
	}
	st, e := a.Load()
	if e != nil {
		return nil, e
	}
	refs := map[string][]string{}
	for _, sub := range st.Subscriptions {
		seen := map[string]bool{}
		for _, it := range sub.Items {
			if it.Kind == itemRemote && !seen[it.SourceID] {
				seen[it.SourceID] = true
				refs[it.SourceID] = append(refs[it.SourceID], sub.Name)
			}
		}
	}
	out := make([]RemoteSourceView, 0, len(c.Sources))
	for _, src := range c.Sources {
		snap, e := a.loadRemoteSnapshot(src.ID)
		if e != nil {
			snap = nil
		}
		out = append(out, a.remoteView(src, snap, refs[src.ID]))
	}
	return out, nil
}

// RemoteSourceSecret returns the stored URL or pasted content of a source, for the
// administrator who asked to see or edit it.
func (a *App) RemoteSourceSecret(id string) (string, error) {
	c, e := a.loadRemoteConfig()
	if e != nil {
		return "", e
	}
	i, ok := c.find(id)
	if !ok {
		return "", errors.New("找不到订阅源")
	}
	if c.Sources[i].Kind == sourceKindURL {
		return c.Sources[i].URL, nil
	}
	return c.Sources[i].Content, nil
}
