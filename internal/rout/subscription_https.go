package rout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Separate metadata, not a subscription database/schema migration. External sites
// never gain deletion rights just because their endpoint works.
type subscriptionHTTPSState struct {
	Version   int       `json:"version"`
	Domain    string    `json:"domain,omitempty"`
	Domains   []string  `json:"domains,omitempty"`
	Ownership string    `json:"ownership,omitempty"` // external, managed, adopted
	Main      string    `json:"main,omitempty"`
	File      string    `json:"file,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	Removed   bool      `json:"removed,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Updated   time.Time `json:"updated,omitempty"`
}

func (a *App) httpsStatePath() string { return filepath.Join(a.Home, "subscription-https.json") }
func (a *App) loadHTTPSState() (subscriptionHTTPSState, error) {
	var s subscriptionHTTPSState
	b, e := os.ReadFile(a.httpsStatePath())
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if json.Unmarshal(b, &s) != nil || s.Version != 1 {
		return s, errors.New("HTTPS ownership metadata is invalid; preserve files and inspect subscription-https.json")
	}
	if s.Domain != "" {
		if _, e := subscriptionDomain(s.Domain); e != nil {
			return s, errors.New("invalid domain in HTTPS ownership metadata")
		}
	}
	for _, domain := range s.Domains {
		if _, e := subscriptionDomain(domain); e != nil {
			return s, errors.New("invalid domain alias in HTTPS ownership metadata")
		}
	}
	if s.Ownership != "" && s.Ownership != "external" && s.Ownership != "managed" && s.Ownership != "adopted" {
		return s, errors.New("invalid HTTPS resource ownership")
	}
	return s, nil
}
func (a *App) saveHTTPSState(s subscriptionHTTPSState) error {
	s.Version = 1
	s.Updated = time.Now().UTC()
	b, e := JSON(s)
	if e != nil {
		return e
	}
	old, e := snapshotSubscriptionFile(a.httpsStatePath())
	if e != nil {
		return e
	}
	return atomicSubscriptionFile(old, b, 0600)
}

func (a *App) httpsFile() string {
	return filepath.Join(a.httpsRuntime().root, "rout-"+nftMeter{home: a.Home}.prefix()[5:13], "subscription.caddy")
}
func (a *App) httpsMain() string { return filepath.Join(a.httpsRuntime().root, "Caddyfile") }
func (a *App) httpsImport() string {
	return "\n# Rout subscription HTTPS " + nftMeter{home: a.Home}.prefix() + "\nimport " + filepath.Dir(a.httpsFile()) + "/*.caddy\n"
}

// Snapshots preserve bytes, mode, UID and GID; no plaintext access tokens are read
// or generated. Backups are private and never overwrite state.json/settings.json.
type subscriptionFileSnapshot struct {
	Path     string      `json:"path"`
	Data     []byte      `json:"data,omitempty"`
	Mode     os.FileMode `json:"mode"`
	UID, GID int
	Exists   bool `json:"exists"`
	backup   string
}

func snapshotSubscriptionFile(path string) (subscriptionFileSnapshot, error) {
	s := subscriptionFileSnapshot{Path: path}
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if !st.Mode().IsRegular() || st.Size() > 64<<20 {
		return s, fmt.Errorf("refusing non-regular or oversized configuration file: %s", path)
	}
	s.Exists = true
	s.Mode = st.Mode().Perm()
	sys := st.Sys().(*syscall.Stat_t)
	s.UID, s.GID = int(sys.Uid), int(sys.Gid)
	s.Data, e = os.ReadFile(path)
	return s, e
}
func atomicSubscriptionFile(s subscriptionFileSnapshot, data []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(s.Path), 0755); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.Path), ".rout-https-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if s.Exists {
		mode = s.Mode
	}
	if e = f.Chmod(mode); e == nil && s.Exists {
		e = f.Chown(s.UID, s.GID)
	}
	if e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, s.Path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(s.Path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (s subscriptionFileSnapshot) restore() error {
	if !s.Exists {
		e := os.Remove(s.Path)
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	return atomicSubscriptionFile(s, s.Data, s.Mode)
}
func (a *App) backupSubscriptionFiles(reason string, paths ...string) ([]subscriptionFileSnapshot, error) {
	var snapshots []subscriptionFileSnapshot
	for _, p := range paths {
		s, e := snapshotSubscriptionFile(p)
		if e != nil {
			return nil, e
		}
		snapshots = append(snapshots, s)
	}
	b, e := JSON(snapshots)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(a.Home, "backups", "subscription-"+reason+"-"+time.Now().UTC().Format("20060102T150405.000000000")+".json")
	if e = AtomicWrite(path, b, 0600); e != nil {
		return nil, e
	}
	for i := range snapshots {
		snapshots[i].backup = path
	}
	return snapshots, nil
}

func renderSubscriptionCaddy(domain string, port int) string {
	return renderSubscriptionCaddySites([]string{domain}, port)
}
func renderSubscriptionCaddySites(domains []string, port int) string {
	return fmt.Sprintf("# Rout subscription HTTPS v1\n%s {\n\thandle /s/* {\n\t\treverse_proxy 127.0.0.1:%d\n\t}\n\thandle {\n\t\trespond \"not found\" 404\n\t}\n\thandle_errors {\n\t\trespond \"subscription unavailable\" 503\n\t}\n\tlog {\n\t\toutput discard\n\t}\n}\n", strings.Join(domains, ", "), port)
}

type httpsRoute struct{ Found, Correct, Conflict bool }

func inspectCaddyDomain(b []byte, domain string, port int) httpsRoute {
	config, e := decodeCaddy(b)
	if e != nil {
		return httpsRoute{}
	}
	out := httpsRoute{}
	var walk func(any, bool)
	walk = func(v any, scope bool) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(item, scope)
			}
		case map[string]any:
			if match, ok := x["match"].([]any); ok {
				hasHost, matches, exact := false, false, false
				for _, entry := range match {
					m, _ := entry.(map[string]any)
					hosts, _ := m["host"].([]any)
					for _, h := range hosts {
						host, _ := h.(string)
						hasHost = true
						if strings.EqualFold(host, domain) {
							matches = true
							exact = true
						}
						if strings.HasPrefix(host, "*.") && strings.HasSuffix(domain, host[1:]) {
							matches = true
						}
					}
				}
				if hasHost {
					scope = matches
				}
				if exact {
					out.Found = true
				}
			}
			if scope && x["handler"] == "reverse_proxy" {
				upstreams, _ := x["upstreams"].([]any)
				for _, item := range upstreams {
					up, _ := item.(map[string]any)
					if up["dial"] == net.JoinHostPort("127.0.0.1", itoa(port)) {
						out.Correct = true
					} else {
						out.Conflict = true
					}
				}
			}
			for key, value := range x {
				if key != "match" {
					walk(value, scope)
				}
			}
		}
	}
	walk(config, false)
	return out
}
func caddyAutomaticHTTPS(b []byte) bool {
	config, e := decodeCaddy(b)
	if e != nil {
		return false
	}
	okay := true
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			if a, ok := x["automatic_https"].(map[string]any); ok {
				if a["disable"] == true || a["disable_certificates"] == true {
					okay = false
				}
			}
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(config)
	return okay
}

// Management is limited to the normal systemd Caddyfile service. Nonstandard
// services remain usable externally but cannot be safely reconfigured here.
func (a *App) checkCaddyLayout() (subscriptionFileSnapshot, []byte, error) {
	r := a.httpsRuntime()
	main := a.httpsMain()
	if !safeProxyPath(r.root, main) {
		return subscriptionFileSnapshot{}, nil, errors.New("Caddyfile path has unsafe ownership, permissions or a symlink; use the external HTTPS configuration")
	}
	st, e := snapshotSubscriptionFile(main)
	if e != nil {
		return st, nil, e
	}
	if !st.Exists {
		return st, nil, errors.New("Caddyfile is missing; preserve the existing installation and configure an isolated import first")
	}
	if st.Mode&0022 != 0 {
		return st, nil, errors.New("Caddyfile is group/world writable; refuse automatic modification")
	}
	execStart, e := r.run("", "systemctl", "show", "caddy", "--property=ExecStart", "--value")
	if e != nil || !regexp.MustCompile(`(?:^|\s)--config\s+`+regexp.QuoteMeta(main)+`(?:\s|;|$)`).Match(execStart) || strings.Contains(string(execStart), "--resume") {
		return st, nil, errors.New("nonstandard Caddy service/configuration; use the existing endpoint externally without changing ownership")
	}
	adapted, e := r.run("", "caddy", "adapt", "--config", main, "--adapter", "caddyfile")
	if e != nil {
		return st, nil, e
	}
	if _, e = decodeCaddy(adapted); e != nil {
		return st, nil, e
	}
	if r.running() {
		active, er := r.active()
		if er != nil || !caddyConfigEqual(active, adapted) {
			return st, nil, errors.New("active Caddy configuration cannot be proven equal to its Caddyfile; no files changed; use external mode or reconcile the configuration first")
		}
	}
	return st, adapted, nil
}
func (a *App) checkHTTPSPorts() error {
	r := a.httpsRuntime()
	state, e := a.Load()
	if e != nil {
		return e
	}
	for _, p := range state.Profiles {
		if p.Enabled && (p.Port == 80 || p.Port == 443) && sharesNetwork(p.Networks(), []string{"tcp"}) {
			return fmt.Errorf("TCP port %d belongs to Rout node %s; its listener will not be modified", p.Port, p.Name)
		}
	}
	pid := 0
	if r.running() {
		b, e := r.run("", "systemctl", "show", "caddy", "--property=MainPID", "--value")
		if e == nil {
			n, _ := parseUint(strings.TrimSpace(string(b)))
			pid = int(n)
		}
	}
	for _, port := range []int{80, 443} {
		listeners, e := r.listeners(port)
		if e != nil {
			return e
		}
		for _, l := range listeners {
			if l.Owner != "caddy" || pid == 0 || l.PID != pid {
				return fmt.Errorf("TCP port %d is occupied by %s (PID %d); existing services will not be stopped", port, l.Owner, l.PID)
			}
		}
	}
	return nil
}

// HTTPSReport separates origin-local, DNS-path and independent external evidence.
type SubscriptionHTTPSReport struct {
	Domain                           string
	Settings                         SubscriptionSettings
	DNS                              httpsDNS
	Ports                            map[int][]httpsListener
	Installed, Running, LocalRunning bool
	Route                            httpsRoute
	Ownership                        string
	ConfigFile, Renewal, LastError   string
	Verification                     httpsVerification
	Issues                           []string
}

func (a *App) HTTPSDiagnostics() (SubscriptionHTTPSReport, error) {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return SubscriptionHTTPSReport{}, e
	}
	defer unlock()
	return a.httpsDiagnostics()
}
func (a *App) httpsDiagnostics() (SubscriptionHTTPSReport, error) {
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return SubscriptionHTTPSReport{}, e
	}
	saved, e := a.loadHTTPSState()
	if e != nil {
		return SubscriptionHTTPSReport{}, e
	}
	r := a.httpsRuntime()
	out := SubscriptionHTTPSReport{Settings: cfg, Installed: r.installed(), Running: r.running(), Ports: map[int][]httpsListener{}, Ownership: "external / unverified", LastError: saved.LastError, Renewal: "external renewal policy not verified"}
	parsed, _ := url.Parse(cfg.PublicURL)
	if parsed != nil {
		out.Domain = parsed.Hostname()
	}
	if out.Domain == "" {
		out.Domain = saved.Domain
	}
	if out.Domain != "" {
		out.DNS = r.dns(out.Domain)
	}
	for _, port := range []int{80, 443} {
		ls, er := r.listeners(port)
		if er != nil {
			out.Issues = append(out.Issues, er.Error())
		}
		out.Ports[port] = ls
	}
	if m, er := r.manager(); er == nil && m != "none" {
		out.LocalRunning = serviceActive(m, a.subscriptionService())
	}
	if out.Installed {
		if active, er := r.active(); er == nil {
			out.Route = inspectCaddyDomain(active, out.Domain, cfg.listenPort())
			if caddyAutomaticHTTPS(active) {
				out.Renewal = "Caddy automatic HTTPS; last renewal event not independently verified"
			}
		}
	}
	if (saved.Ownership == "managed" || saved.Ownership == "adopted") && !saved.Removed {
		if _, er := a.ownedHTTPSFile(saved); er == nil {
			out.Ownership = "Rout / " + saved.Ownership
			if !httpsOwnsPublicURL(saved, cfg.PublicURL) {
				out.Ownership = "external current URL / separate Rout-owned site retained"
			}
			out.ConfigFile = saved.File
		} else {
			out.Issues = append(out.Issues, er.Error())
			out.Ownership = "modified / ownership not verified"
		}
	} else if out.Installed && out.Route.Found && out.Route.Correct && !out.Route.Conflict {
		out.Ownership = "external / existing Caddy configuration"
	}
	if cfg.Enabled && cfg.PublicURL != "" {
		token, body, cleanup, er := a.beginSubscriptionProbe()
		if er != nil {
			out.Issues = append(out.Issues, "cannot create the short-lived verification capability")
		} else {
			out.Verification = r.verify(cfg.PublicURL, cfg.listenPort(), token, body)
			if r.external != nil && out.Verification.PublicFromHost {
				if er = r.external(cfg.PublicURL, token, body); er == nil {
					out.Verification.External = true
				}
			}
			if er = cleanup(); er != nil {
				return out, fmt.Errorf("remove expired diagnostic hash file %s: %w", a.subscriptionProbeFile(), er)
			}
		}
	}
	return out, nil
}
func (a *App) ownedHTTPSFile(s subscriptionHTTPSState) (subscriptionFileSnapshot, error) {
	r := a.httpsRuntime()
	if (s.Ownership != "managed" && s.Ownership != "adopted") || s.File == "" || !safeProxyPath(r.root, s.File) || s.Main != a.httpsMain() {
		return subscriptionFileSnapshot{}, errors.New("HTTPS configuration is externally managed; automatic modification/removal is refused")
	}
	f, e := snapshotSubscriptionFile(s.File)
	if e != nil {
		return f, e
	}
	if !f.Exists || hashToken(string(f.Data)) != s.Digest {
		return f, errors.New("Rout HTTPS configuration changed externally; preserve it and inspect ownership before continuing")
	}
	return f, nil
}

// UseExistingSubscriptionHTTPS verifies the existing endpoint and saves its base URL
// without claiming, rewriting, reloading or reinstalling any Caddy resource.
func (a *App) UseExistingSubscriptionHTTPS(domain string) (err error) {
	domain, e := subscriptionDomain(domain)
	if e != nil {
		return e
	}
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return errors.New("enable the loopback subscription service first")
	}
	base := "https://" + domain
	if u, _ := url.Parse(cfg.PublicURL); u != nil && u.Hostname() == domain {
		base = cfg.PublicURL
	}
	token, body, cleanup, e := a.beginSubscriptionProbe()
	if e != nil {
		return e
	}
	result := a.httpsRuntime().verify(base, cfg.listenPort(), token, body)
	e = cleanup()
	if e != nil {
		return e
	}
	if !result.LocalService || !result.PublicFromHost {
		return errors.New("existing HTTPS endpoint could not be authenticated; no configuration or token was changed")
	}
	previous, e := a.loadHTTPSState()
	if e != nil {
		return e
	}
	if cfg.PublicURL == base && previous.Ownership == "external" && previous.Domain == domain {
		return nil
	}
	snapshots, e := a.backupSubscriptionFiles("https-external", a.httpsStatePath(), filepath.Join(a.Home, "settings.json"), filepath.Join(a.Home, "state.json"))
	if e != nil {
		return e
	}
	before := cfg
	metadataChanged := false
	defer func() {
		if err != nil {
			var rollback []error
			if cfg != before {
				rollback = append(rollback, a.saveSubscriptionSettings(before))
			}
			if metadataChanged {
				rollback = append(rollback, snapshots[0].restore())
			}
			if rb := errors.Join(rollback...); rb != nil {
				err = errors.Join(err, fmt.Errorf("endpoint-selection rollback incomplete: %w; inspect %s", rb, snapshots[0].backup))
			}
		}
	}()
	if cfg.PublicURL != base {
		cfg.PublicURL = base
		if e = a.saveSubscriptionSettings(cfg); e != nil {
			return e
		}
	}
	if previous.Ownership == "managed" || previous.Ownership == "adopted" {
		return nil
	}
	metadataChanged = true
	return a.saveHTTPSState(subscriptionHTTPSState{Domain: domain, Ownership: "external"})
}

// adoptableHTTPSFile accepts ONLY a literal, standalone single-site fragment.
// Complex snippets, shared blocks, imports, manual certs and root Caddyfiles remain
// external. No parser attempts to carve a site out of a shared file.
func (a *App) adoptableHTTPSFile(domain string, port int) (string, error) {
	main, _, e := a.checkCaddyLayout()
	if e != nil {
		return "", e
	}
	var candidates []string
	for _, line := range strings.Split(string(main.Data), "\n") {
		fields := strings.Fields(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
		if len(fields) != 2 || fields[0] != "import" {
			continue
		}
		pattern := fields[1]
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(filepath.Dir(main.Path), pattern)
		}
		files, _ := filepath.Glob(pattern)
		for _, path := range files {
			if path == main.Path || !safeProxyPath(a.httpsRuntime().root, path) {
				continue
			}
			f, er := snapshotSubscriptionFile(path)
			if er != nil || !f.Exists || f.Mode&0022 != 0 {
				continue
			}
			var text []string
			for _, row := range strings.Split(string(f.Data), "\n") {
				text = append(text, strings.SplitN(row, "#", 2)[0])
			}
			literal := `^\s*(?:https://)?` + regexp.QuoteMeta(domain) + `\s*\{\s*reverse_proxy\s+127\.0\.0\.1:` + itoa(port) + `\s*\}\s*$`
			if regexp.MustCompile(literal).MatchString(strings.Join(text, "\n")) {
				candidates = append(candidates, path)
			}
		}
	}
	if len(candidates) != 1 {
		return "", errors.New("safe adoption requires exactly one separately imported, single-domain reverse-proxy fragment; keep this site externally managed")
	}
	return candidates[0], nil
}
func (a *App) AdoptSubscriptionHTTPS(domain string) (err error) {
	domain, e := subscriptionDomain(domain)
	if e != nil {
		return e
	}
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	if e = a.requireHTTPSManagement(); e != nil {
		return e
	}
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	previous, e := a.loadHTTPSState()
	if e != nil {
		return e
	}
	path, e := a.adoptableHTTPSFile(domain, cfg.listenPort())
	if e != nil {
		return e
	}
	if (previous.Ownership == "managed" || previous.Ownership == "adopted") && !previous.Removed && previous.File != path {
		return errors.New("another HTTPS resource already belongs to Rout; preserve it before adopting a different file")
	}
	token, body, cleanup, e := a.beginSubscriptionProbe()
	if e != nil {
		return e
	}
	result := a.httpsRuntime().verify("https://"+domain, cfg.listenPort(), token, body)
	e = cleanup()
	if e != nil {
		return e
	}
	if !result.LocalService || !result.PublicFromHost {
		return errors.New("existing endpoint verification failed; ownership was not transferred")
	}
	checked, e := a.adoptableHTTPSFile(domain, cfg.listenPort())
	if e != nil || checked != path {
		return errors.New("external configuration changed during adoption; no ownership transferred")
	}
	snapshots, e := a.backupSubscriptionFiles("adoption", path, a.httpsStatePath(), filepath.Join(a.Home, "settings.json"), filepath.Join(a.Home, "state.json"))
	if e != nil {
		return e
	}
	changed := false
	defer func() {
		if err != nil && changed {
			err = errors.Join(err, snapshots[1].restore(), a.saveSubscriptionSettings(cfg))
		}
	}()
	// No file movement, edits or Caddy reload: adoption only records explicit rights
	// over this one verified file. Shared imports/certificates remain external.
	changed = true
	if e = a.saveHTTPSState(subscriptionHTTPSState{Domain: domain, Domains: []string{domain}, Ownership: "adopted", Main: a.httpsMain(), File: path, Digest: hashToken(string(snapshots[0].Data))}); e != nil {
		return e
	}
	next := cfg
	next.PublicURL = "https://" + domain
	if httpsOwnsPublicURL(subscriptionHTTPSState{Domain: domain}, cfg.PublicURL) {
		next.PublicURL = cfg.PublicURL
	}
	if next != cfg {
		return a.saveSubscriptionSettings(next)
	}
	return nil
}

func restoreSubscriptionFiles(snapshots []subscriptionFileSnapshot) error {
	var errs []error
	for _, s := range snapshots {
		if e := s.restore(); e != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", s.Path, e))
		}
	}
	return errors.Join(errs...)
}
func sameFileSnapshot(s subscriptionFileSnapshot) bool {
	now, e := snapshotSubscriptionFile(s.Path)
	return e == nil && s.Exists == now.Exists && (!s.Exists || bytes.Equal(s.Data, now.Data) && s.Mode == now.Mode && s.UID == now.UID && s.GID == now.GID)
}

func httpsOwnsPublicURL(s subscriptionHTTPSState, raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Path != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	return s.Domain == u.Hostname() || contains(s.Domains, u.Hostname())
}
