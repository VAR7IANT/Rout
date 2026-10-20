package rout

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errSubscriptionExternalHTTPS = errors.New("compatible external Caddy site detected; use the existing endpoint or explicitly adopt an isolated fragment")

func (a *App) requireHTTPSManagement() error {
	r := a.httpsRuntime()
	m, e := r.manager()
	if e != nil || m != "systemd" {
		return errors.New("automatic Caddy management requires systemd on Debian/Ubuntu; use an externally managed HTTPS proxy on this platform")
	}
	if id := r.osID(); id != "debian" && id != "ubuntu" {
		return errors.New("automatic Caddy deployment is supported on Debian/Ubuntu only; existing external HTTPS endpoints remain usable")
	}
	return nil
}

// Install permission is supplied only after a separate explicit CLI confirmation.
// Installing a package never permits stopping a listener that was already present.
func (a *App) DeploySubscriptionHTTPS(domain string, allowInstall bool) (err error) {
	domain, err = subscriptionDomain(domain)
	if err != nil {
		return err
	}
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	return a.deploySubscriptionHTTPSLocked(domain, allowInstall)
}
func (a *App) deploySubscriptionHTTPSLocked(domain string, allowInstall bool) (err error) {
	var e error
	if e = a.requireHTTPSManagement(); e != nil {
		return e
	}
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return errors.New("enable the loopback subscription service before deploying HTTPS")
	}
	previous, e := a.loadHTTPSState()
	if e != nil {
		return e
	}
	r := a.httpsRuntime()
	dns := r.dns(domain)
	if dns.Error != "" {
		return errors.New(dns.Error)
	}
	if e = a.checkHTTPSPorts(); e != nil {
		return e
	}
	wasInstalled, wasRunning := r.installed(), r.running()
	wasEnabled := false
	if wasInstalled {
		_, e = r.run("", "systemctl", "is-enabled", "caddy")
		wasEnabled = e == nil
	}
	installedNow := false
	// Package installation can start the vendor service. On any subsequent failure,
	// restore its prior stopped/disabled state; the package itself is retained.
	defer func() {
		if err != nil && installedNow && !wasRunning && r.installed() {
			_, stop := r.run("", "systemctl", "stop", "caddy")
			_, disable := r.run("", "systemctl", "disable", "caddy")
			err = errors.Join(err, stop, disable)
			if stop != nil || disable != nil || r.running() {
				err = errors.Join(err, errors.New("rollback incomplete: newly installed Caddy package retained; inspect systemctl status caddy and restore its prior stopped/disabled state"))
			}
		}
	}()
	if !wasInstalled {
		if !allowInstall {
			return errors.New("Caddy installation requires explicit confirmation")
		}
		if _, e = r.run("", "apt-get", "update"); e != nil {
			return e
		}
		installedNow = true
		if _, e = r.run("", "apt-get", "install", "-y", "caddy"); e != nil {
			return e
		}
		if !r.installed() {
			return errors.New("Caddy package installation did not provide a working executable")
		}
		if _, e = r.run("", "caddy", "version"); e != nil {
			return e
		}
	} else if !wasRunning {
		return errors.New("existing Caddy is stopped; review and start its configuration before integrating it, or use an external endpoint; no files changed")
	}
	if e = a.checkHTTPSPorts(); e != nil {
		return e
	}
	main, active, e := a.checkCaddyLayout()
	if e != nil {
		return e
	}
	if !caddyAutomaticHTTPS(active) {
		return errors.New("Caddy automatic certificate management is disabled in the existing configuration; no global TLS policy will be changed")
	}
	route := inspectCaddyDomain(active, domain, cfg.listenPort())
	owned := (previous.Ownership == "managed" || previous.Ownership == "adopted")
	file := a.httpsFile()
	if owned {
		f, er := a.ownedHTTPSFile(previous)
		if er != nil {
			return er
		}
		file = f.Path
	} else if route.Found || route.Correct || route.Conflict {
		if route.Found && route.Correct && !route.Conflict {
			return errSubscriptionExternalHTTPS
		}
		return errors.New("the requested domain already has a Caddy route; it will not be overwritten")
	}
	if owned && domain != previous.Domain && !contains(previous.Domains, domain) && (route.Found || route.Correct || route.Conflict) {
		return errSubscriptionExternalHTTPS
	}
	if !safeProxyPath(r.root, file) {
		return errors.New("unsafe HTTPS fragment path; no configuration changed")
	}
	fragment, e := snapshotSubscriptionFile(file)
	if e != nil {
		return e
	}
	if fragment.Exists && !owned {
		return errors.New("an unowned HTTPS fragment already exists; it will not be overwritten")
	}
	if owned && !previous.Removed && route.Found && route.Correct && !route.Conflict {
		domains := previous.Domains
		if len(domains) == 0 {
			domains = []string{previous.Domain}
		}
		if contains(domains, domain) && bytesEqual(fragment.Data, []byte(renderSubscriptionCaddySites(domains, cfg.listenPort()))) {
			token, body, cleanup, er := a.beginSubscriptionProbe()
			if er != nil {
				return er
			}
			result := r.verify("https://"+domain, cfg.listenPort(), token, body)
			er = cleanup()
			if er != nil {
				return er
			}
			if result.LocalService && result.LocalTLS && result.PublicFromHost {
				if !wasEnabled {
					if _, er = r.run("", "systemctl", "enable", "caddy"); er != nil {
						return er
					}
				}
				if previous.LastError != "" {
					previous.LastError = ""
					return a.saveHTTPSState(previous)
				}
				return nil
			}
		}
	}
	// A frozen/removed site can be redeployed only if the recorded placeholder still
	// matches. Recognition by filename alone never grants ownership.
	snapshots, e := a.backupSubscriptionFiles("https", main.Path, file, a.httpsStatePath(), filepath.Join(a.Home, "settings.json"), filepath.Join(a.Home, "state.json"))
	if e != nil {
		return e
	}
	if !sameFileSnapshot(main) || !sameFileSnapshot(fragment) {
		return errors.New("Caddy files changed during inspection; retry without overwriting the external change")
	}
	expected := map[string]string{}
	activated, urlChanged := false, false
	defer func() {
		if err == nil {
			return
		}
		var rollback []error
		for _, s := range snapshots[:3] {
			if digest, changed := expected[s.Path]; changed {
				if sameFileSnapshot(s) {
					continue
				}
				now, er := snapshotSubscriptionFile(s.Path)
				if er != nil || !now.Exists || hashToken(string(now.Data)) != digest {
					rollback = append(rollback, fmt.Errorf("external change detected at %s; automatic restore refused", s.Path))
					continue
				}
				if er = s.restore(); er != nil {
					rollback = append(rollback, fmt.Errorf("restore %s: %w", s.Path, er))
				}
			}
		}
		if urlChanged {
			rollback = append(rollback, a.saveSubscriptionSettings(cfg))
		}
		if activated && wasRunning {
			_, er := r.run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile")
			rollback = append(rollback, er)
			if er == nil {
				_, er = r.run("", "systemctl", "reload", "caddy")
				rollback = append(rollback, er)
			}
			restored, er := r.active()
			if er != nil || !caddyConfigEqual(restored, active) {
				rollback = append(rollback, errors.New("previous active Caddy configuration could not be verified"))
			}
		}
		if !wasEnabled {
			_, er := r.run("", "systemctl", "disable", "caddy")
			rollback = append(rollback, er)
		}
		for _, s := range snapshots[:3] {
			if _, changed := expected[s.Path]; changed && !sameFileSnapshot(s) {
				rollback = append(rollback, fmt.Errorf("restored file verification failed: %s", s.Path))
			}
		}
		if rb := errors.Join(rollback...); rb != nil {
			err = errors.Join(err, fmt.Errorf("rollback incomplete: %w; recover from %s, validate %s and reload Caddy only after review", rb, snapshots[0].backup, main.Path))
		} else {
			err = fmt.Errorf("%w; previous configuration restored and verified", err)
		}
		// Keep diagnostic errors separate from subscription settings and token hashes.
		if !sameFileSnapshot(snapshots[2]) {
			err = errors.Join(err, errors.New("last error not saved because HTTPS ownership metadata changed externally"))
			return
		}
		previous.LastError = sanitizeSubscriptionLogs([]byte(err.Error()))
		if len(previous.LastError) > 2048 {
			previous.LastError = previous.LastError[:2048]
		}
		if er := a.saveHTTPSState(previous); er != nil {
			err = errors.Join(err, fmt.Errorf("record last HTTPS error: %w", er))
		}
	}()
	domains := []string{domain}
	if owned && !previous.Removed {
		domains = append([]string(nil), previous.Domains...)
		if len(domains) == 0 {
			domains = []string{previous.Domain}
		}
		if !contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	data := []byte(renderSubscriptionCaddySites(domains, cfg.listenPort()))
	// Validate the generated fragment independently before it can replace a file.
	if e = os.MkdirAll(filepath.Dir(file), 0755); e != nil {
		return e
	}
	check, e := os.CreateTemp(filepath.Dir(file), ".rout-validate-*")
	if e != nil {
		return e
	}
	checkPath := check.Name()
	defer os.Remove(checkPath)
	if _, e = check.Write(data); e != nil {
		check.Close()
		return e
	}
	if e = check.Close(); e != nil {
		return e
	}
	if _, e = r.run("", "caddy", "validate", "--config", checkPath, "--adapter", "caddyfile"); e != nil {
		return e
	}
	expected[file] = hashToken(string(data))
	if e = atomicSubscriptionFile(fragment, data, 0644); e != nil {
		return e
	}
	// For a newly managed fragment, add one stable, absolute import. Preserve all
	// pre-existing bytes, comments and imported sites, and validate the full layout.
	if !owned {
		next := append(append([]byte(nil), main.Data...), []byte(a.httpsImport())...)
		if strings.Contains(string(main.Data), a.httpsImport()) {
			next = main.Data
		}
		if !bytesEqual(next, main.Data) {
			expected[main.Path] = hashToken(string(next))
			if e = atomicSubscriptionFile(main, next, main.Mode); e != nil {
				return e
			}
		}
	}
	if _, e = r.run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile"); e != nil {
		return e
	}
	if _, e = r.run("", "systemctl", "enable", "caddy"); e != nil {
		return e
	}
	activated = true
	action := "reload"
	if !r.running() {
		action = "start"
	}
	if _, e = r.run("", "systemctl", action, "caddy"); e != nil {
		return e
	}
	if !r.running() {
		return errors.New("Caddy did not remain running")
	}
	adapted, e := r.run("", "caddy", "adapt", "--config", main.Path, "--adapter", "caddyfile")
	if e != nil {
		return e
	}
	loaded, e := r.active()
	if e != nil || !caddyConfigEqual(adapted, loaded) {
		return errors.New("Caddy reload did not activate the validated configuration; endpoint verification alone cannot prove ownership")
	}
	token, body, cleanup, e := a.beginSubscriptionProbe()
	if e != nil {
		return e
	}
	// Certificate issuance is asynchronous. Retry without logging the capability or
	// accepting a successful write as proof of a working subscription endpoint.
	verified := httpsVerification{}
	deadline := time.Now().Add(r.verificationWait)
	for {
		verified = r.verify("https://"+domain, cfg.listenPort(), token, body)
		if verified.LocalService && verified.LocalTLS && verified.PublicFromHost {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	e = cleanup()
	if e != nil {
		return fmt.Errorf("remove diagnostic hash file %s: %w", a.subscriptionProbeFile(), e)
	}
	if !verified.LocalService || !verified.LocalTLS || !verified.PublicFromHost {
		return errors.New("HTTPS certificate/response verification failed; check every DNS record, inbound TCP 80/443, Cloudflare DNS-only mode and ACME reachability")
	}
	next := cfg
	next.PublicURL = "https://" + domain
	if httpsOwnsPublicURL(subscriptionHTTPSState{Domain: domain}, cfg.PublicURL) {
		next.PublicURL = cfg.PublicURL
	}
	if cfg.PublicURL != next.PublicURL {
		urlChanged = true // An atomic rename can succeed even if the final directory sync fails.
		if e = a.saveSubscriptionSettings(next); e != nil {
			return e
		}
	}
	ownership := "managed"
	if owned {
		ownership = previous.Ownership
	}
	saved := subscriptionHTTPSState{Domain: domain, Domains: domains, Ownership: ownership, Main: main.Path, File: file, Digest: hashToken(string(data))}
	saved.Version = 1
	saved.Updated = time.Now().UTC()
	metadata, e := JSON(saved)
	if e != nil {
		return e
	}
	expected[a.httpsStatePath()] = hashToken(string(metadata))
	if e = atomicSubscriptionFile(snapshots[2], metadata, 0600); e != nil {
		return e
	}

	return nil
}
func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// Removal leaves a harmless placeholder for exact imports. It never stops Caddy,
// removes certificates, clears the public URL, or changes subscription records.
func (a *App) RemoveSubscriptionHTTPS() (err error) {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	if e = a.requireHTTPSManagement(); e != nil {
		return e
	}
	previous, e := a.loadHTTPSState()
	if e != nil {
		return e
	}
	if previous.Removed {
		return nil
	}
	fragment, e := a.ownedHTTPSFile(previous)
	if e != nil {
		return e
	}
	main, active, e := a.checkCaddyLayout()
	if e != nil {
		return e
	}
	snapshots, e := a.backupSubscriptionFiles("https-remove", fragment.Path, a.httpsStatePath())
	if e != nil {
		return e
	}
	changed := false
	placeholder := []byte("# Rout subscription HTTPS removed; subscriptions and certificates preserved\n")
	defer func() {
		if err != nil && changed {
			var rb error
			current, er := snapshotSubscriptionFile(fragment.Path)
			if sameFileSnapshot(fragment) {
				// A failed write before rename left the original fragment intact.
				rb = snapshots[1].restore()
			} else if er != nil || !current.Exists || hashToken(string(current.Data)) != hashToken(string(placeholder)) {
				rb = errors.New("HTTPS fragment changed externally during removal; automatic restore refused")
			} else {
				rb = restoreSubscriptionFiles(snapshots)
			}
			if rb == nil {
				if _, er = a.httpsRuntime().run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile"); er != nil {
					rb = er
				} else {
					_, rb = a.httpsRuntime().run("", "systemctl", "reload", "caddy")
				}
			}
			restored, er := a.httpsRuntime().active()
			if er != nil || !caddyConfigEqual(active, restored) {
				rb = errors.Join(rb, errors.New("old active configuration not verified"))
			}
			if rb != nil {
				err = errors.Join(err, fmt.Errorf("HTTPS removal rollback incomplete: %w; inspect recovery snapshot %s", rb, snapshots[0].backup))
			}
		}
	}()
	if !sameFileSnapshot(fragment) || !sameFileSnapshot(main) {
		return errors.New("Caddy configuration changed before removal; retry inspection")
	}
	changed = true
	if e = atomicSubscriptionFile(fragment, placeholder, fragment.Mode); e != nil {
		return e
	}
	if _, e = a.httpsRuntime().run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile"); e != nil {
		return e
	}
	if _, e = a.httpsRuntime().run("", "systemctl", "reload", "caddy"); e != nil {
		return e
	}
	current, e := a.httpsRuntime().active()
	if e != nil {
		return e
	}
	domains := previous.Domains
	if len(domains) == 0 {
		domains = []string{previous.Domain}
	}
	for _, domain := range domains {
		if inspectCaddyDomain(current, domain, 0).Found {
			return errors.New("removed domain is still present in Caddy; inspect duplicate/shared routes")
		}
	}
	previous.Removed = true
	previous.Digest = hashToken(string(placeholder))
	previous.LastError = ""
	return a.saveHTTPSState(previous)
}
