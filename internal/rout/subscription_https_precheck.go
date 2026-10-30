package rout

import (
	"errors"
	"net/url"
	"os"
)

// Before an automatic deployment Rout must tell apart five situations that look alike
// from a saved public URL alone. Only the third one may stop the deployment:
//
//  1. nothing was ever set up for the domain (fresh)
//  2. a saved URL names the domain but nothing serves it any more (stale; Caddy removed,
//     stopped, or running without a site) -> redeploy
//  3. a Caddy site exists for the domain but does not authenticate -> preserve it, explain
//  4. nothing serves the domain but TCP 80/443 belong to something else -> the
//     deployment's own port check refuses, without stopping that service
//  5. an HTTPS endpoint works but is not managed by Rout -> offer to use it as it is
//
// Recognizing a saved URL is never evidence that a site exists.

type httpsSiteState int

const (
	httpsSiteNone    httpsSiteState = iota // nothing serves the domain (fresh, or a stale saved URL)
	httpsSiteWorking                       // an HTTPS endpoint answers Rout's authenticated probe
	httpsSiteBroken                        // a Caddy site for the domain exists but does not authenticate
)

type httpsPrecheck struct {
	State httpsSiteState
	// Stale: the saved public URL (or Rout's own recorded fragment) names a deployment
	// that no longer exists. Absence names why, in stable English.
	Stale        bool
	OwnedMissing bool
	Absence      string
	// Failure is the stable English diagnosis for httpsSiteBroken.
	Failure      string
	Verification httpsVerification
}

// Stable diagnostics. Each is a catalog entry (messages.json), so the CLI shows the
// selected language while automation keeps matching the English text.
const (
	msgHTTPSNoCaddy            = "Caddy is not installed"
	msgHTTPSCaddyStopped       = "Caddy is installed but not running"
	msgHTTPSCaddyNoSite        = "Caddy is running but has no site for this domain"
	msgHTTPSCaddyUninspectable = "Caddy is running but its configuration cannot be inspected (admin API unavailable)"
	msgHTTPSNoEndpoint         = "no HTTPS endpoint answers for this domain"
	msgHTTPSOwnedMissing       = "the Rout-managed HTTPS configuration file no longer exists"
	msgSiteStopped             = "a Caddy site for this domain exists in the Caddyfile but Caddy is not running; the configuration was preserved, review it and start Caddy yourself, or use it externally"
	msgSiteCertificate         = "existing Caddy site found for this domain but its HTTPS certificate is not valid; the configuration was preserved, inspect HTTPS diagnostics"
	msgSiteAuthentication      = "existing Caddy site found for this domain but it does not forward the authenticated subscription probe to Rout; the configuration was preserved, check its upstream port and path rules"
	msgSitePublicPath          = "existing Caddy site found for this domain and it works on this server but not through public DNS; the configuration was preserved, check the A/AAAA records, any CDN proxy and the firewall"
	msgSiteUnverified          = "existing Caddy site found but its authenticated endpoint is not verified; preserve it and inspect HTTPS diagnostics"
	msgLocalServiceDown        = "the local subscription service did not answer the verification probe; restart it with 'sudo rout subscription restart' and retry"
	msgDeployCertificate       = "HTTPS certificate verification failed; the certificate is not valid for this domain yet, check DNS, inbound TCP 80/443, Cloudflare DNS-only mode and ACME reachability"
	msgDeployAuthentication    = "HTTPS answers but the authenticated subscription probe did not reach Rout; check the upstream port and refresh the subscription helper"
	msgDeployPublicPath        = "HTTPS works on this server but not through public DNS; check every A/AAAA record, any CDN proxy and the provider firewall"
	msgDeployNoResponse        = "HTTPS certificate/response verification failed; check every DNS record, inbound TCP 80/443, Cloudflare DNS-only mode and ACME reachability"
	msgConfirmStartCaddy       = "existing Caddy is installed but stopped; starting it also activates every site in its Caddyfile, so it needs explicit confirmation; no files changed"
)

// siteFailure and deployFailure turn a failed verification into the one sentence that
// names the layer that failed. The layers are checked from the inside out.
func siteFailure(v httpsVerification) string {
	switch {
	case !v.LocalService:
		return msgLocalServiceDown
	case v.CertificateError:
		return msgSiteCertificate
	case v.Answered:
		return msgSiteAuthentication
	case v.LocalTLS && !v.PublicFromHost:
		return msgSitePublicPath
	}
	return msgSiteUnverified
}

func deployFailure(v httpsVerification) string {
	switch {
	case !v.LocalService:
		return msgLocalServiceDown
	case v.CertificateError:
		return msgDeployCertificate
	case v.Answered:
		return msgDeployAuthentication
	case v.LocalTLS && !v.PublicFromHost:
		return msgDeployPublicPath
	}
	return msgDeployNoResponse
}

// stoppedCaddyRoute reads, never writes, the Caddyfile of an installed but stopped Caddy,
// so a site configured there is recognized even though the admin API is down.
func (a *App) stoppedCaddyRoute(domain string, port int) httpsRoute {
	r := a.httpsRuntime()
	main := a.httpsMain()
	if !r.installed() || r.running() || !safeProxyPath(r.root, main) {
		return httpsRoute{}
	}
	if st, e := os.Stat(main); e != nil || !st.Mode().IsRegular() {
		return httpsRoute{}
	}
	adapted, e := r.run("", "caddy", "adapt", "--config", main, "--adapter", "caddyfile")
	if e != nil {
		return httpsRoute{}
	}
	return inspectCaddyDomain(adapted, domain, port)
}

// ownedFragmentMissing reports that Rout recorded a fragment of its own which no longer
// exists (Caddy was uninstalled, /etc/caddy was purged). Nothing is left to protect, so
// the deployment may rebuild it. A fragment that exists but differs from the recorded
// digest is never "missing": that is an external edit and stays protected.
func (a *App) ownedFragmentMissing(s subscriptionHTTPSState) bool {
	r := a.httpsRuntime()
	if (s.Ownership != "managed" && s.Ownership != "adopted") || s.File == "" || s.Main != a.httpsMain() || !safeProxyPath(r.root, s.File) {
		return false
	}
	_, e := os.Lstat(s.File)
	return os.IsNotExist(e)
}

func (a *App) httpsAbsence(route httpsRoute, inspectable bool) string {
	r := a.httpsRuntime()
	switch {
	case !r.installed():
		return msgHTTPSNoCaddy
	case !r.running():
		return msgHTTPSCaddyStopped
	case !inspectable:
		return msgHTTPSCaddyUninspectable
	case !route.Found:
		return msgHTTPSCaddyNoSite
	}
	return msgHTTPSNoEndpoint
}

// precheckSubscriptionHTTPS classifies what currently serves the domain. It changes
// nothing; the only side effect is the short-lived hash-only verification capability,
// which is always removed again. An error means the check itself could not be made,
// or that the local subscription service is down (deploying would only fail later).
func (a *App) precheckSubscriptionHTTPS(domain string) (httpsPrecheck, error) {
	out := httpsPrecheck{}
	r := a.httpsRuntime()
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return out, e
	}
	saved, e := a.loadHTTPSState()
	if e != nil {
		return out, e
	}
	if (saved.Ownership == "managed" || saved.Ownership == "adopted") && !saved.Removed {
		// Rout owns this deployment: repairing it is exactly what was asked for. Only
		// tell the user when its file has vanished, so the redeployment is explained.
		if a.ownedFragmentMissing(saved) {
			out.Stale, out.OwnedMissing = true, true
			out.Absence = msgHTTPSOwnedMissing
		}
		return out, nil
	}
	route := httpsRoute{}
	active, activeErr := r.active()
	if activeErr == nil {
		route = inspectCaddyDomain(active, domain, cfg.listenPort())
	}
	configuredOnly := false
	if !route.Found {
		if route = a.stoppedCaddyRoute(domain, cfg.listenPort()); route.Found {
			configuredOnly = true
		}
	}
	configured, _ := url.Parse(cfg.PublicURL)
	savedURL := configured != nil && configured.Hostname() == domain
	if !route.Found && !savedURL {
		return out, nil // fresh: nothing to protect, nothing to explain
	}

	token, body, cleanup, e := a.beginSubscriptionProbe()
	if e != nil {
		return out, e
	}
	base := "https://" + domain
	if savedURL {
		base = cfg.PublicURL
	}
	out.Verification = r.verify(base, cfg.listenPort(), token, body)
	if e = cleanup(); e != nil {
		return out, e
	}
	switch v := out.Verification; {
	case !v.LocalService:
		// Rout's own loopback service is down. That is not an HTTPS problem and no
		// amount of redeploying Caddy fixes it, so say so before touching anything.
		return out, errors.New(msgLocalServiceDown)
	case v.PublicFromHost:
		out.State = httpsSiteWorking
	case configuredOnly:
		out.State, out.Failure = httpsSiteBroken, msgSiteStopped
	case route.Found:
		out.State, out.Failure = httpsSiteBroken, siteFailure(v)
	default:
		out.Stale, out.Absence = true, a.httpsAbsence(route, activeErr == nil)
	}
	return out, nil
}
