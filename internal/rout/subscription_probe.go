package rout

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The diagnostic credential is random, header-only, never logged and never stored.
// Its hash authorizes only a synthetic response, never access to real subscriptions.
// The existing /s/{token} authentication and output remain unchanged.
const subscriptionProbePath = "/s/_rout_probe"

type subscriptionProbe struct {
	Hash    string    `json:"hash"`
	Expires time.Time `json:"expires"`
	Body    string    `json:"body"`
}

func (a *App) subscriptionProbeFile() string {
	return filepath.Join(a.Home, ".subscription-https-probe.json")
}

func (a *App) beginSubscriptionProbe() (string, string, func() error, error) {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription-probe.lock"), trafficLockWait)
	if e != nil {
		return "", "", nil, e
	}
	token, hash, e := newSubscriptionToken()
	if e != nil {
		unlock()
		return "", "", nil, e
	}
	// A syntactically valid, inert share link: no real credential or node is used.
	body := renderSubscription([]string{"vless://00000000-0000-4000-8000-000000000000@127.0.0.1:9?encryption=none#Rout-HTTPS-check-" + RandomHex(12)})
	p := subscriptionProbe{Hash: hash, Expires: time.Now().Add(2 * time.Minute), Body: body}
	b, e := json.Marshal(p)
	if e == nil {
		e = AtomicWrite(a.subscriptionProbeFile(), b, 0600)
	}
	if e != nil {
		remove := os.Remove(a.subscriptionProbeFile())
		if os.IsNotExist(remove) {
			remove = nil
		}
		unlock()
		return "", "", nil, errors.Join(e, remove)
	}
	var once sync.Once
	var cleanupErr error
	cleanup := func() error {
		once.Do(func() {
			defer unlock()
			e := os.Remove(a.subscriptionProbeFile())
			if !os.IsNotExist(e) {
				cleanupErr = e
			}
		})
		return cleanupErr
	}
	return token, body, cleanup, nil
}

func (a *App) serveSubscriptionProbe(w http.ResponseWriter, r *http.Request) {
	credential, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !tokenPattern.MatchString(credential) {
		notFound(w)
		return
	}
	path := a.subscriptionProbeFile()
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 4096 {
		notFound(w)
		return
	}
	b, e := os.ReadFile(path)
	var p subscriptionProbe
	if e != nil || json.Unmarshal(b, &p) != nil || !tokenHashPattern.MatchString(p.Hash) ||
		!time.Now().Before(p.Expires) || p.Expires.After(time.Now().Add(2*time.Minute)) ||
		subtle.ConstantTimeCompare([]byte(hashToken(credential)), []byte(p.Hash)) != 1 {
		notFound(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		plain(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Method == http.MethodHead {
		plain(w, http.StatusOK, "")
		return
	}
	plain(w, http.StatusOK, p.Body)
}

var errSubscriptionProbe = errors.New("subscription response verification failed; no existing token was used or changed")

// Refinements of errSubscriptionProbe (errors.Is still matches it) that let a failed
// HTTPS check say which layer failed: the certificate, or the answer behind it.
var (
	errSubscriptionProbeCertificate = fmt.Errorf("%w: certificate refused", errSubscriptionProbe)
	errSubscriptionProbeResponse    = fmt.Errorf("%w: unexpected response", errSubscriptionProbe)
)
