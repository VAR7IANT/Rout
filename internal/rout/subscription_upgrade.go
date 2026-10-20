package rout

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

// PrepareSubscriptionUpgrade is idempotent and read-only with respect to live
// settings/state. v0.3.5 needs no database migration; this is a recovery snapshot,
// not a new database or a reconstructed set of subscriptions.
func (a *App) PrepareSubscriptionUpgrade() error {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	configUnlock, e := a.lock()
	if e != nil {
		return e
	}
	defer configUnlock()
	state, e := a.Load()
	if e != nil {
		return e
	}
	settings, e := a.LoadSettings()
	if e != nil {
		return e
	}
	if len(state.Subscriptions) == 0 && settings.Subscription == nil {
		return nil
	}
	var files []subscriptionFileSnapshot
	for _, name := range []string{"state.json", "settings.json", "subscription-https.json"} {
		f, e := snapshotSubscriptionFile(filepath.Join(a.Home, name))
		if e != nil {
			return e
		}
		files = append(files, f)
	}
	b, e := JSON(files)
	if e != nil {
		return e
	}
	path := filepath.Join(a.Home, "backups", "subscription-upgrade-v"+Version+"-"+hashToken(string(b))[:16]+".json")
	old, e := os.ReadFile(path)
	if e == nil {
		if !bytes.Equal(old, b) {
			return errors.New("existing subscription upgrade backup does not match; preserve it for inspection")
		}
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	return AtomicWrite(path, b, 0600)
}
