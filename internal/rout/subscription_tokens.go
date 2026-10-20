package rout

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

var errSubscriptionTokens = errors.New("无法读取或保存订阅令牌文件；请检查 secrets 目录权限 0700、文件权限 0600 及文件内容；原有订阅认证不受影响")

func (a *App) subscriptionTokensPath() string {
	return filepath.Join(a.Home, "secrets", "subscription-tokens.json")
}

// This private CLI convenience file is deliberately outside State, HTTP serving,
// diagnostics and all automatic/manual state backups. A missing file is legacy
// hash-only storage, not a reason to generate or rotate a token.
func (a *App) loadSubscriptionTokens() (map[string]string, error) {
	path := a.subscriptionTokensPath()
	for _, p := range []string{filepath.Dir(path), path} {
		st, e := os.Lstat(p)
		if os.IsNotExist(e) {
			return map[string]string{}, nil
		}
		if e != nil {
			return nil, errSubscriptionTokens
		}
		if p == path {
			if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 64<<10 {
				return nil, errSubscriptionTokens
			}
		} else if !st.IsDir() || st.Mode().Perm() != 0700 {
			return nil, errSubscriptionTokens
		}
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, errSubscriptionTokens
	}
	var saved map[string]string
	if json.Unmarshal(b, &saved) != nil || saved == nil {
		return nil, errSubscriptionTokens
	}
	for hash, token := range saved {
		if !tokenHashPattern.MatchString(hash) || !tokenPattern.MatchString(token) || hashToken(token) != hash {
			return nil, errSubscriptionTokens
		}
	}
	return saved, nil
}

// Called under the configuration lock, before publishing the new state hash.
// Retain all currently referenced tokens until that commit succeeds. Thus either
// side of an interrupted rotation remains displayable, without a journal or a
// second authentication mechanism. The next token write prunes obsolete hashes;
// at most maxSubscriptions+1 entries remain. Revoked tokens never authenticate.
func (a *App) saveSubscriptionTokens(old State, tokens []string) error {
	saved, e := a.loadSubscriptionTokens()
	if e != nil {
		return e
	}
	keep := map[string]string{}
	for _, sub := range old.Subscriptions {
		if token := saved[sub.TokenHash]; token != "" {
			keep[sub.TokenHash] = token
		}
	}
	for _, token := range tokens {
		if !tokenPattern.MatchString(token) {
			return errSubscriptionTokens
		}
		keep[hashToken(token)] = token
	}
	path := a.subscriptionTokensPath()
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return errSubscriptionTokens
	}
	b, e := JSON(keep)
	if e != nil {
		return errSubscriptionTokens
	}
	if e = AtomicWrite(path, b, 0600); e != nil {
		return errSubscriptionTokens
	}
	return nil
}
