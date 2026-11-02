package rout

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The web management panel (rout-web) is a separate, loopback-only HTTP service. Its only
// secret is the administrator password hash, kept in <home>/web.json (0600). The panel can
// start and stop services and edit the whole configuration, so it never listens on a public
// address: HTTPS is provided by a reverse proxy in front of it.

const (
	webSchema          = 1
	webDefaultPort     = 8790
	webMinPassword     = 12
	webMaxPassword     = 256
	webDefaultIdleMin  = 60
	webDefaultMaxHours = 12
)

// webPBKDF2Iterations is a variable only so tests can lower the cost.
var webPBKDF2Iterations = 600000

type WebConfig struct {
	Schema int `json:"schema"`
	Port   int `json:"port,omitempty"`
	// PasswordHash is "pbkdf2-sha256$iterations$salt$hash" (base64). Empty until a password
	// has been set from the command line; the panel refuses every login until then.
	PasswordHash      string    `json:"password_hash,omitempty"`
	PasswordChangedAt time.Time `json:"password_changed_at,omitempty"`
	// AllowedHosts are the extra Host header values accepted besides loopback names (the
	// public domain of the HTTPS reverse proxy).
	AllowedHosts    []string `json:"allowed_hosts,omitempty"`
	SessionIdleMin  int      `json:"session_idle_min,omitempty"`
	SessionMaxHours int      `json:"session_max_hours,omitempty"`
	// SecureCookie forces the Secure attribute even when the request does not say it came
	// over HTTPS (the proxy normally sets X-Forwarded-Proto).
	SecureCookie bool `json:"secure_cookie,omitempty"`
	// HTTPSDomain records the domain deployed by `rout web https`.
	HTTPSDomain string `json:"https_domain,omitempty"`
}

func (c WebConfig) port() int {
	if c.Port == 0 {
		return webDefaultPort
	}
	return c.Port
}
func (c WebConfig) idle() time.Duration {
	if c.SessionIdleMin <= 0 {
		return webDefaultIdleMin * time.Minute
	}
	return time.Duration(c.SessionIdleMin) * time.Minute
}
func (c WebConfig) maxAge() time.Duration {
	if c.SessionMaxHours <= 0 {
		return webDefaultMaxHours * time.Hour
	}
	return time.Duration(c.SessionMaxHours) * time.Hour
}

func (c WebConfig) Validate() error {
	if c.Schema != webSchema {
		return errors.New("不支持的面板配置版本")
	}
	if c.Port != 0 && (c.Port < 1024 || c.Port > 65535) {
		return errors.New("面板端口应在 1024–65535 之间")
	}
	if len(c.AllowedHosts) > 8 {
		return errors.New("允许的主机名最多 8 个")
	}
	for _, h := range c.AllowedHosts {
		if _, e := normalizeWebHost(h); e != nil {
			return e
		}
	}
	if c.SessionIdleMin < 0 || c.SessionIdleMin > 24*60 || c.SessionMaxHours < 0 || c.SessionMaxHours > 24*30 {
		return errors.New("会话时长设置无效")
	}
	if c.PasswordHash != "" {
		if _, _, _, e := parsePasswordHash(c.PasswordHash); e != nil {
			return e
		}
	}
	return nil
}

// normalizeWebHost accepts a bare host name or IP, with an optional port, and returns the
// lower-case host:port or host form used for comparison with the Host header.
func normalizeWebHost(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	host, port := raw, ""
	if h, p, e := net.SplitHostPort(raw); e == nil {
		host, port = h, p
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.Trim(raw, "[]")
	}
	if port != "" {
		if n, e := strconv.Atoi(port); e != nil || n < 1 || n > 65535 {
			return "", errors.New("主机名端口无效")
		}
	}
	if net.ParseIP(host) == nil {
		d, e := subscriptionDomain(host)
		if e != nil {
			return "", errors.New("主机名无效")
		}
		host = d
	}
	if port != "" {
		return net.JoinHostPort(host, port), nil
	}
	return host, nil
}

func (a *App) webConfigPath() string { return filepath.Join(a.Home, "web.json") }

func (a *App) LoadWebConfig() (WebConfig, error) {
	b, e := os.ReadFile(a.webConfigPath())
	if os.IsNotExist(e) {
		return WebConfig{Schema: webSchema}, nil
	}
	if e != nil {
		return WebConfig{}, e
	}
	var c WebConfig
	if e = json.Unmarshal(b, &c); e != nil {
		return WebConfig{}, errors.New("面板配置文件无效")
	}
	if e = c.Validate(); e != nil {
		return WebConfig{}, e
	}
	return c, nil
}

func (a *App) saveWebConfig(c WebConfig) error {
	c.Schema = webSchema
	if e := c.Validate(); e != nil {
		return e
	}
	b, e := JSON(c)
	if e != nil {
		return e
	}
	return AtomicWrite(a.webConfigPath(), b, 0600)
}

// mutateWebConfig changes web.json under a lock, so a password change and a settings change
// cannot overwrite each other.
func (a *App) mutateWebConfig(change func(*WebConfig) error) error {
	unlock, e := lockFile(filepath.Join(a.Home, ".web.lock"), 10*time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	c, e := a.LoadWebConfig()
	if e != nil {
		return e
	}
	if e = change(&c); e != nil {
		return e
	}
	return a.saveWebConfig(c)
}

// ---- password hashing ------------------------------------------------------------------

// pbkdf2SHA256 is PBKDF2 (RFC 8018) with HMAC-SHA-256; the standard library only gained it
// in Go 1.24 and the module supports Go 1.23.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	var counter [4]byte
	u := make([]byte, hashLen)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		prf.Write(counter[:])
		u = prf.Sum(u[:0])
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func checkPasswordStrength(pw string) error {
	if !utf8.ValidString(pw) || strings.ContainsAny(pw, "\x00\r\n") {
		return errors.New("密码含有无效字符")
	}
	if n := utf8.RuneCountInString(pw); n < webMinPassword || len(pw) > webMaxPassword {
		return fmt.Errorf("密码长度应为 %d–%d 个字符", webMinPassword, webMaxPassword)
	}
	return nil
}

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	key := pbkdf2SHA256([]byte(pw), salt, webPBKDF2Iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", webPBKDF2Iterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func parsePasswordHash(h string) (iterations int, salt, key []byte, err error) {
	parts := strings.Split(h, "$")
	bad := errors.New("面板密码记录无效")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return 0, nil, nil, bad
	}
	iterations, e := strconv.Atoi(parts[1])
	if e != nil || iterations < 1000 || iterations > 10_000_000 {
		return 0, nil, nil, bad
	}
	if salt, e = base64.RawStdEncoding.DecodeString(parts[2]); e != nil || len(salt) < 16 {
		return 0, nil, nil, bad
	}
	if key, e = base64.RawStdEncoding.DecodeString(parts[3]); e != nil || len(key) != 32 {
		return 0, nil, nil, bad
	}
	return iterations, salt, key, nil
}

// verifyPassword compares in constant time. A missing password never verifies; the work is
// still done so that "no password set" is not distinguishable by timing.
func verifyPassword(hash, pw string) bool {
	iterations, salt, key, e := parsePasswordHash(hash)
	if e != nil {
		pbkdf2SHA256([]byte(pw), make([]byte, 16), webPBKDF2Iterations, 32)
		return false
	}
	got := pbkdf2SHA256([]byte(pw), salt, iterations, 32)
	return subtle.ConstantTimeCompare(got, key) == 1
}

// webNow is the wall clock the panel records; tests substitute a fake one.
func (a *App) webNow() time.Time {
	if a.webHooks != nil && a.webHooks.now != nil {
		return a.webHooks.now().UTC()
	}
	return time.Now().UTC()
}

// SetWebPassword stores a new password hash after checking its strength.
func (a *App) SetWebPassword(pw string) error {
	if e := checkPasswordStrength(pw); e != nil {
		return e
	}
	h, e := hashPassword(pw)
	if e != nil {
		return e
	}
	return a.mutateWebConfig(func(c *WebConfig) error {
		c.PasswordHash, c.PasswordChangedAt = h, a.webNow()
		return nil
	})
}

// GenerateWebPassword returns a random password that satisfies the strength rules.
func GenerateWebPassword() string {
	b := make([]byte, 18)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
