package rout

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Cryptography of the Telegram control plane. Nothing here is novel: HKDF-SHA256, AES-256-GCM,
// HMAC-SHA256, ECDSA P-256 self-signed certificates and TLS 1.3 from the standard library.
//
// Two different trust roots are kept apart on purpose:
//
//   - the Bot Token is a shared secret that every server of the user already holds. It proves
//     "this party was given the token by the user" and is used for (1) finding the hub
//     (the hub's address is published in the private chat, encrypted and authenticated with
//     keys derived from the token) and (2) the enrollment proof. It is NOT machine identity;
//   - machine identity is a per-server ECDSA certificate. The hub's certificate fingerprint is
//     pinned by every agent, every agent's fingerprint is authorized by the hub after a human
//     tapped "Allow" in Telegram (or in the panel). Command traffic is mutually authenticated
//     TLS 1.3 between exactly those pinned identities.

// hkdfSHA256 is RFC 5869 (the standard library only gained crypto/hkdf in Go 1.24 and the
// module supports Go 1.23).
func hkdfSHA256(secret, salt, info []byte, n int) []byte {
	ext := hmac.New(sha256.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// tgKeys are the independent keys derived from one Bot Token.
type tgKeys struct{ announce, callback, enroll []byte }

func deriveTelegramKeys(token string) tgKeys {
	salt := []byte("rout-telegram/v1")
	d := func(label string) []byte { return hkdfSHA256([]byte(token), salt, []byte(label), 32) }
	return tgKeys{announce: d("announce"), callback: d("callback"), enroll: d("enroll")}
}

// macParts is HMAC-SHA256 over length-prefixed parts, so ("ab","c") and ("a","bc") differ.
func macParts(key []byte, parts ...string) []byte {
	m := hmac.New(sha256.New, key)
	var n [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		m.Write(n[:])
		m.Write([]byte(p))
	}
	return m.Sum(nil)
}

func macEqual(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }

// sealB64 encrypts and authenticates with AES-256-GCM; the result is base64url(nonce‖ciphertext).
func sealB64(key, plaintext []byte) (string, error) {
	blk, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(blk)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(g.Seal(nonce, nonce, plaintext, nil)), nil
}

func openB64(key []byte, s string) ([]byte, error) {
	raw, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		return nil, e
	}
	blk, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(blk)
	if e != nil {
		return nil, e
	}
	if len(raw) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("short ciphertext")
	}
	return g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
}

// ---- identity ------------------------------------------------------------------------------

// tgIdentity is one server's long-term identity: a self-signed ECDSA P-256 certificate used as
// both the hub's TLS server certificate and an agent's TLS client certificate.
type tgIdentity struct{ CertPEM, KeyPEM string }

func newTelegramIdentity(serverID string) (tgIdentity, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return tgIdentity{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		return tgIdentity{}, e
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "rout-" + serverID},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(20, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		return tgIdentity{}, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return tgIdentity{}, e
	}
	return tgIdentity{
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})),
	}, nil
}

func (i tgIdentity) tlsCert() (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(i.CertPEM), []byte(i.KeyPEM))
}

// fingerprint is the lower-case hex SHA-256 of the certificate (the value that is pinned).
func (i tgIdentity) fingerprint() string {
	b, _ := pem.Decode([]byte(i.CertPEM))
	if b == nil {
		return ""
	}
	return certFingerprint(b.Bytes)
}

func certFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// fingerprintGroups is what a human compares: 128 bits as eight groups of four.
func fingerprintGroups(fp string) string {
	fp = strings.ToUpper(fp)
	if len(fp) > 32 {
		fp = fp[:32]
	}
	var parts []string
	for len(fp) > 0 {
		n := 4
		if len(fp) < n {
			n = len(fp)
		}
		parts = append(parts, fp[:n])
		fp = fp[n:]
	}
	return strings.Join(parts, " ")
}

// sameFingerprint compares a pinned (full) fingerprint with what a human typed or was shown
// (grouped, possibly truncated to 128 bits, any case).
func sameFingerprint(pinned, shown string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.Map(func(r rune) rune {
			if r == ' ' || r == ':' || r == '-' {
				return -1
			}
			return r
		}, s))
	}
	p, s := norm(pinned), norm(shown)
	if len(s) < 32 || len(s) > len(p) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p[:len(s)]), []byte(s)) == 1
}

// ---- hub announcement ------------------------------------------------------------------------

// tgAnnouncement is what the hub publishes (pinned, in the private chat) so that other servers
// can find it with only the Bot Token and the Chat ID. It is encrypted and authenticated with a
// key derived from the token: the chat shows an opaque string, and only a holder of the token
// can produce or read it.
type tgAnnouncement struct {
	V         int      `json:"v"`
	HubID     string   `json:"h"`
	Name      string   `json:"n"`
	Endpoints []string `json:"e"`
	FP        string   `json:"f"` // full SHA-256 of the hub's certificate
	TS        int64    `json:"t"`
}

const announcePrefix = "rout1."

func (k tgKeys) sealAnnouncement(an tgAnnouncement) (string, error) {
	an.V = 1
	b, e := json.Marshal(an)
	if e != nil {
		return "", e
	}
	s, e := sealB64(k.announce, b)
	if e != nil {
		return "", e
	}
	return announcePrefix + s, nil
}

// announcementText is the pinned chat message. Only the last token matters to the parser.
func announcementText(sealed string) string {
	return "🤖 Rout Control hub address — pinned for your Rout servers, please do not delete or unpin.\n\n" + sealed
}

func (k tgKeys) openAnnouncement(text string) (tgAnnouncement, error) {
	var an tgAnnouncement
	for _, f := range strings.Fields(text) {
		if !strings.HasPrefix(f, announcePrefix) {
			continue
		}
		b, e := openB64(k.announce, strings.TrimPrefix(f, announcePrefix))
		if e != nil {
			return an, errors.New("announcement not authentic for this token")
		}
		if e = json.Unmarshal(b, &an); e != nil || an.V != 1 || an.HubID == "" || len(an.FP) != 64 || len(an.Endpoints) > 8 {
			return tgAnnouncement{}, errors.New("malformed announcement")
		}
		return an, nil
	}
	return an, errors.New("no announcement")
}

// ---- enrollment proof ------------------------------------------------------------------------

// enrollProof binds the hub's one-time challenge, the agent's server ID and the fingerprint of
// the agent's certificate to knowledge of the token. It filters random Internet callers; the
// real authorization is the human approval in Telegram.
func (k tgKeys) enrollProof(nonce, serverID, certFP string) string {
	return hex.EncodeToString(macParts(k.enroll, "enroll1", nonce, serverID, certFP))
}

func (k tgKeys) checkEnrollProof(nonce, serverID, certFP, proof string) bool {
	got, e := hex.DecodeString(proof)
	return e == nil && macEqual(got, macParts(k.enroll, "enroll1", nonce, serverID, certFP))
}

// ---- callback data -------------------------------------------------------------------------

// cbTag authenticates a callback_data string for one chat. Telegram only delivers callbacks of
// buttons this bot sent, so this is defence in depth against stale/foreign data; the dangerous
// actions additionally need a single-use server-side confirmation.
func (k tgKeys) cbTag(chatID int64, data string) string {
	t := macParts(k.callback, "cb1", itoa64(chatID), data)
	return base64.RawURLEncoding.EncodeToString(t[:8])
}

func (k tgKeys) cbCheck(chatID int64, data, tag string) bool {
	return len(tag) == 11 && subtle.ConstantTimeCompare([]byte(tag), []byte(k.cbTag(chatID, data))) == 1
}

func itoa64(n int64) string { return big.NewInt(n).String() }

// randomID is n random bytes as lower-case hex.
func randomID(n int) string { return RandomHex(n) }
