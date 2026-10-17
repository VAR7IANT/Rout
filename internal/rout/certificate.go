package rout

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"time"
)

// Trust in a self-signed node certificate comes from the pinned/embedded certificate,
// not from its validity period, and replacing it always requires re-importing clients.
// A short expiry therefore only breaks embedded-trust clients (sing-box JSON) silently.
const selfSignedYears = 10

// Certificates expiring within this window are reported by list/status/doctor.
const certificateWarnDays = 30

func GenerateCertificate(host string) (string, string, error) {
	if !validHost(host) {
		return "", "", errors.New("TLS SNI 无效")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", "", e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return "", "", e
	}
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(selfSignedYears, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(host); ip != nil {
		c.IPAddresses = []net.IP{ip}
	} else {
		c.DNSNames = []string{host}
	}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		return "", "", e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})), nil
}
func CertificatePin(cert string) (string, error) {
	b, _ := pem.Decode([]byte(cert))
	if b == nil {
		return "", errors.New("证书无效")
	}
	if _, e := x509.ParseCertificate(b.Bytes); e != nil {
		return "", errors.New("证书无效")
	}
	h := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(h[:]), nil
}

// CertificateExpiry reports when a node's TLS certificate stops being valid.
func (p Profile) CertificateExpiry() (time.Time, bool) {
	if p.Kind != "node" || (p.Protocol != "hy2" && p.Protocol != "tuic") {
		return time.Time{}, false
	}
	b, _ := pem.Decode([]byte(p.CertPEM))
	if b == nil {
		return time.Time{}, false
	}
	c, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return time.Time{}, false
	}
	return c.NotAfter, true
}

// CertificateDays is the number of whole days left (negative once expired).
func (p Profile) CertificateDays(now time.Time) (int, bool) {
	end, ok := p.CertificateExpiry()
	if !ok {
		return 0, false
	}
	return int(math.Floor(end.Sub(now).Hours() / 24)), true
}

// RegenerateCertificate issues a new self-signed certificate for the node's SNI. The
// pin changes, so every client must re-import the link or exported configuration.
func RegenerateCertificate(p Profile) (Profile, error) {
	if p.Kind != "node" || (p.Protocol != "hy2" && p.Protocol != "tuic") {
		return p, errors.New("该节点未使用文件证书")
	}
	cert, key, e := GenerateCertificate(p.SNI)
	if e != nil {
		return p, e
	}
	p.CertPEM, p.KeyPEM, p.TLSGenerated = cert, key, true
	return p, nil
}
