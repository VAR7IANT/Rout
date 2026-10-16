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
	"math/big"
	"net"
	"time"
)

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
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
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
