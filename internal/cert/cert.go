// Package cert generates a self-signed TLS certificate at runtime so the
// POC can serve HTTPS without shipping any key material in the repo.
// Self-signed is fine for a demo (we control both ends) and unacceptable
// for anything public — browsers/users must not be trained to click
// through certificate warnings.
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// SelfSigned creates an in-memory TLS certificate for localhost/127.0.0.1.
// Nothing is written to disk: the key lives only for the process lifetime.
func SelfSigned() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "siamo-poc-security demo",
			Organization: []string{"Siamo Systems (demo)"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pemEncode("CERTIFICATE", der),
		pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
	)
}
