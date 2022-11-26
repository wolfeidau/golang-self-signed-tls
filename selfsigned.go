package selfsigned

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Option assign configuration for automatic self signed cert generation
type Option func(opts *certOptions)

// settings for self signed cert generation
type certOptions struct {
	hosts    []string
	validFor time.Duration
	rsaBits  int
}

// Hosts added to the DNS names in the certificate.
// Defaults to "127.0.0.1", "localhost"
func Hosts(hosts []string) Option {
	return func(opts *certOptions) {
		opts.hosts = hosts
	}
}

// ValidFor duration the certificate will be issued.
// Defaults to 365 days
func ValidFor(validFor time.Duration) Option {
	return func(opts *certOptions) {
		opts.validFor = validFor
	}
}

// RSABits bit length of the RSA key used in this certificate.
// Defaults to 2048
func RSABits(rsaBits int) Option {
	return func(opts *certOptions) {
		opts.rsaBits = rsaBits
	}
}

// GenerateCertResult contains the public certificate and private key in pem format, along with a hex encoded sha fingerprint of the certificate
type GenerateCertResult struct {
	PublicCert  []byte
	PrivateKey  []byte
	Fingerprint string
}

// GenerateCertWithConfig generates the self signed certificates with defaults needed to provide TLS connections to a service.
func GenerateCert(options ...Option) (*GenerateCertResult, error) {

	opts := &certOptions{
		hosts:    []string{"127.0.0.1", "localhost"},
		validFor: 365 * 24 * time.Hour,
		rsaBits:  2048,
	}

	for _, opt := range options {
		opt(opts)
	}

	notBefore := time.Now()
	notAfter := time.Now().Add(opts.validFor)

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	priv, err := rsa.GenerateKey(rand.Reader, opts.rsaBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)

	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	for _, h := range opts.hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	pubBuf := new(bytes.Buffer)
	err = pem.Encode(pubBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, fmt.Errorf("failed to encode cert in pem format: %w", err)
	}

	fingerprint := sha1.Sum(derBytes)

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key: %w", err)
	}

	privBuf := new(bytes.Buffer)
	err = pem.Encode(privBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return nil, fmt.Errorf("failed to encode cert in pem format: %w", err)
	}

	return &GenerateCertResult{PublicCert: pubBuf.Bytes(), PrivateKey: privBuf.Bytes(), Fingerprint: hex.EncodeToString(fingerprint[:])}, nil
}
