package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gitlab.com/gartnera/tunnel/client"
	"gitlab.com/gartnera/tunnel/server"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// generateCertificate generates a CA certificate, client certificate, and returns a tls.Config.
func generateCertificate(cn string) (*tls.Config, error) {
	// Generate CA private key
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"My CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, err
	}

	// Generate server private key
	serverPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create server certificate template
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}

	// Sign server certificate with CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	// Create a tls.Config with the server certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCertDER},
				PrivateKey:  serverPrivateKey,
			},
		},
		RootCAs: x509.NewCertPool(),
	}

	tlsConfig.RootCAs.AddCert(caCert)

	return tlsConfig, nil
}

func TestE2E(t *testing.T) {
	r := require.New(t)
	logger := zaptest.NewLogger(t)

	server := server.New("localtest.me", logger)

	tlsConfig, err := generateCertificate("*.localtest.me")
	r.NoError(err)

	go func() {
		err = server.Start(":0", tlsConfig)
		logger.Error("server start returned error", zap.Error(err))
	}()
	time.Sleep(time.Millisecond * 50)

	_, port, _ := net.SplitHostPort(server.Addr().String())
	controlAddr := fmt.Sprintf("control.localtest.me:%s", port)
	client := client.New(
		controlAddr,
		"",
		"",
		false,
		false,
		false,
		"localhost:1234",
		client.WithControlTLSConfig(tlsConfig),
	)
	err = client.Start()
	r.NoError(err, "client start")

	r.Contains(client.IssuedAddr(), "localtest.me")
}
