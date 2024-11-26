package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/foomo/simplecert"
	"gitlab.com/gartnera/tunnel/server"
	"go.uber.org/zap"
)

func main() {

	var ok bool
	var err error
	basename, ok := os.LookupEnv("TUNNEL_BASENAME")
	if !ok {
		panic("TUNNEL_BASENAME not defined")
	}
	port, ok := os.LookupEnv("TUNNEL_PORT")
	if !ok {
		panic("TUNNEL_PORT not defined")
	}

	_, ok = os.LookupEnv("DEBUG")
	var logger *zap.Logger
	if ok {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		panic(err)
	}

	sCfg := simplecert.Default
	sCfg.Domains = []string{fmt.Sprintf("*.%s", basename)}
	sCfg.CacheDir = os.Getenv("SIMPLECERT_CACHE_DIR")
	sCfg.SSLEmail = os.Getenv("SIMPLECERT_SSL_EMAIL")
	sCfg.DNSProvider = os.Getenv("SIMPLECERT_DNS_PROVIDER")
	// simply restart server when certificate is renewed. rely on systemd to restart
	sCfg.DidRenewCertificate = func() {
		os.Exit(2)
	}
	if os.Getenv("SIMPLECERT_USE_PUBLIC_DNS") != "" {
		sCfg.DNSServers = []string{"1.1.1.1"}
	}

	config := &tls.Config{}
	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err == nil {
		config.Certificates = []tls.Certificate{cer}
	} else if sCfg.DNSProvider != "" {
		certReloader, err := simplecert.Init(sCfg, nil)
		if err != nil {
			panic(err)
		}
		config.GetCertificate = certReloader.GetCertificateFunc()
	} else {
		logger.Fatal("could not parse cert or initiate simplecert", zap.Error(err))
	}

	server := server.New(basename, logger)
	laddr := ":" + port
	err = server.Start(laddr, config)
	if err != nil {
		logger.Fatal("server start", zap.Error(err))
	}
}
