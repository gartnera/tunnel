package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/foomo/simplecert"
	"github.com/icrowley/fake"
	gNet "gitlab.com/gartnera/golib/net"
	"go.uber.org/zap"
)

var basename string
var controlName string
var port string
var logger *zap.Logger

var state = struct {
	sync.RWMutex
	hostnameMap map[string]*ProxySession
	secretMap   map[string]*ProxySession
}{
	hostnameMap: make(map[string]*ProxySession),
	secretMap:   make(map[string]*ProxySession),
}

// getHostname generates a three word unique subdomain
// recursively call self until we get a unique name
func getHostname() string {
	res := fmt.Sprintf("%s-%s-%s.%s", fake.Word(), fake.Word(), fake.Word(), basename)
	_, exists := state.hostnameMap[res]
	_, wildcardExists := getWildcardHostname(res)
	if exists || wildcardExists {
		return getHostname()
	}
	return res
}

func getWildcardHostname(serverName string) (string, bool) {
	namePrefix := strings.Split(serverName, "-")[0]
	wildcardHostname := fmt.Sprintf("%s-*.%s", namePrefix, basename)
	_, exists := state.hostnameMap[wildcardHostname]
	return wildcardHostname, exists
}

type ProxySession struct {
	sync.RWMutex
	secret       string
	conns        chan net.Conn
	backendCount int
	hostname     string
}

func NewProxySession(secret string, hostname string) *ProxySession {
	session := &ProxySession{
		secret:   secret,
		conns:    make(chan net.Conn, 500),
		hostname: hostname,
	}
	state.Lock()
	defer state.Unlock()
	state.hostnameMap[hostname] = session
	state.secretMap[secret] = session

	return session
}

func (s *ProxySession) backendConnected(conn net.Conn) {
	logger.Debug("backend connected",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("hostname", s.hostname),
	)
	s.Lock()
	logger.Debug("backend connected (inside lock)",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("hostname", s.hostname),
	)
	s.backendCount++
	s.Unlock()
	conn.Write([]byte(s.hostname))
	s.conns <- conn
	logger.Debug("backend connected (after chan)",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("hostname", s.hostname),
	)
}

func (s *ProxySession) backendDisconnected() {
	s.Lock()
	defer s.Unlock()
	s.backendCount--
	if s.backendCount == 0 {
		state.Lock()
		defer state.Unlock()
		delete(state.hostnameMap, s.hostname)
		delete(state.secretMap, s.secret)
		close(s.conns)
		fmt.Printf("all backends disconnected for %s\n", s.hostname)
	}
}

func (s *ProxySession) getBackend() net.Conn {
	s.RLock()
	if s.backendCount == 0 {
		logger.Error("no backends available")
		return nil
	}
	s.RUnlock()
	backend, ok := <-s.conns
	if !ok {
		logger.Debug("conns closed", zap.String("hostname", s.hostname))
		return nil
	}
	logger.Debug("got backend",
		zap.String("backendAddr", backend.RemoteAddr().String()),
	)
	_, err := backend.Write([]byte("frontend-connected"))
	if err != nil {
		logger.Error("backend rejected frontend-connected", zap.Error(err))
		backend.Close()
		s.backendDisconnected()
		return s.getBackend()
	}
	return backend
}

func main() {
	log.SetFlags(log.Lshortfile)

	var ok bool
	var err error
	basename, ok = os.LookupEnv("TUNNEL_BASENAME")
	if !ok {
		panic("TUNNEL_BASENAME not defined")
	}
	controlName = "control." + basename
	port, ok = os.LookupEnv("TUNNEL_PORT")
	if !ok {
		panic("TUNNEL_PORT not defined")
	}

	_, ok = os.LookupEnv("DEBUG")
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

	var serverName string
	config := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = info.ServerName
			return nil, nil
		},
	}
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

	laddr := ":" + port
	ln, err := tls.Listen("tcp", laddr, config)
	if err != nil {
		logger.Fatal("could not listen", zap.String("laddr", laddr), zap.Error(err))
	}
	defer ln.Close()

	ctx := context.Background()
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("unable to accept", zap.Error(err))
			continue
		}
		logger.Debug("new connection",
			zap.String("localAddr", conn.LocalAddr().String()),
			zap.String("remoteAddr", conn.RemoteAddr().String()),
		)
		// the tls connection isn't initialized until one side reads or writes
		// we need to read immediately to get the ServerName before goroutine
		conn.Read(nil)
		go handleConnection(ctx, conn, serverName)
	}
}

func handleBackend(conn net.Conn, serverName string) {
	logger := logger.With(
		zap.String("remoteAddr", conn.RemoteAddr().String()),
	)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		logger.Error("unable to read command from conn", zap.Error(err))
		conn.Close()
		return
	}
	s := string(buf[:n])
	ss := strings.Split(s, ":")
	ssLen := len(ss)
	if ssLen != 3 {
		logger.Error("invalid command from conn")
		conn.Close()
		return
	}
	cmd := ss[0]
	secret := ss[1]
	state.Lock()
	session, existingSessionFound := state.secretMap[secret]
	state.Unlock()
	if cmd == "backend-shutdown" {
		defer conn.Close()
		if !existingSessionFound {
			logger.Error("invalid shutdown command", zap.String("cmd", cmd))
			return
		}
		logger.Debug("shutdown requested", zap.String("hostname", session.hostname))
		state.Lock()
		defer state.Unlock()
		delete(state.hostnameMap, session.hostname)
		delete(state.secretMap, session.secret)
		return
	}
	if cmd != "backend-open" {
		logger.Error("unknown command", zap.String("cmd", cmd))
		conn.Close()
		return
	}
	if existingSessionFound {
		logger.Debug("existing session found", zap.String("hostname", session.hostname))
		session.backendConnected(conn)
		return
	}
	hostname := ss[2]
	if hostname == "" {
		hostname = getHostname()
	}
	if !strings.HasSuffix(hostname, basename) {
		logger.Error("requested hostname needs basename",
			zap.String("hostname", hostname),
			zap.String("basename", basename),
		)
		conn.Close()
		return
	}
	if strings.HasPrefix(hostname, "control.") {
		logger.Error("ignoring request for control")
		conn.Close()
		return
	}
	// test hostname exists (secret mismatch)
	state.Lock()
	_, exists := state.hostnameMap[hostname]
	state.Unlock()
	// test wildcard exists
	_, wildcardExists := getWildcardHostname(hostname)
	if exists || wildcardExists {
		logger.Error("hostname already exists", zap.String("hostname", hostname))
		conn.Close()
		return
	}

	session = NewProxySession(secret, hostname)
	logger.Info("new session", zap.String("hostname", hostname))
	session.backendConnected(conn)
}

func handleFrontend(ctx context.Context, conn net.Conn, serverName string) {
	state.Lock()
	session, ok := state.hostnameMap[serverName]
	state.Unlock()

	// look for wildcard match in hostnameMap
	wildcardHostname, wildcardExists := getWildcardHostname(serverName)
	if !ok && wildcardExists {
		state.Lock()
		session, ok = state.hostnameMap[wildcardHostname]
		state.Unlock()
	}
	if !ok {
		conn.Close()
		return
	}
	backend := session.getBackend()
	if backend == nil {
		logger.Error("nil backend")
		conn.Close()
		return
	}

	gNet.PipeConn(ctx, backend, conn)
	backend.Close()
	conn.Close()
	session.backendDisconnected()
}

func handleConnection(ctx context.Context, conn net.Conn, serverName string) {
	if serverName == controlName {
		logger.Debug("new control connection", zap.String("remoteAddr", conn.RemoteAddr().String()))
		handleBackend(conn, serverName)
		return
	}
	handleFrontend(ctx, conn, serverName)
}
