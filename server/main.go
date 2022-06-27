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
)

var basename string
var controlName string
var port string

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
	fmt.Println(wildcardHostname)
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
		conns:    make(chan net.Conn, 30),
		hostname: hostname,
	}
	state.Lock()
	defer state.Unlock()
	state.hostnameMap[hostname] = session
	state.secretMap[secret] = session

	return session
}

func (s *ProxySession) backendConnected(conn net.Conn) {
	s.Lock()
	defer s.Unlock()
	s.backendCount++
	s.conns <- conn
	conn.Write([]byte(s.hostname))
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
		return nil
	}
	s.RUnlock()
	backend, ok := <-s.conns
	if !ok {
		return nil
	}
	_, err := backend.Write([]byte("frontend-connected"))
	if err != nil {
		backend.Close()
		s.backendDisconnected()
		return s.getBackend()
	}
	return backend
}

func main() {
	log.SetFlags(log.Lshortfile)

	var ok bool
	basename, ok = os.LookupEnv("TUNNEL_BASENAME")
	if !ok {
		panic("TUNNEL_BASENAME not defined")
	}
	controlName = "control." + basename
	port, ok = os.LookupEnv("TUNNEL_PORT")
	if !ok {
		panic("TUNNEL_PORT not defined")
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
		panic(fmt.Errorf("could not parse cert or initiate simplecert: %w", err))
	}

	laddr := ":" + port
	ln, err := tls.Listen("tcp", laddr, config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	ctx := context.Background()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		// the tls connection isn't initialized until one side reads or writes
		// we need to read immediately to get the ServerName before goroutine
		conn.Read(nil)
		go handleConnection(ctx, conn, serverName)
	}
}

func handleBackend(conn net.Conn, serverName string) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}
	s := string(buf[:n])
	ss := strings.Split(s, ":")
	ssLen := len(ss)
	if ssLen != 3 {
		conn.Close()
		return
	}
	cmd := ss[0]
	secret := ss[1]
	session, existingSessionFound := state.secretMap[secret]
	if cmd == "backend-shutdown" {
		defer conn.Close()
		if !existingSessionFound {
			fmt.Printf("invalid shutdown command: %s\n", cmd)
			return
		}
		fmt.Printf("shutdown requested for %s\n", session.hostname)
		state.Lock()
		defer state.Unlock()
		delete(state.hostnameMap, session.hostname)
		delete(state.secretMap, session.secret)
		return
	}
	if cmd != "backend-open" {
		fmt.Printf("unknown cmd: %s\n", cmd)
		conn.Close()
		return
	}
	if existingSessionFound {
		session.backendConnected(conn)
		return
	}
	hostname := ss[2]
	if hostname == "" {
		hostname = getHostname()
	}
	if !strings.HasSuffix(hostname, basename) {
		fmt.Printf("requested hostname (%s) needs basename (%s)\n", hostname, basename)
		conn.Close()
		return
	}
	if strings.HasPrefix(hostname, "control.") {
		fmt.Printf("ignoring request for control\n")
		conn.Close()
		return
	}
	// test hostname exists (secret mismatch)
	_, exists := state.hostnameMap[hostname]
	// test wildcard exists
	_, wildcardExists := getWildcardHostname(hostname)
	if exists || wildcardExists {
		fmt.Printf("hostname (%s) already exists\n", hostname)
		conn.Close()
		return
	}

	session = NewProxySession(secret, hostname)
	fmt.Printf("new session: %s\n", session.hostname)
	session.backendConnected(conn)
}

func handleFrontend(ctx context.Context, conn net.Conn, serverName string) {
	session, ok := state.hostnameMap[serverName]

	// look for wildcard match in hostnameMap
	wildcardHostname, wildcardExists := getWildcardHostname(serverName)
	if !ok && wildcardExists {
		session, ok = state.hostnameMap[wildcardHostname]
	}
	if !ok {
		conn.Close()
		return
	}
	backend := session.getBackend()
	if backend == nil {
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
		handleBackend(conn, serverName)
		return
	}
	handleFrontend(ctx, conn, serverName)
}
