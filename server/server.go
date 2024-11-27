package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/icrowley/fake"
	gNet "gitlab.com/gartnera/golib/net"
	"go.uber.org/zap"
)

type Server struct {
	basename    string
	controlName string
	logger      *zap.Logger

	addr net.Addr

	sync.RWMutex
	hostnameMap map[string]*proxySession
	secretMap   map[string]*proxySession
}

func New(basename string, logger *zap.Logger) *Server {
	return &Server{
		basename:    basename,
		controlName: fmt.Sprintf("control.%s", basename),
		logger:      logger,
		hostnameMap: make(map[string]*proxySession),
		secretMap:   make(map[string]*proxySession),
	}
}

func (s *Server) Start(laddr string, tlsConfig *tls.Config) error {
	var serverName string
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		serverName = info.ServerName
		return nil, nil
	}
	ln, err := tls.Listen("tcp", laddr, tlsConfig)
	if err != nil {
		s.logger.Fatal("could not listen", zap.String("laddr", laddr), zap.Error(err))
	}
	defer ln.Close()
	s.Lock()
	s.addr = ln.Addr()
	s.Unlock()

	ctx := context.Background()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Error("unable to accept", zap.Error(err))
			continue
		}
		s.logger.Debug("new connection",
			zap.String("localAddr", conn.LocalAddr().String()),
			zap.String("remoteAddr", conn.RemoteAddr().String()),
		)
		// the tls connection isn't initialized until one side reads or writes
		// we need to read immediately to get the ServerName before goroutine
		conn.Read(nil)
		go s.handleConnection(ctx, conn, serverName)
	}
}

func (s *Server) Addr() net.Addr {
	return s.addr
}

// getHostname generates a three word unique subdomain
// recursively call self until we get a unique name
func (s *Server) getHostname() string {
	res := fmt.Sprintf("%s-%s-%s.%s", fake.Word(), fake.Word(), fake.Word(), s.basename)
	_, exists := s.hostnameMap[res]
	_, wildcardExists := s.getWildcardHostname(res)
	if exists || wildcardExists {
		return s.getHostname()
	}
	return res
}

func (s *Server) getWildcardHostname(serverName string) (string, bool) {
	namePrefix := strings.Split(serverName, "-")[0]
	wildcardHostname := fmt.Sprintf("%s-*.%s", namePrefix, s.basename)
	_, exists := s.hostnameMap[wildcardHostname]
	return wildcardHostname, exists
}

type proxySession struct {
	sync.RWMutex
	server       *Server
	secret       string
	conns        chan net.Conn
	backendCount int
	hostname     string
}

func (s *Server) newProxySession(secret string, hostname string) *proxySession {
	session := &proxySession{
		server:   s,
		secret:   secret,
		conns:    make(chan net.Conn, 500),
		hostname: hostname,
	}
	s.Lock()
	defer s.Unlock()
	s.hostnameMap[hostname] = session
	s.secretMap[secret] = session

	return session
}

func (s *proxySession) backendConnected(conn net.Conn) {
	s.server.logger.Debug("backend connected",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("hostname", s.hostname),
	)
	s.Lock()
	s.server.logger.Debug("backend connected (inside lock)",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("hostname", s.hostname),
	)
	s.backendCount++
	s.Unlock()
	conn.Write([]byte(s.hostname))
	s.conns <- conn
	s.server.logger.Debug("backend connected (after chan)",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("hostname", s.hostname),
	)
}

func (s *proxySession) backendDisconnected() {
	s.Lock()
	defer s.Unlock()
	s.backendCount--
	if s.backendCount == 0 {
		s.server.Lock()
		defer s.server.Unlock()
		delete(s.server.hostnameMap, s.hostname)
		delete(s.server.secretMap, s.secret)
		close(s.conns)
		fmt.Printf("all backends disconnected for %s\n", s.hostname)
	}
}

func (s *proxySession) getBackend() net.Conn {
	s.RLock()
	if s.backendCount == 0 {
		s.server.logger.Error("no backends available")
		return nil
	}
	s.RUnlock()
	backend, ok := <-s.conns
	if !ok {
		s.server.logger.Debug("conns closed", zap.String("hostname", s.hostname))
		return nil
	}
	s.server.logger.Debug("got backend",
		zap.String("backendAddr", backend.RemoteAddr().String()),
	)
	_, err := backend.Write([]byte("frontend-connected"))
	if err != nil {
		s.server.logger.Error("backend rejected frontend-connected", zap.Error(err))
		backend.Close()
		s.backendDisconnected()
		return s.getBackend()
	}
	return backend
}

func (s *Server) handleBackend(conn net.Conn) {
	logger := s.logger.With(
		zap.String("remoteAddr", conn.RemoteAddr().String()),
	)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		logger.Error("unable to read command from conn", zap.Error(err))
		conn.Close()
		return
	}
	rawCmd := string(buf[:n])
	cmdParts := strings.Split(rawCmd, ":")
	cmdLen := len(cmdParts)
	if cmdLen != 3 {
		logger.Error("invalid command from conn")
		conn.Close()
		return
	}
	cmd := cmdParts[0]
	secret := cmdParts[1]
	s.Lock()
	session, existingSessionFound := s.secretMap[secret]
	s.Unlock()
	if cmd == "backend-shutdown" {
		defer conn.Close()
		if !existingSessionFound {
			logger.Error("invalid shutdown command", zap.String("cmd", cmd))
			return
		}
		logger.Debug("shutdown requested", zap.String("hostname", session.hostname))
		s.Lock()
		defer s.Unlock()
		delete(s.hostnameMap, session.hostname)
		delete(s.secretMap, session.secret)
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
	hostname := cmdParts[2]
	if hostname == "" {
		hostname = s.getHostname()
	}
	if !strings.HasSuffix(hostname, s.basename) {
		logger.Error("requested hostname needs basename",
			zap.String("hostname", hostname),
			zap.String("basename", s.basename),
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
	s.Lock()
	_, exists := s.hostnameMap[hostname]
	s.Unlock()
	// test wildcard exists
	_, wildcardExists := s.getWildcardHostname(hostname)
	if exists || wildcardExists {
		logger.Error("hostname already exists", zap.String("hostname", hostname))
		conn.Close()
		return
	}

	session = s.newProxySession(secret, hostname)
	logger.Info("new session", zap.String("hostname", hostname))
	session.backendConnected(conn)
}

func (s *Server) handleFrontend(ctx context.Context, conn net.Conn, serverName string) {
	s.Lock()
	session, ok := s.hostnameMap[serverName]
	s.Unlock()

	// look for wildcard match in hostnameMap
	wildcardHostname, wildcardExists := s.getWildcardHostname(serverName)
	if !ok && wildcardExists {
		s.Lock()
		session, ok = s.hostnameMap[wildcardHostname]
		s.Unlock()
	}
	if !ok {
		conn.Close()
		return
	}
	backend := session.getBackend()
	if backend == nil {
		s.logger.Error("nil backend")
		conn.Close()
		return
	}

	gNet.PipeConn(ctx, backend, conn)
	backend.Close()
	conn.Close()
	session.backendDisconnected()
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn, serverName string) {
	if serverName == s.controlName {
		s.logger.Debug("new control connection", zap.String("remoteAddr", conn.RemoteAddr().String()))
		s.handleBackend(conn)
		return
	}
	s.handleFrontend(ctx, conn, serverName)
}
