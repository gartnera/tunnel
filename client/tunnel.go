package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gNet "gitlab.com/gartnera/golib/net"
)

type Tunnel struct {
	token                string
	server               string
	hostname             string
	useTLS               bool
	tlsSkipVerify        bool
	target               string
	httpTargetHostHeader bool
	connectLock          sync.Mutex
}

func NewTunnel(server, hostname, token string, useTLS, tlsSkipVerify, httpTargetHostHeader bool, target string) *Tunnel {
	return &Tunnel{
		server:               server,
		hostname:             hostname,
		token:                token,
		useTLS:               useTLS,
		tlsSkipVerify:        tlsSkipVerify,
		target:               target,
		httpTargetHostHeader: httpTargetHostHeader,
	}
}

func (t *Tunnel) Start() error {
	conn, err := t.stage1(true)
	if err != nil {
		return fmt.Errorf("unable to complete initial connection to server: %w", err)
	}
	go t.stage2(conn)

	for i := 0; i < 20; i++ {
		go t.both()
	}
	return nil
}

func (t *Tunnel) Shutdown() {
	conn, err := tls.Dial("tcp", t.server, t.getControlTlsConfig())
	if err != nil {
		panic(err)
	}
	msg := fmt.Sprintf("backend-shutdown:%s:%s", t.token, t.hostname)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		panic(err)
	}
}

func (t *Tunnel) getControlTlsConfig() *tls.Config {
	serverName, _, _ := net.SplitHostPort(t.server)
	return &tls.Config{
		ServerName: serverName,
	}
}

func (t *Tunnel) stage1(print bool) (net.Conn, error) {
	var err error
	var conn net.Conn
	backoff := time.Second * 10
	t.connectLock.Lock()
	for {
		conn, err = tls.Dial("tcp", t.server, t.getControlTlsConfig())
		if err == nil {
			break
		}
		fmt.Printf("error while connecting to server: %s\n", err)
		time.Sleep(backoff)
		backoff = backoff + (time.Second * 10)
	}
	t.connectLock.Unlock()
	msg := fmt.Sprintf("backend-open:%s:%s", t.token, t.hostname)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, fmt.Errorf("unable to write to conn: %w", err)
	}

	buf := make([]byte, 512)

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("unable to read from conn: %w", err)

	}
	res := string(buf[:n])
	if print {
		fmt.Printf("URL: https://%s\n", res)
	}
	return conn, nil
}

func (t *Tunnel) both() {
	conn, err := t.stage1(false)
	if err != nil {
		fmt.Printf("unable to connect to server: %v\n", err)
		go t.both()
		return
	}
	t.stage2(conn)
}

func (t *Tunnel) dialTLS(network, addr string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: t.tlsSkipVerify,
	}
	addrWithPort := addr
	if port == "" {
		addrWithPort += ":443"
	}
	conn, err := tls.Dial("tcp", addrWithPort, conf)
	if err != nil {
		return nil, fmt.Errorf("unable to dial tls: %w", err)
	}
	return conn, nil
}

func (t *Tunnel) stage2(conn net.Conn) {
	buf := make([]byte, 100)
	n, err := conn.Read(buf)

	go t.both()

	// conn closed by server or other
	if err != nil {
		conn.Close()
		return
	}
	res := string(buf[:n])
	if res != "frontend-connected" {
		conn.Close()
		return
	}
	defer conn.Close()

	var tConn net.Conn
	if strings.HasPrefix(t.target, "http") {
		lis := NewSingleConnListener(conn)
		targetUrl, _ := url.Parse(t.target)
		reverseProxy := NewSingleHostReverseProxy(targetUrl, t.httpTargetHostHeader)
		reverseProxy.Transport = &http.Transport{
			DialTLS:         t.dialTLS,
			IdleConnTimeout: time.Second * 10,
		}
		_ = http.Serve(lis, reverseProxy)
		return
	} else if t.useTLS {
		tConn, err = t.dialTLS("tcp", t.target)
	} else {
		tConn, err = net.Dial("tcp", t.target)
	}
	if err != nil {
		s := fmt.Sprintf("target %s returned error %s", t.target, err)
		r := http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(bytes.NewBufferString(s)),
		}
		r.Write(conn)
		return
	}

	ctx := context.Background()
	gNet.PipeConn(ctx, tConn, conn)
	tConn.Close()
}
