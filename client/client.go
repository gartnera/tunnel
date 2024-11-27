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

type ClientOpt func(c *Client)

// WithControlTLSConfig sets the `tls.Config` used when connecting
// to the control server
func WithControlTLSConfig(tlsConfig *tls.Config) ClientOpt {
	return func(c *Client) {
		c.controlTTLSconfig = tlsConfig
	}
}

// WithHostname requests a specific hostname. A token must be specified if using a hostname.
func WithHostname(hostname string, token string) ClientOpt {
	return func(c *Client) {
		c.hostname = hostname
		c.token = token
	}
}

// WithUseTLS enables use of TLS when connecting to the target
func WithUseTLS(useTLS bool) ClientOpt {
	return func(c *Client) {
		c.useTLS = useTLS
	}
}

// WithTLSSkipVerify skips verification of TLS certificates when connecting to the target
func WithTLSSkipVerify(skipVerify bool) ClientOpt {
	return func(c *Client) {
		c.tlsSkipVerify = skipVerify
	}
}

// WithHTTPTargetHostHeader rewrites the HTTP Host header to the target name.
// This is useful if the target breaks if it's hostname is unexpected.
func WithHTTPTargetHostHeader(useHostHeader bool) ClientOpt {
	return func(c *Client) {
		c.httpTargetHostHeader = useHostHeader
	}
}

type Client struct {
	token                string
	server               string
	hostname             string
	useTLS               bool
	tlsSkipVerify        bool
	target               string
	httpTargetHostHeader bool

	controlTTLSconfig *tls.Config
	issuedAddr        string
	connectLock       sync.Mutex
}

func New(server, target string, opts ...ClientOpt) *Client {
	c := &Client{
		server:            server,
		target:            target,
		controlTTLSconfig: &tls.Config{},
	}

	for _, opt := range opts {
		opt(c)
	}
	serverName, _, _ := net.SplitHostPort(c.server)
	c.controlTTLSconfig.ServerName = serverName

	return c
}

func (c *Client) Start() error {
	conn, err := c.stage1(true)
	if err != nil {
		return fmt.Errorf("unable to complete initial connection to server: %w", err)
	}
	go c.stage2(conn)

	for i := 0; i < 20; i++ {
		go c.both()
	}
	return nil
}

func (c *Client) Shutdown() {
	conn, err := tls.Dial("tcp", c.server, c.controlTTLSconfig)
	if err != nil {
		panic(err)
	}
	msg := fmt.Sprintf("backend-shutdown:%s:%s", c.token, c.hostname)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		panic(err)
	}
}

// IssuedAddr gets the address issued by the server
func (c *Client) IssuedAddr() string {
	return c.issuedAddr
}

// IssuedAddrHTTPS gets the address issued by the server with https prefix
func (c *Client) IssuedAddrHTTPS() string {
	addr := c.issuedAddr
	if strings.HasSuffix(addr, ":443") {
		addr = strings.TrimSuffix(addr, ":443")
	}
	return fmt.Sprintf("https://%s", addr)
}

func (c *Client) stage1(first bool) (net.Conn, error) {
	var err error
	var conn net.Conn
	backoff := time.Second * 10
	c.connectLock.Lock()
	for {
		conn, err = tls.Dial("tcp", c.server, c.controlTTLSconfig)
		if err == nil {
			break
		}
		fmt.Printf("error while connecting to server: %s\n", err)
		time.Sleep(backoff)
		backoff = backoff + (time.Second * 10)
	}
	c.connectLock.Unlock()
	msg := fmt.Sprintf("backend-open:%s:%s", c.token, c.hostname)
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
	if first {
		_, port, _ := net.SplitHostPort(c.server)
		if port == "" {
			port = "443"
		}
		c.issuedAddr = fmt.Sprintf("%s:%s", res, port)
	}
	return conn, nil
}

func (c *Client) both() {
	conn, err := c.stage1(false)
	if err != nil {
		fmt.Printf("unable to connect to server: %v\n", err)
		go c.both()
		return
	}
	c.stage2(conn)
}

func (c *Client) dialTLS(network, addr string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: c.tlsSkipVerify,
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

func (c *Client) stage2(conn net.Conn) {
	buf := make([]byte, 100)
	n, err := conn.Read(buf)

	go c.both()

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
	if strings.HasPrefix(c.target, "http") {
		lis := NewSingleConnListener(conn)
		targetUrl, _ := url.Parse(c.target)
		reverseProxy := NewSingleHostReverseProxy(targetUrl, c.httpTargetHostHeader)
		reverseProxy.Transport = &http.Transport{
			DialTLS:         c.dialTLS,
			IdleConnTimeout: time.Second * 10,
		}
		_ = http.Serve(lis, reverseProxy)
		return
	} else if c.useTLS {
		tConn, err = c.dialTLS("tcp", c.target)
	} else {
		tConn, err = net.Dial("tcp", c.target)
	}
	if err != nil {
		s := fmt.Sprintf("target %s returned error %s", c.target, err)
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
