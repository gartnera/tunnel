package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/jamiealquiza/envy"
	"github.com/myesui/uuid"
	gNet "gitlab.com/gartnera/golib/net"
)

var defaultServer string

var token *string
var server *string
var serverPort *string
var hostname *string
var useTLS bool
var tlsSkipVerify bool
var target string
var httpTargetHostHeader bool

var connectLock sync.Mutex

func stage1(print bool) (net.Conn, error) {
	conf := &tls.Config{
		ServerName: *server,
	}
	var err error
	var conn net.Conn
	backoff := time.Second * 10
	connectLock.Lock()
	for {
		conn, err = tls.Dial("tcp", fmt.Sprintf("%s:%s", *server, *serverPort), conf)
		if err == nil {
			break
		}
		fmt.Printf("error while connecting to server: %s\n", err)
		time.Sleep(backoff)
		backoff = backoff + (time.Second * 10)
	}
	connectLock.Unlock()
	msg := fmt.Sprintf("backend-open:%s:%s", *token, *hostname)
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

func both() {
	conn, err := stage1(false)
	if err != nil {
		fmt.Printf("unable to connect to server: %v\n", err)
		go both()
		return
	}
	stage2(conn)
}

func dialTLS(network, addr string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: tlsSkipVerify,
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

func stage2(conn net.Conn) {
	buf := make([]byte, 100)
	n, err := conn.Read(buf)

	go both()

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
	if strings.HasPrefix(target, "http") {
		lis := NewSingleConnListener(conn)
		targetUrl, _ := url.Parse(target)
		reverseProxy := NewSingleHostReverseProxy(targetUrl)
		reverseProxy.Transport = &http.Transport{
			DialTLS:         dialTLS,
			IdleConnTimeout: time.Second * 10,
		}
		_ = http.Serve(lis, reverseProxy)
		return
	} else if useTLS {
		tConn, err = dialTLS("tcp", target)
	} else {
		tConn, err = net.Dial("tcp", target)
	}
	if err != nil {
		s := fmt.Sprintf("target %s returned error %s", target, err)
		r := http.Response{
			StatusCode: 500,
			Body:       ioutil.NopCloser(bytes.NewBufferString(s)),
		}
		r.Write(conn)
		return
	}

	ctx := context.Background()
	gNet.PipeConn(ctx, tConn, conn)
	tConn.Close()
}

func shutdown() {
	conf := &tls.Config{
		ServerName: *server,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", *server, *serverPort), conf)
	if err != nil {
		panic(err)
	}
	msg := fmt.Sprintf("backend-shutdown:%s:%s", *token, *hostname)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		panic(err)
	}
}

func main() {
	log.SetFlags(log.Lshortfile)

	token = flag.String("token", uuid.NewV4().String(), "Secret token")
	server = flag.String("server", defaultServer, "Tunnel server")
	serverPort = flag.String("server-port", "443", "Port to connect to the tunnel server")
	hostnameHelp := fmt.Sprintf("Hostname to request (test.%s)", defaultServer)
	hostname = flag.String("hostname", "", hostnameHelp)
	flag.BoolVar(&useTLS, "use-tls", false, "use TLS when connecting to the local server")
	flag.BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "skip tls verification of the local server")
	flag.BoolVar(&httpTargetHostHeader, "http-target-host-header", false, "rewrite the host header to match the target host")

	envy.Parse("TUNNEL")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0], "<hostname:port>")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "Example:", os.Args[0], "localhost:8888")
		os.Exit(1)
	}
	target = flag.Arg(0)

	// we now use the control subdomain rather than the basename of the server
	controlName := "control." + *server
	server = &controlName

	conn, err := stage1(true)
	if err != nil {
		panic(fmt.Errorf("unable to connect to server: %w", err))
	}
	go stage2(conn)

	for i := 0; i < 20; i++ {
		go both()
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	<-signalChannel
	shutdown()

}
