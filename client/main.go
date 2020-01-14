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
	"os"
	"os/signal"

	"github.com/jamiealquiza/envy"
	"github.com/myesui/uuid"
	gNet "gitlab.com/gartnera/golib/net"
)

var defaultServer string

var token *string
var server *string
var hostname *string
var target string

func stage1(print bool) net.Conn {
	conf := &tls.Config{
		ServerName: *server,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", *server), conf)
	if err != nil {
		panic(err)
	}
	msg := fmt.Sprintf("backend-open:%s:%s", *token, *hostname)
	n, err := conn.Write([]byte(msg))
	if err != nil {
		panic(err)
	}

	buf := make([]byte, 512)

	n, err = conn.Read(buf)
	if err != nil {
		panic(err)
	}
	res := string(buf[:n])
	if print {
		fmt.Printf("URL: https://%s\n", res)
	}
	return conn
}

func both() {
	conn := stage1(false)
	stage2(conn)
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

	tConn, err := net.Dial("tcp", target)
	if err != nil {
		// TODO: test if conn is http connection
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

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", *server), conf)
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
	hostnameHelp := fmt.Sprintf("Hostname to request (test.%s)", defaultServer)
	hostname = flag.String("hostname", "", hostnameHelp)

	envy.Parse("TUNNEL")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0], "<hostname:port>")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "Example:", os.Args[0], "localhost:8888")
		os.Exit(1)
	}
	target = flag.Arg(0)

	conn := stage1(true)
	go stage2(conn)

	for i := 0; i < 10; i++ {
		go both()
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	<-signalChannel
	shutdown()

}
