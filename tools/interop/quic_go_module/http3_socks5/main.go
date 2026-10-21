// Command http3_socks5 is the independent HTTP/3 origin used by Netz's
// SOCKS5 UDP ASSOCIATE pool gate.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "UDP listen address")
	certPath := flag.String("cert", "", "server certificate")
	keyPath := flag.String("key", "", "server private key")
	expectedAuthority := flag.String("authority", "", "expected HTTP authority")
	flag.Parse()
	if *certPath == "" || *keyPath == "" || *expectedAuthority == "" {
		log.Fatal("-cert, -key, and -authority are required")
	}
	certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}
	packetConn, err := net.ListenPacket("udp4", *address)
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	defer packetConn.Close()

	var connections atomic.Uint32
	results := make(chan error, 2)
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 8 * time.Second,
			MaxIdleTimeout:       8 * time.Second,
		},
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			connections.Add(1)
			fmt.Println("quic-go SOCKS5 HTTP/3 connection established")
			return ctx
		},
	}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("quic-go SOCKS5 HTTP/3 request path=%s host=%s\n", r.URL.RequestURI(), r.Host)
		if r.Method != http.MethodGet || r.Host != *expectedAuthority {
			results <- fmt.Errorf("unexpected request: method=%s host=%q", r.Method, r.Host)
			return
		}
		var requestErr error
		switch r.URL.RequestURI() {
		case "/h3-one":
			_, requestErr = w.Write([]byte("h3-socks-one"))
		case "/h3-two":
			_, requestErr = w.Write([]byte("h3-socks-two"))
		default:
			requestErr = fmt.Errorf("unexpected target %q", r.URL.RequestURI())
		}
		results <- requestErr
	})

	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(packetConn) }()
	fmt.Printf("quic-go SOCKS5 HTTP/3 server listening=%s\n", packetConn.LocalAddr())
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				log.Fatal(err)
			}
		case err := <-serveErrors:
			log.Fatalf("serve HTTP/3: %v", err)
		case <-time.After(12 * time.Second):
			log.Fatal("timed out waiting for HTTP/3 requests")
		}
	}
	time.Sleep(150 * time.Millisecond)
	if connections.Load() != 1 {
		log.Fatalf("expected one QUIC connection, got %d", connections.Load())
	}
	if err := server.Close(); err != nil {
		log.Fatalf("close HTTP/3 server: %v", err)
	}
	fmt.Println("quic-go SOCKS5 HTTP/3 server passed: requests=2 connections=1")
}
