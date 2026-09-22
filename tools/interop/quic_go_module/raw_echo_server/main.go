// Command raw_echo_server provides the quic-go server used by netz's
// handshake-fault gate. It intentionally covers only the two-stream echo and
// peer-close contract needed by that matrix.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
	"netz-quic-go-interop/internal/testcert"
)

var payloads = [...]string{"hello", "world"}

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "listen UDP address")
	caOut := flag.String("ca-out", "", "PEM trust anchor output")
	v1Only := flag.Bool("v1-only", false, "require QUIC v1")
	v2Only := flag.Bool("v2-only", false, "require QUIC v2")
	flag.Parse()
	if *caOut == "" || *v1Only == *v2Only {
		log.Fatal("exactly one of -v1-only and -v2-only is required")
	}
	version := quic.Version1
	versionNumber := 1
	if *v2Only {
		version = quic.Version2
		versionNumber = 2
	}
	certificate, certificatePEM, err := testcert.SelfSignedLocalhost()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caOut, certificatePEM, 0o600); err != nil {
		log.Fatal(err)
	}
	listener, err := quic.ListenAddr(*address, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"hq-interop"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		Versions:             []quic.Version{version},
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       10 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("go_quic_echo_server: listening=%s version=%d force_retry=false\n", listener.Addr(), versionNumber)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	connection, err := listener.Accept(ctx)
	if err != nil {
		log.Fatal(err)
	}
	state := connection.ConnectionState()
	if state.Version != version || state.TLS.NegotiatedProtocol != "hq-interop" ||
		!state.TLS.HandshakeComplete {
		log.Fatal("invalid authenticated QUIC handshake")
	}
	for index, expected := range payloads {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if stream.StreamID() != quic.StreamID(index*4) {
			log.Fatalf("unexpected stream ID %d", stream.StreamID())
		}
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		payload, err := io.ReadAll(stream)
		if err != nil || string(payload) != expected {
			log.Fatalf("invalid stream %d payload %q: %v", stream.StreamID(), payload, err)
		}
		if _, err := stream.Write(payload); err != nil {
			log.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			log.Fatal(err)
		}
	}
	time.Sleep(250 * time.Millisecond)
	if err := connection.CloseWithError(57, "quic-go interop complete"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("go_quic_echo_server: handshake_done=true version=%d retry=false key_updates=0 echo_streams=2 echo_bytes=10\n", versionNumber)
}
