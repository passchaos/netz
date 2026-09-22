// Command raw_echo_client provides the quic-go client used by netz's
// handshake-fault gate.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

var payloads = [...]string{"hello", "world"}

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "peer UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor")
	serverName := flag.String("server-name", "localhost", "TLS server name")
	expectPeerClose := flag.Bool("expect-peer-close", false, "require application close 58")
	v2Only := flag.Bool("v2-only", false, "require QUIC v2")
	flag.Parse()
	if *caPath == "" || !*expectPeerClose {
		log.Fatal("-ca and -expect-peer-close are required")
	}
	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("parse CA bundle")
	}
	version := quic.Version1
	if *v2Only {
		version = quic.Version2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	connection, err := quic.DialAddr(ctx, *address, &tls.Config{
		RootCAs: roots, ServerName: *serverName,
		NextProtos: []string{"hq-interop"}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{
		Versions:             []quic.Version{version},
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       10 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer connection.CloseWithError(0, "")
	state := connection.ConnectionState()
	if state.Version != version || state.TLS.NegotiatedProtocol != "hq-interop" ||
		!state.TLS.HandshakeComplete || len(state.TLS.PeerCertificates) == 0 {
		log.Fatal("invalid authenticated QUIC handshake")
	}
	for index, payload := range payloads {
		stream, err := connection.OpenStreamSync(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if stream.StreamID() != quic.StreamID(index*4) {
			log.Fatalf("unexpected stream ID %d", stream.StreamID())
		}
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := stream.Write([]byte(payload)); err != nil {
			log.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			log.Fatal(err)
		}
		echo, err := io.ReadAll(stream)
		if err != nil || string(echo) != payload {
			log.Fatalf("invalid stream %d echo %q: %v", stream.StreamID(), echo, err)
		}
	}
	select {
	case <-connection.Context().Done():
		var applicationError *quic.ApplicationError
		cause := context.Cause(connection.Context())
		if !errors.As(cause, &applicationError) || !applicationError.Remote ||
			applicationError.ErrorCode != 58 ||
			applicationError.ErrorMessage != "netz interop complete" {
			log.Fatalf("unexpected peer close: %v", cause)
		}
	case <-ctx.Done():
		log.Fatalf("timed out waiting for peer close: %v", context.Cause(ctx))
	}
	fmt.Printf("go_quic_peer_close_client: handshake_done=true peer_close=58 reason=%q echo_streams=2 echo_bytes=10\n", "netz interop complete")
}
