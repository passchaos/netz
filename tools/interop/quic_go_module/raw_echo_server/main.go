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
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"netz-quic-go-interop/internal/testcert"
)

var echoPayloads = [...]string{"hello", "world"}
var keyUpdatePayloads = [...]string{"before-update", "phase-one", "phase-two"}

type keyUpdateTrace struct {
	mu            sync.Mutex
	remoteUpdates int
}

func (t *keyUpdateTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *keyUpdateTrace) SupportsSchemas(string) bool      { return true }
func (t *keyUpdateTrace) Close() error                     { return nil }

func (t *keyUpdateTrace) RecordEvent(event qlogwriter.Event) {
	update, ok := event.(qlog.KeyUpdated)
	if !ok || update.Trigger != qlog.KeyUpdateRemote ||
		update.KeyType != qlog.KeyTypeClient1RTT {
		return
	}
	t.mu.Lock()
	t.remoteUpdates++
	t.mu.Unlock()
}

func (t *keyUpdateTrace) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remoteUpdates
}

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "listen UDP address")
	caOut := flag.String("ca-out", "", "PEM trust anchor output")
	v1Only := flag.Bool("v1-only", false, "require QUIC v1")
	v2Only := flag.Bool("v2-only", false, "require QUIC v2")
	forceRetry := flag.Bool("force-retry", false, "require address validation with Retry")
	keyUpdates := flag.Int("key-updates", 0, "expected peer-initiated key updates")
	flag.Parse()
	if *caOut == "" || (*v1Only && *v2Only) || (*keyUpdates != 0 && *keyUpdates != 2) {
		log.Fatal("-ca-out, at most one version flag, and zero or two key updates are required")
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
	udpAddress, err := net.ResolveUDPAddr("udp4", *address)
	if err != nil {
		log.Fatal(err)
	}
	udpConnection, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		log.Fatal(err)
	}
	defer udpConnection.Close()
	var retryRequested atomic.Bool
	trace := &keyUpdateTrace{}
	transport := &quic.Transport{
		Conn: udpConnection,
		VerifySourceAddress: func(net.Addr) bool {
			retryRequested.Store(true)
			return *forceRetry
		},
	}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"hq-interop"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		Versions:             []quic.Version{version},
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       10 * time.Second,
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return trace
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("go_quic_echo_server: listening=%s version=%d force_retry=%t\n", listener.Addr(), versionNumber, *forceRetry)
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
	if *forceRetry && !retryRequested.Load() {
		log.Fatal("forced Retry was not requested")
	}
	payloads := echoPayloads[:]
	if *keyUpdates != 0 {
		payloads = keyUpdatePayloads[:]
	}
	echoBytes := 0
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
		echoBytes += len(payload)
	}
	time.Sleep(250 * time.Millisecond)
	if trace.count() != *keyUpdates {
		log.Fatalf("observed %d peer key updates, want %d", trace.count(), *keyUpdates)
	}
	if err := connection.CloseWithError(57, "quic-go interop complete"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("go_quic_echo_server: handshake_done=true version=%d retry=%t key_updates=%d echo_streams=%d echo_bytes=%d\n", versionNumber, *forceRetry, *keyUpdates, len(payloads), echoBytes)
}
