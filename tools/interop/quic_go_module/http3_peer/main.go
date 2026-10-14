// Command peer provides the quic-go side of the netz HTTP/3 interoperability
// gate. It deliberately stays in a repository-owned, version-pinned Go module
// so the gate doesn't depend on a mutable sibling checkout.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"netz-quic-go-interop/internal/testcert"
)

const (
	cancellationResponseSize = 128 * 1024
	streamReceiveWindow      = 8 * 1024
	connectionReceiveWindow  = 24 * 1024
	readBeforeCancel         = 12 * 1024
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	address := flag.String("addr", "127.0.0.1:4433", "peer UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor for client mode")
	caOut := flag.String("ca-out", "", "PEM output path for server mode")
	v2Only := flag.Bool("v2-only", false, "require QUIC v2")
	redirect := flag.Bool("redirect", false, "serve HTTP redirect interoperability scenario")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*address, *caOut, *v2Only, *redirect)
	case "client":
		runClient(*address, *caPath, *v2Only)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

func quicConfig(v2Only bool) *quic.Config {
	version := quic.Version1
	if v2Only {
		version = quic.Version2
	}
	return &quic.Config{
		Versions:                       []quic.Version{version},
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 10 * time.Second,
		InitialStreamReceiveWindow:     streamReceiveWindow,
		MaxStreamReceiveWindow:         streamReceiveWindow,
		InitialConnectionReceiveWindow: connectionReceiveWindow,
		MaxConnectionReceiveWindow:     connectionReceiveWindow,
	}
}

func runServer(address, caOut string, v2Only, redirect bool) {
	if caOut == "" {
		log.Fatal("-ca-out is required in server mode")
	}
	certificate, certificatePEM, err := testcert.Localhost()
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}
	if err := os.WriteFile(caOut, certificatePEM, 0o600); err != nil {
		log.Fatalf("write CA PEM: %v", err)
	}

	packetConn, err := net.ListenPacket("udp4", address)
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	defer packetConn.Close()

	var negotiatedVersion atomic.Uint32
	var connectionCount atomic.Uint32
	cancelResponseStarted := make(chan struct{})
	siblingStarted := make(chan struct{})
	cancellationObserved := make(chan struct{})
	results := make(chan error, 6)
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: quicConfig(v2Only),
		ConnContext: func(ctx context.Context, connection *quic.Conn) context.Context {
			negotiatedVersion.Store(uint32(connection.ConnectionState().Version))
			connectionCount.Add(1)
			return ctx
		},
	}
	server.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if redirect {
			results <- serveRedirect(writer, request)
			return
		}
		switch request.URL.RequestURI() {
		case "/cancel?from=netz":
			results <- serveCancellation(writer, request, cancelResponseStarted, siblingStarted, cancellationObserved)
		case "/interop?from=netz":
			results <- serveSibling(writer, request, cancelResponseStarted, siblingStarted, cancellationObserved)
		default:
			results <- fmt.Errorf("unexpected request target %q", request.URL.RequestURI())
		}
	})

	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(packetConn) }()
	fmt.Printf("quic-go HTTP/3 interop server listening=%s ca_out=%s\n", packetConn.LocalAddr(), caOut)
	expectedRequests := 2
	if redirect {
		expectedRequests = 6
	}
	for range expectedRequests {
		select {
		case err := <-results:
			if err != nil {
				log.Fatal(err)
			}
		case err := <-serveErrors:
			log.Fatalf("serve HTTP/3: %v", err)
		case <-time.After(15 * time.Second):
			log.Fatal("timed out waiting for HTTP/3 requests")
		}
	}
	time.Sleep(250 * time.Millisecond)
	if err := server.Close(); err != nil {
		log.Fatalf("close HTTP/3 server: %v", err)
	}
	version := checkedVersion(negotiatedVersion.Load(), v2Only)
	if redirect {
		if connectionCount.Load() != 4 {
			log.Fatalf("unexpected redirect connection count %d", connectionCount.Load())
		}
		fmt.Printf("quic-go HTTP/3 server verified netz redirects: version=%d requests=6 redirects=3 method=POST-to-GET credentials=same-origin connections=4 exclusive_pool_connections=1 shared_pool_connections=1\n", version)
		return
	}
	fmt.Printf("quic-go HTTP/3 server interoperated with netz: version=%d cancel=H3_REQUEST_CANCELLED concurrent_sibling=true stream_window=%d large_response=%d request_body=12 request_trailers=1 response_body=16 response_trailers=1\n", version, streamReceiveWindow, cancellationResponseSize)
}

func serveRedirect(writer http.ResponseWriter, request *http.Request) error {
	switch request.URL.RequestURI() {
	case "/redirect-start?from=netz":
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return fmt.Errorf("read redirect source body: %w", err)
		}
		if request.Method != http.MethodPost || string(body) != "redirect-body" ||
			request.Header.Get("Authorization") != "Bearer quic-go-redirect" ||
			request.Header.Get("Content-Type") != "text/plain" {
			return fmt.Errorf("invalid redirect source: method=%s body=%q headers=%v", request.Method, body, request.Header)
		}
		writer.Header().Set("Location", "/redirect-final?from=quic-go#not-on-wire")
		writer.WriteHeader(http.StatusSeeOther)
		_, err = io.WriteString(writer, "redirecting")
		return err
	case "/redirect-final?from=quic-go":
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return fmt.Errorf("read redirected body: %w", err)
		}
		if request.Method != http.MethodGet || len(body) != 0 ||
			request.Header.Get("Authorization") != "Bearer quic-go-redirect" ||
			request.Header.Get("Content-Type") != "" ||
			request.Header.Get("Content-Length") != "" {
			return fmt.Errorf("invalid redirected request: method=%s body=%q headers=%v", request.Method, body, request.Header)
		}
		_, err = io.WriteString(writer, "quic-go-redirected")
		return err
	default:
		return fmt.Errorf("unexpected redirect target %q", request.URL.RequestURI())
	}
}

func serveCancellation(writer http.ResponseWriter, request *http.Request, started, siblingStarted, observed chan struct{}) error {
	if request.Method != http.MethodGet || request.ContentLength > 0 {
		return fmt.Errorf("unexpected cancellation request: method=%s content_length=%d", request.Method, request.ContentLength)
	}
	writer.Header().Set("Content-Length", fmt.Sprint(cancellationResponseSize))
	writer.Header().Set("X-Quic-Go-Cancel", "large-response-started")
	writer.WriteHeader(http.StatusOK)
	flusher, ok := writer.(interface{ FlushError() error })
	if !ok {
		return errors.New("HTTP/3 response writer has no FlushError")
	}
	if err := flusher.FlushError(); err != nil {
		return fmt.Errorf("flush cancellation response head: %w", err)
	}
	close(started)
	select {
	case <-siblingStarted:
	case <-request.Context().Done():
		return fmt.Errorf("cancellation request ended before sibling started: %w", context.Cause(request.Context()))
	}

	chunk := bytes.Repeat([]byte{'q'}, 2048)
	for written := 0; written < cancellationResponseSize; {
		n, err := writer.Write(chunk)
		written += n
		if err == nil {
			continue
		}
		var http3Err *http3.Error
		if !errors.As(err, &http3Err) || !http3Err.Remote ||
			http3Err.ErrorCode != http3.ErrCodeRequestCanceled {
			return fmt.Errorf("unexpected response cancellation after %d bytes: %w", written, err)
		}
		close(observed)
		return nil
	}
	return errors.New("cancellation response completed without H3_REQUEST_CANCELLED")
}

func serveSibling(writer http.ResponseWriter, request *http.Request, cancelStarted, started, cancellationObserved chan struct{}) error {
	select {
	case <-cancelStarted:
	case <-request.Context().Done():
		return fmt.Errorf("sibling request ended before cancellation response started: %w", context.Cause(request.Context()))
	}
	close(started)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return fmt.Errorf("read sibling request: %w", err)
	}
	if err := request.Body.Close(); err != nil {
		return fmt.Errorf("close sibling request: %w", err)
	}
	if request.Method != http.MethodPost || string(body) != "netz-request" ||
		request.Header.Get("X-Netz-Request") != "request-header" ||
		request.Trailer.Get("X-Netz-Trailer") != "request-trailer" {
		return fmt.Errorf("invalid sibling request: method=%s body=%q headers=%v trailers=%v", request.Method, body, request.Header, request.Trailer)
	}
	select {
	case <-cancellationObserved:
	case <-request.Context().Done():
		return fmt.Errorf("sibling ended before cancellation recovery: %w", context.Cause(request.Context()))
	}

	writer.Header().Set("X-Quic-Go-Response", "response-header")
	writer.Header().Set("Trailer", "X-Quic-Go-Trailer")
	writer.WriteHeader(http.StatusCreated)
	if _, err := io.WriteString(writer, "quic-go-response"); err != nil {
		return fmt.Errorf("write sibling response: %w", err)
	}
	writer.Header().Set("X-Quic-Go-Trailer", "response-trailer")
	return nil
}

type cancellationDropConn struct {
	net.PacketConn
	dropNext atomic.Bool
	dropped  atomic.Uint32
}

func (conn *cancellationDropConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	// quic-go records PacketSent synchronously before enqueueing the same
	// datagram for this write, so the tracer below selects that exact packet.
	if conn.dropNext.CompareAndSwap(true, false) {
		conn.dropped.Add(1)
		return len(packet), nil
	}
	return conn.PacketConn.WriteTo(packet, address)
}

type cancellationTrace struct {
	dropConn      *cancellationDropConn
	armed         atomic.Bool
	transmissions atomic.Uint32
}

func (trace *cancellationTrace) AddProducer() qlogwriter.Recorder { return trace }
func (trace *cancellationTrace) SupportsSchemas(string) bool      { return true }
func (trace *cancellationTrace) Close() error                     { return nil }

func (trace *cancellationTrace) RecordEvent(event qlogwriter.Event) {
	packet, ok := event.(qlog.PacketSent)
	if !ok || !trace.armed.Load() {
		return
	}
	for _, frame := range packet.Frames {
		stop, ok := frame.Frame.(*qlog.StopSendingFrame)
		if !ok || stop.StreamID != 0 ||
			stop.ErrorCode != quic.StreamErrorCode(http3.ErrCodeRequestCanceled) {
			continue
		}
		if trace.transmissions.Add(1) == 1 {
			trace.dropConn.dropNext.Store(true)
		}
	}
}

func runClient(address, caPath string, v2Only bool) {
	if caPath == "" {
		log.Fatal("-ca is required in client mode")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("read CA bundle: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("parse CA bundle")
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen UDP: %v", err)
	}
	dropConn := &cancellationDropConn{PacketConn: packetConn}
	trace := &cancellationTrace{dropConn: dropConn}
	config := quicConfig(v2Only)
	config.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return trace
	}
	quicTransport := &quic.Transport{Conn: dropConn}
	defer quicTransport.Close()
	var dialCount atomic.Uint32
	var negotiatedVersion atomic.Uint32
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
		},
		QUICConfig: config,
		Dial: func(ctx context.Context, peer string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			dialCount.Add(1)
			udpAddress, err := net.ResolveUDPAddr("udp4", peer)
			if err != nil {
				return nil, err
			}
			connection, err := quicTransport.DialEarly(ctx, udpAddress, tlsConfig, quicConfig)
			if err == nil {
				negotiatedVersion.Store(uint32(connection.ConnectionState().Version))
			}
			return connection, err
		},
	}
	defer transport.Close()
	client := &http.Client{Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cancelRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/cancel-response?from=quic-go", nil)
	if err != nil {
		log.Fatalf("build cancellation request: %v", err)
	}
	cancelRequest.Host = "localhost"
	cancelResponse, err := client.Do(cancelRequest)
	if err != nil {
		log.Fatalf("start cancellation request: %v", err)
	}
	if cancelResponse.StatusCode != http.StatusOK ||
		cancelResponse.ContentLength != cancellationResponseSize ||
		cancelResponse.Header.Get("X-Netz-Cancel") != "large-response-started" {
		log.Fatalf("invalid cancellation response: status=%d length=%d headers=%v", cancelResponse.StatusCode, cancelResponse.ContentLength, cancelResponse.Header)
	}

	siblingResult := make(chan error, 1)
	go func() { siblingResult <- runSiblingClient(ctx, client, address) }()
	prefix := make([]byte, readBeforeCancel)
	if _, err := io.ReadFull(cancelResponse.Body, prefix); err != nil {
		log.Fatalf("read cancellation response prefix: %v", err)
	}
	if !bytes.Equal(prefix, bytes.Repeat([]byte{'n'}, len(prefix))) {
		log.Fatal("invalid cancellation response prefix")
	}
	trace.armed.Store(true)
	if err := cancelResponse.Body.Close(); err != nil {
		log.Fatalf("cancel response body: %v", err)
	}
	select {
	case err := <-siblingResult:
		if err != nil {
			log.Fatal(err)
		}
	case <-ctx.Done():
		log.Fatalf("wait for sibling response: %v", context.Cause(ctx))
	}
	if dialCount.Load() != 1 || dropConn.dropped.Load() != 1 || trace.transmissions.Load() < 2 {
		log.Fatalf("invalid cancellation recovery: dials=%d dropped=%d stop_sending=%d", dialCount.Load(), dropConn.dropped.Load(), trace.transmissions.Load())
	}
	version := checkedVersion(negotiatedVersion.Load(), v2Only)
	fmt.Printf("quic-go HTTP/3 client interoperated with netz: version=%d cancel=H3_REQUEST_CANCELLED dropped_stop_sending=1 stop_sending_transmissions>=2 concurrent_sibling=true connection_reused=true stream_window=%d read_before_cancel=%d large_response=%d request_body=15 request_trailers=1 response_body=13 response_trailers=1\n", version, streamReceiveWindow, readBeforeCancel, cancellationResponseSize)
}

func runSiblingClient(ctx context.Context, client *http.Client, address string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+"/interop?from=quic-go", bytes.NewBufferString("quic-go-request"))
	if err != nil {
		return fmt.Errorf("build sibling request: %w", err)
	}
	request.Host = "localhost"
	request.Header.Set("X-Quic-Go-Request", "request-header")
	request.Trailer = http.Header{"X-Quic-Go-Trailer": []string{"request-trailer"}}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send sibling request: %w", err)
	}
	body, err := io.ReadAll(response.Body)
	if err == nil {
		err = response.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("read sibling response: %w", err)
	}
	if response.StatusCode != http.StatusCreated || string(body) != "netz-response" ||
		response.Header.Get("X-Netz-Response") != "response-header" ||
		response.Trailer.Get("X-Netz-Trailer") != "response-trailer" {
		return fmt.Errorf("invalid sibling response: status=%d body=%q headers=%v trailers=%v", response.StatusCode, body, response.Header, response.Trailer)
	}
	return nil
}

func checkedVersion(actual uint32, v2Only bool) int {
	expected := quic.Version1
	version := 1
	if v2Only {
		expected = quic.Version2
		version = 2
	}
	if actual != uint32(expected) {
		log.Fatalf("negotiated QUIC version %#x, want v%d", actual, version)
	}
	return version
}
