// Command websocket_h3_quic_go is an RFC 9220 peer used by netz's
// process-boundary WebSocket-over-HTTP/3 interoperability gate. Its RFC 6455
// framing is intentionally implemented here instead of sharing netz's codec.
package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa
)

const (
	websocketPath           = "/rfc9220"
	origin                  = "https://example.test"
	protocol                = "netz-chat"
	perMessageDeflate       = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
	clientMessage           = "netz websocket h3"
	serverMessage           = "quic-go websocket h3"
	clientCompressedMessage = "netz compressed websocket h3 netz compressed websocket h3 netz compressed websocket h3"
	serverCompressedMessage = "quic-go compressed websocket h3 quic-go compressed websocket h3 quic-go compressed websocket h3"
	clientCompressedAgain   = "netz second compressed message netz second compressed message netz second compressed message"
	serverCompressedAgain   = "quic-go second compressed message quic-go second compressed message quic-go second compressed message"
	pingPayload             = "probe"
	closeReason             = "done"
	normalCloseCode         = 1000
	maxFramePayload         = 4096
)

type benchmarkConfig struct {
	warmup       uint32
	iterations   uint32
	payloadBytes uint32
	timeout      time.Duration
}

type memorySnapshot struct {
	mallocs    uint64
	frees      uint64
	totalAlloc uint64
	heapAlloc  uint64
	heapSys    uint64
	sys        uint64
	numGC      uint32
}

func readMemory() memorySnapshot {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return memorySnapshot{
		mallocs: stats.Mallocs, frees: stats.Frees, totalAlloc: stats.TotalAlloc,
		heapAlloc: stats.HeapAlloc, heapSys: stats.HeapSys, sys: stats.Sys,
		numGC: stats.NumGC,
	}
}

func (config benchmarkConfig) rounds() uint32 { return config.warmup + config.iterations }
func (config benchmarkConfig) aggregateTimeout() time.Duration {
	rounds := uint64(config.rounds()) + 2
	if uint64(config.timeout) > uint64(math.MaxInt64)/rounds {
		return time.Duration(math.MaxInt64)
	}
	return config.timeout * time.Duration(rounds)
}

func (config benchmarkConfig) validate() error {
	if config.iterations == 0 || config.payloadBytes == 0 ||
		config.warmup > 100_000 || config.iterations > 1_000_000 ||
		config.payloadBytes > maxFramePayload || config.timeout <= 0 ||
		config.timeout > 10*time.Minute || config.rounds() < config.warmup {
		return errors.New("invalid WebSocket benchmark configuration")
	}
	return nil
}

type frame struct {
	fin     bool
	opcode  byte
	masked  bool
	rsv1    bool
	payload []byte
}

type frameReadOptions struct {
	expectMasked bool
	allowRSV1    bool
}

type frameWriteOptions struct {
	fin    bool
	masked bool
	rsv1   bool
}

type deadlineReadWriter interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
}

func main() {
	mode := flag.String("mode", "server", "server or client")
	address := flag.String("addr", "127.0.0.1:4433", "peer UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor for client mode")
	caOut := flag.String("ca-out", "", "PEM output path for server mode")
	v2Only := flag.Bool("v2-only", false, "use only QUIC v2")
	warmup := flag.Uint("warmup", 20, "benchmark warmup roundtrips")
	iterations := flag.Uint("iterations", 1000, "benchmark measured roundtrips")
	payloadBytes := flag.Uint("payload-bytes", 4096, "benchmark binary payload bytes")
	timeoutMS := flag.Uint("timeout-ms", 30000, "benchmark per-operation timeout milliseconds")
	stats := flag.Bool("stats", false, "report Go runtime heap telemetry")
	flag.Parse()
	if *warmup > math.MaxUint32 || *iterations > math.MaxUint32 ||
		*payloadBytes > math.MaxUint32 || *timeoutMS > math.MaxUint32 {
		log.Fatal("WebSocket benchmark option exceeds uint32")
	}
	benchmark := benchmarkConfig{
		warmup: uint32(*warmup), iterations: uint32(*iterations),
		payloadBytes: uint32(*payloadBytes), timeout: time.Duration(*timeoutMS) * time.Millisecond,
	}

	switch *mode {
	case "server":
		runServer(*address, *caOut, *v2Only)
	case "client":
		runClient(*address, *caPath, *v2Only)
	case "bench-server":
		if err := benchmark.validate(); err != nil {
			log.Fatal(err)
		}
		var before memorySnapshot
		if *stats {
			before = readMemory()
		}
		runBenchmarkServer(*address, *caOut, benchmark)
		if *stats {
			printMemory("netz-client+quic-go-server", "server", benchmark, before, readMemory())
		}
	case "bench-client":
		if err := benchmark.validate(); err != nil {
			log.Fatal(err)
		}
		var before memorySnapshot
		if *stats {
			before = readMemory()
		}
		runBenchmarkClient(*address, *caPath, benchmark)
		if *stats {
			printMemory("quic-go-client+netz-server", "client", benchmark, before, readMemory())
		}
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

func benchmarkQUICConfig(config benchmarkConfig) *quic.Config {
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1},
		HandshakeIdleTimeout:           config.timeout,
		MaxIdleTimeout:                 config.timeout,
		InitialStreamReceiveWindow:     1024 * 1024,
		MaxStreamReceiveWindow:         1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     8 * 1024 * 1024,
		MaxIncomingStreams:             16,
		MaxIncomingUniStreams:          16,
		InitialPacketSize:              1280,
		DisablePathMTUDiscovery:        true,
	}
}

func quicConfig(v2Only bool) *quic.Config {
	config := &quic.Config{}
	if v2Only {
		config.Versions = []quic.Version{quic.Version2}
	}
	return config
}

func runServer(address, caOut string, v2Only bool) {
	if caOut == "" {
		log.Fatal("-ca-out is required in server mode")
	}
	certificate, certificatePEM, err := localhostCertificate()
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}
	if err := os.WriteFile(caOut, certificatePEM, 0o600); err != nil {
		log.Fatalf("write CA PEM: %v", err)
	}

	served := make(chan error, 1)
	negotiatedVersion := make(chan quic.Version, 1)
	server := &http3.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: quicConfig(v2Only),
		ConnContext: func(ctx context.Context, connection *quic.Conn) context.Context {
			select {
			case negotiatedVersion <- connection.ConnectionState().Version:
			default:
			}
			return ctx
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			served <- serveWebSocket(writer, request)
		}),
	}
	errChan := make(chan error, 1)
	go func() { errChan <- server.ListenAndServe() }()
	fmt.Printf("quic-go RFC 9220 server listening=%s ca_out=%s\n", address, caOut)

	select {
	case err := <-served:
		if err != nil {
			log.Fatal(err)
		}
	case err := <-errChan:
		log.Fatalf("serve HTTP/3: %v", err)
	case <-time.After(10 * time.Second):
		log.Fatal("timed out waiting for RFC 9220 session")
	}
	// A successful handler write precedes ACK processing. Leave the connection
	// alive briefly so the peer can consume the close response before teardown.
	time.Sleep(250 * time.Millisecond)
	if err := server.Close(); err != nil {
		log.Fatalf("close HTTP/3 server: %v", err)
	}
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP/3 server exit: %v", err)
		}
	case <-time.After(time.Second):
		log.Fatal("timed out stopping HTTP/3 server")
	}
	verifyVersion(<-negotiatedVersion, v2Only)
	fmt.Printf("quic-go RFC 9220 server interoperated with netz: version=%d extended_connect=true origin=true subprotocol=%s masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/%s\n", versionNumber(v2Only), protocol, closeReason)
}

func runBenchmarkServer(address, caOut string, config benchmarkConfig) {
	if caOut == "" {
		log.Fatal("-ca-out is required in benchmark server mode")
	}
	certificate, certificatePEM, err := localhostCertificate()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caOut, certificatePEM, 0o600); err != nil {
		log.Fatal(err)
	}
	served := make(chan error, 1)
	server := &http3.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: benchmarkQUICConfig(config),
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			served <- serveBenchmarkWebSocket(writer, request, config)
		}),
	}
	errChan := make(chan error, 1)
	go func() { errChan <- server.ListenAndServe() }()
	fmt.Printf("QUIC_GO_WEBSOCKET_H3_BENCH_ADDR=%s\n", address)
	printBenchmarkConfig("netz-client+quic-go-server", config)
	select {
	case err := <-served:
		if err != nil {
			log.Fatal(err)
		}
	case err := <-errChan:
		log.Fatal(err)
	case <-time.After(config.aggregateTimeout()):
		log.Fatal("WebSocket-over-H3 benchmark server timed out")
	}
	time.Sleep(100 * time.Millisecond)
	if err := server.Close(); err != nil {
		log.Fatalf("close HTTP/3 benchmark server: %v", err)
	}
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP/3 benchmark server exit: %v", err)
		}
	case <-time.After(time.Second):
		log.Fatal("timed out stopping HTTP/3 benchmark server")
	}
}

func serveBenchmarkWebSocket(writer http.ResponseWriter, request *http.Request, config benchmarkConfig) error {
	if request.Method != http.MethodConnect || request.Proto != "websocket" ||
		request.ProtoMajor != 3 || request.URL.RequestURI() != "/rfc9220-benchmark" ||
		request.Host != "localhost" || request.Header.Get("Origin") != origin ||
		request.Header.Get("Sec-WebSocket-Version") != "13" ||
		request.Header.Get("Sec-WebSocket-Protocol") != "netz-benchmark" ||
		request.Header.Get("Sec-WebSocket-Extensions") != "" {
		return fmt.Errorf("unexpected benchmark RFC 9220 request: method=%s protocol=%s target=%s host=%s headers=%v", request.Method, request.Proto, request.URL.RequestURI(), request.Host, request.Header)
	}
	if err := validateBenchmarkHeaders(request.Header, config); err != nil {
		return err
	}
	writer.Header().Set("Sec-WebSocket-Protocol", "netz-benchmark")
	writer.WriteHeader(http.StatusOK)
	stream := writer.(http3.HTTPStreamer).HTTPStream()
	if err := stream.SetDeadline(time.Now().Add(config.timeout)); err != nil {
		return err
	}
	return runBenchmarkEchoServer(stream, config, true)
}

func runBenchmarkClient(address, caPath string, config benchmarkConfig) {
	if caPath == "" {
		log.Fatal("-ca is required in benchmark client mode")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("parse CA bundle")
	}
	connectContext, cancelConnect := context.WithTimeout(context.Background(), config.timeout)
	connection, err := quic.DialAddr(connectContext, address, &tls.Config{
		RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
	}, benchmarkQUICConfig(config))
	cancelConnect()
	if err != nil {
		log.Fatal(err)
	}
	defer connection.CloseWithError(0, "")
	client := (&http3.Transport{}).NewClientConn(connection)
	settingsTimer := time.NewTimer(config.timeout)
	defer settingsTimer.Stop()
	select {
	case <-client.ReceivedSettings():
	case <-settingsTimer.C:
		log.Fatal("timed out waiting for HTTP/3 SETTINGS")
	}
	if !client.Settings().EnableExtendedConnect {
		log.Fatal("netz server didn't enable Extended CONNECT")
	}
	openContext, cancelOpen := context.WithTimeout(context.Background(), config.timeout)
	stream, err := client.OpenRequestStream(openContext)
	cancelOpen()
	if err != nil {
		log.Fatal(err)
	}
	if err := stream.SetDeadline(time.Now().Add(config.timeout)); err != nil {
		log.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, "https://localhost/rfc9220-benchmark", nil)
	if err != nil {
		log.Fatal(err)
	}
	request.Host = "localhost"
	request.Proto = "websocket"
	request.Header.Set("Origin", origin)
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Protocol", "netz-benchmark")
	setBenchmarkHeaders(request.Header, config)
	if err := stream.SendRequestHeader(request); err != nil {
		log.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		log.Fatal(err)
	}
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Sec-WebSocket-Protocol") != "netz-benchmark" ||
		response.Header.Get("Sec-WebSocket-Extensions") != "" {
		log.Fatalf("unexpected benchmark RFC 9220 response: status=%d headers=%v", response.StatusCode, response.Header)
	}
	printBenchmarkConfig("quic-go-client+netz-server", config)
	elapsed, checksum, err := runBenchmarkEchoClient(stream, config, true)
	if err != nil {
		log.Fatal(err)
	}
	printBenchmarkResult("quic-go-client+netz-server", config, elapsed, checksum)
}

func runBenchmarkEchoServer(stream deadlineReadWriter, config benchmarkConfig, expectMasked bool) error {
	ready := []byte("NZWSREADY")
	if err := writeFrameReusable(stream, opBinary, ready, frameWriteOptions{fin: true}, nil); err != nil {
		return err
	}
	payload := make([]byte, config.payloadBytes)
	var checksum uint64
	for round := uint32(0); round < config.rounds(); round++ {
		if err := stream.SetDeadline(time.Now().Add(config.timeout)); err != nil {
			return err
		}
		frame, err := readFrameInto(stream, frameReadOptions{expectMasked: expectMasked}, payload)
		if err != nil {
			return err
		}
		if !frame.fin || frame.opcode != opBinary || frame.rsv1 || len(frame.payload) != len(payload) {
			return fmt.Errorf("unexpected benchmark frame: %+v", frame)
		}
		roundChecksum, err := verifyBenchmarkPayload(frame.payload, round)
		if err != nil {
			return err
		}
		if round >= config.warmup {
			checksum += roundChecksum
		}
		if err := writeFrameReusable(stream, opBinary, frame.payload, frameWriteOptions{fin: true}, nil); err != nil {
			return err
		}
	}
	if err := stream.SetDeadline(time.Now().Add(config.timeout)); err != nil {
		return err
	}
	closeFrame, err := readFrame(stream, frameReadOptions{expectMasked: expectMasked})
	if err != nil {
		return err
	}
	code, reason, err := parseClose(closeFrame)
	if err != nil || code != normalCloseCode || reason != closeReason {
		return fmt.Errorf("unexpected benchmark close: code=%d reason=%q err=%v", code, reason, err)
	}
	if err := writeFrameReusable(stream, opClose, closeFrame.payload, frameWriteOptions{fin: true}, nil); err != nil {
		return err
	}
	printBenchmarkServerComplete("quic-go", "netz-client+quic-go-server", config, checksum)
	return nil
}

func runBenchmarkEchoClient(stream deadlineReadWriter, config benchmarkConfig, masked bool) (time.Duration, uint64, error) {
	readyStorage := make([]byte, len("NZWSREADY"))
	ready, err := readFrameInto(stream, frameReadOptions{}, readyStorage)
	if err != nil || ready.opcode != opBinary || !ready.fin || string(ready.payload) != "NZWSREADY" {
		return 0, 0, fmt.Errorf("invalid benchmark ready frame: %+v err=%v", ready, err)
	}
	payload := make([]byte, config.payloadBytes)
	response := make([]byte, config.payloadBytes)
	wire := make([]byte, config.payloadBytes)
	for round := uint32(0); round < config.warmup; round++ {
		if _, err := benchmarkEchoRound(stream, config, round, payload, response, wire, masked); err != nil {
			return 0, 0, err
		}
	}
	started := time.Now()
	var checksum uint64
	for sample := uint32(0); sample < config.iterations; sample++ {
		round := config.warmup + sample
		value, err := benchmarkEchoRound(stream, config, round, payload, response, wire, masked)
		if err != nil {
			return 0, 0, err
		}
		checksum += value
	}
	elapsed := time.Since(started)
	closePayload := make([]byte, 2+len(closeReason))
	binary.BigEndian.PutUint16(closePayload, normalCloseCode)
	copy(closePayload[2:], closeReason)
	if err := stream.SetDeadline(time.Now().Add(config.timeout)); err != nil {
		return 0, 0, err
	}
	if err := writeFrame(stream, opClose, closePayload, frameWriteOptions{fin: true, masked: masked}); err != nil {
		return 0, 0, err
	}
	closeFrame, err := readFrame(stream, frameReadOptions{})
	if err != nil {
		return 0, 0, err
	}
	code, reason, err := parseClose(closeFrame)
	if err != nil || code != normalCloseCode || reason != closeReason {
		return 0, 0, fmt.Errorf("unexpected benchmark close response: code=%d reason=%q err=%v", code, reason, err)
	}
	return elapsed, checksum, nil
}

func benchmarkEchoRound(stream deadlineReadWriter, config benchmarkConfig, round uint32, payload, response, wire []byte, masked bool) (uint64, error) {
	if err := stream.SetDeadline(time.Now().Add(config.timeout)); err != nil {
		return 0, err
	}
	expected := fillBenchmarkPayload(payload, round)
	if err := writeFrameReusable(stream, opBinary, payload, frameWriteOptions{fin: true, masked: masked}, wire); err != nil {
		return 0, err
	}
	frame, err := readFrameInto(stream, frameReadOptions{}, response)
	if err != nil {
		return 0, err
	}
	if !frame.fin || frame.opcode != opBinary || frame.rsv1 || uint32(len(frame.payload)) != config.payloadBytes {
		return 0, fmt.Errorf("unexpected benchmark echo: %+v", frame)
	}
	actual, err := verifyBenchmarkPayload(frame.payload, round)
	if err != nil || actual != expected {
		return 0, fmt.Errorf("benchmark echo mismatch checksum=%d expected=%d err=%v", actual, expected, err)
	}
	return actual, nil
}

func serveWebSocket(writer http.ResponseWriter, request *http.Request) error {
	if request.Method != http.MethodConnect || request.Proto != "websocket" ||
		request.ProtoMajor != 3 || request.URL.RequestURI() != websocketPath ||
		request.Host != "localhost" || request.Header.Get("Origin") != origin ||
		request.Header.Get("Sec-WebSocket-Version") != "13" ||
		request.Header.Get("Sec-WebSocket-Protocol") != protocol ||
		request.Header.Get("Sec-WebSocket-Extensions") != perMessageDeflate {
		return fmt.Errorf("unexpected RFC 9220 request: method=%s protocol=%s target=%s host=%s headers=%v", request.Method, request.Proto, request.URL.RequestURI(), request.Host, request.Header)
	}
	writer.Header().Set("Sec-WebSocket-Protocol", protocol)
	writer.Header().Set("Sec-WebSocket-Extensions", perMessageDeflate)
	writer.WriteHeader(http.StatusOK)
	stream := writer.(http3.HTTPStreamer).HTTPStream()
	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	return serverConversation(stream)
}

func serverConversation(stream io.ReadWriter) error {
	first, err := readFrame(stream, frameReadOptions{expectMasked: true})
	if err != nil {
		return err
	}
	second, err := readFrame(stream, frameReadOptions{expectMasked: true})
	if err != nil {
		return err
	}
	combined := append(append([]byte(nil), first.payload...), second.payload...)
	if first.fin || first.opcode != opText || !second.fin ||
		second.opcode != opContinuation || string(combined) != clientMessage {
		return fmt.Errorf("unexpected fragmented client message: first=%+v second=%+v", first, second)
	}
	if err := writeFrame(stream, opText, []byte(serverMessage), frameWriteOptions{fin: true}); err != nil {
		return err
	}
	for index, exchange := range []struct {
		client string
		server string
	}{
		{clientCompressedMessage, serverCompressedMessage},
		{clientCompressedAgain, serverCompressedAgain},
	} {
		compressed, err := readFrame(stream, frameReadOptions{
			expectMasked: true,
			allowRSV1:    true,
		})
		if err != nil {
			return err
		}
		if !compressed.fin || compressed.opcode != opText || !compressed.rsv1 {
			return fmt.Errorf("unexpected compressed client frame %d: %+v", index, compressed)
		}
		decoded, err := decompressMessage(compressed.payload)
		if err != nil || string(decoded) != exchange.client {
			return fmt.Errorf("unexpected compressed client message %d: payload=%q err=%v", index, decoded, err)
		}
		encoded, err := compressMessage([]byte(exchange.server))
		if err != nil {
			return err
		}
		if len(encoded) >= len(exchange.server) {
			return fmt.Errorf("server permessage-deflate payload %d did not shrink", index)
		}
		if err := writeFrame(stream, opText, encoded, frameWriteOptions{
			fin:  true,
			rsv1: true,
		}); err != nil {
			return err
		}
	}
	ping, err := readFrame(stream, frameReadOptions{expectMasked: true})
	if err != nil {
		return err
	}
	if !ping.fin || ping.opcode != opPing || string(ping.payload) != pingPayload {
		return fmt.Errorf("unexpected ping: %+v", ping)
	}
	if err := writeFrame(stream, opPong, ping.payload, frameWriteOptions{fin: true}); err != nil {
		return err
	}
	closeFrame, err := readFrame(stream, frameReadOptions{expectMasked: true})
	if err != nil {
		return err
	}
	code, reason, err := parseClose(closeFrame)
	if err != nil || code != normalCloseCode || reason != closeReason {
		return fmt.Errorf("unexpected close: code=%d reason=%q err=%v", code, reason, err)
	}
	return writeFrame(stream, opClose, closeFrame.payload, frameWriteOptions{fin: true})
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := quic.DialAddr(ctx, address, &tls.Config{
		RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
	}, quicConfig(v2Only))
	if err != nil {
		log.Fatalf("dial QUIC: %v", err)
	}
	defer connection.CloseWithError(0, "")
	client := (&http3.Transport{}).NewClientConn(connection)
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		log.Fatal("timed out waiting for HTTP/3 SETTINGS")
	}
	if !client.Settings().EnableExtendedConnect {
		log.Fatal("netz server didn't enable Extended CONNECT")
	}
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		log.Fatalf("open request stream: %v", err)
	}
	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Fatalf("set request-stream deadline: %v", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://localhost"+websocketPath, nil)
	if err != nil {
		log.Fatalf("build RFC 9220 request: %v", err)
	}
	request.Host = "localhost"
	request.Proto = "websocket"
	request.Header.Set("Origin", origin)
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Protocol", protocol)
	request.Header.Set("Sec-WebSocket-Extensions", perMessageDeflate)
	if err := stream.SendRequestHeader(request); err != nil {
		log.Fatalf("send RFC 9220 request: %v", err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		log.Fatalf("read RFC 9220 response: %v", err)
	}
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Sec-WebSocket-Protocol") != protocol ||
		response.Header.Get("Sec-WebSocket-Extensions") != perMessageDeflate {
		log.Fatalf("unexpected RFC 9220 response: status=%d headers=%v", response.StatusCode, response.Header)
	}
	if err := clientConversation(stream); err != nil {
		log.Fatal(err)
	}
	verifyVersion(connection.ConnectionState().Version, v2Only)
	fmt.Printf("quic-go RFC 9220 client interoperated with netz: version=%d extended_connect=true origin=true subprotocol=%s masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/%s\n", versionNumber(v2Only), protocol, closeReason)
}

func clientConversation(stream io.ReadWriter) error {
	split := len(clientMessage) / 2
	if err := writeFrame(stream, opText, []byte(clientMessage[:split]), frameWriteOptions{
		masked: true,
	}); err != nil {
		return err
	}
	if err := writeFrame(stream, opContinuation, []byte(clientMessage[split:]), frameWriteOptions{
		fin:    true,
		masked: true,
	}); err != nil {
		return err
	}
	response, err := readFrame(stream, frameReadOptions{})
	if err != nil {
		return err
	}
	if !response.fin || response.opcode != opText || string(response.payload) != serverMessage {
		return fmt.Errorf("unexpected text response: %+v", response)
	}
	for index, exchange := range []struct {
		client string
		server string
	}{
		{clientCompressedMessage, serverCompressedMessage},
		{clientCompressedAgain, serverCompressedAgain},
	} {
		encoded, err := compressMessage([]byte(exchange.client))
		if err != nil {
			return err
		}
		if len(encoded) >= len(exchange.client) {
			return fmt.Errorf("client permessage-deflate payload %d did not shrink", index)
		}
		if err := writeFrame(stream, opText, encoded, frameWriteOptions{
			fin:    true,
			masked: true,
			rsv1:   true,
		}); err != nil {
			return err
		}
		compressed, err := readFrame(stream, frameReadOptions{allowRSV1: true})
		if err != nil {
			return err
		}
		if !compressed.fin || compressed.opcode != opText || !compressed.rsv1 {
			return fmt.Errorf("unexpected compressed server frame %d: %+v", index, compressed)
		}
		decoded, err := decompressMessage(compressed.payload)
		if err != nil || string(decoded) != exchange.server {
			return fmt.Errorf("unexpected compressed server message %d: payload=%q err=%v", index, decoded, err)
		}
	}
	if err := writeFrame(stream, opPing, []byte(pingPayload), frameWriteOptions{
		fin:    true,
		masked: true,
	}); err != nil {
		return err
	}
	pong, err := readFrame(stream, frameReadOptions{})
	if err != nil {
		return err
	}
	if !pong.fin || pong.opcode != opPong || string(pong.payload) != pingPayload {
		return fmt.Errorf("unexpected pong: %+v", pong)
	}
	closePayload := make([]byte, 2+len(closeReason))
	binary.BigEndian.PutUint16(closePayload, normalCloseCode)
	copy(closePayload[2:], closeReason)
	if err := writeFrame(stream, opClose, closePayload, frameWriteOptions{
		fin:    true,
		masked: true,
	}); err != nil {
		return err
	}
	closeFrame, err := readFrame(stream, frameReadOptions{})
	if err != nil {
		return err
	}
	code, reason, err := parseClose(closeFrame)
	if err != nil || code != normalCloseCode || reason != closeReason {
		return fmt.Errorf("unexpected close response: code=%d reason=%q err=%v", code, reason, err)
	}
	return nil
}

func readFrame(reader io.Reader, options frameReadOptions) (frame, error) {
	payload := make([]byte, maxFramePayload)
	return readFrameInto(reader, options, payload)
}

func readFrameInto(reader io.Reader, options frameReadOptions, storage []byte) (frame, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return frame{}, err
	}
	result := frame{
		fin: header[0]&0x80 != 0, opcode: header[0] & 0x0f,
		masked: header[1]&0x80 != 0, rsv1: header[0]&0x40 != 0,
	}
	if !validOpcode(result.opcode) {
		return frame{}, fmt.Errorf("invalid RFC 6455 opcode: %#x", result.opcode)
	}
	if header[0]&0x30 != 0 || result.masked != options.expectMasked ||
		(result.rsv1 && (!options.allowRSV1 || result.opcode == opContinuation || result.opcode >= opClose)) {
		return frame{}, fmt.Errorf("invalid RFC 6455 header: %#x %#x", header[0], header[1])
	}
	length := uint64(header[1] & 0x7f)
	if result.opcode >= opClose && (!result.fin || length > 125) {
		return frame{}, errors.New("invalid RFC 6455 control frame")
	}
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return frame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
		if length <= 125 {
			return frame{}, errors.New("non-minimal WebSocket payload length")
		}
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return frame{}, err
		}
		length = binary.BigEndian.Uint64(extended[:])
		if length>>63 != 0 {
			return frame{}, errors.New("invalid 64-bit WebSocket payload length")
		}
		if length <= 65535 {
			return frame{}, errors.New("non-minimal WebSocket payload length")
		}
	}
	if length > maxFramePayload {
		return frame{}, fmt.Errorf("WebSocket payload too large: %d", length)
	}
	var mask [4]byte
	if result.masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return frame{}, err
		}
	}
	if length > uint64(len(storage)) {
		return frame{}, fmt.Errorf("WebSocket payload exceeds destination: %d > %d", length, len(storage))
	}
	result.payload = storage[:int(length)]
	if _, err := io.ReadFull(reader, result.payload); err != nil {
		return frame{}, err
	}
	if result.masked {
		for index := range result.payload {
			result.payload[index] ^= mask[index%len(mask)]
		}
	}
	return result, nil
}

func writeFrame(writer io.Writer, opcode byte, payload []byte, options frameWriteOptions) error {
	var wire [maxFramePayload]byte
	return writeFrameReusable(writer, opcode, payload, options, wire[:])
}

func writeFrameReusable(writer io.Writer, opcode byte, payload []byte, options frameWriteOptions, wireStorage []byte) error {
	if !validOpcode(opcode) || len(payload) > maxFramePayload {
		return errors.New("invalid WebSocket frame")
	}
	if opcode >= opClose && (!options.fin || len(payload) > 125) {
		return errors.New("invalid control frame")
	}
	if options.rsv1 && (opcode == opContinuation || opcode >= opClose) {
		return errors.New("invalid compressed frame opcode")
	}
	var headerStorage [14]byte
	header := headerStorage[:2]
	header[0] = opcode
	header[1] = 0
	if options.fin {
		header[0] |= 0x80
	}
	if options.rsv1 {
		header[0] |= 0x40
	}
	if options.masked {
		header[1] |= 0x80
	}
	switch {
	case len(payload) <= 125:
		header[1] |= byte(len(payload))
	case len(payload) <= 65535:
		header[1] |= 126
		binary.BigEndian.PutUint16(headerStorage[2:4], uint16(len(payload)))
		header = headerStorage[:4]
	default:
		header[1] |= 127
		binary.BigEndian.PutUint64(headerStorage[2:10], uint64(len(payload)))
		header = headerStorage[:10]
	}
	wirePayload := payload
	if options.masked {
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		copy(headerStorage[len(header):], mask[:])
		header = headerStorage[:len(header)+len(mask)]
		if len(wireStorage) < len(payload) {
			return errors.New("masked WebSocket payload exceeds scratch")
		}
		wirePayload = wireStorage[:len(payload)]
		for index, value := range payload {
			wirePayload[index] = value ^ mask[index%len(mask)]
		}
	}
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, wirePayload)
}

func setBenchmarkHeaders(headers http.Header, config benchmarkConfig) {
	headers.Set("X-Netz-Bench-Warmup", strconv.FormatUint(uint64(config.warmup), 10))
	headers.Set("X-Netz-Bench-Iterations", strconv.FormatUint(uint64(config.iterations), 10))
	headers.Set("X-Netz-Bench-Payload-Bytes", strconv.FormatUint(uint64(config.payloadBytes), 10))
	headers.Set("X-Netz-Bench-Timeout-Ms", strconv.FormatUint(uint64(config.timeout/time.Millisecond), 10))
}

func validateBenchmarkHeaders(headers http.Header, config benchmarkConfig) error {
	expected := map[string]uint64{
		"X-Netz-Bench-Warmup":        uint64(config.warmup),
		"X-Netz-Bench-Iterations":    uint64(config.iterations),
		"X-Netz-Bench-Payload-Bytes": uint64(config.payloadBytes),
		"X-Netz-Bench-Timeout-Ms":    uint64(config.timeout / time.Millisecond),
	}
	for name, wanted := range expected {
		value, err := strconv.ParseUint(headers.Get(name), 10, 64)
		if err != nil || value != wanted {
			return fmt.Errorf("invalid benchmark header %s=%q", name, headers.Get(name))
		}
	}
	return nil
}

func benchmarkPayloadByte(round uint32, offset int) byte {
	return byte(uint64(offset)*131 + uint64(round)*17)
}

func fillBenchmarkPayload(payload []byte, round uint32) uint64 {
	var checksum uint64
	for index := range payload {
		payload[index] = benchmarkPayloadByte(round, index)
		checksum += uint64(payload[index])
	}
	return checksum
}

func verifyBenchmarkPayload(payload []byte, round uint32) (uint64, error) {
	var checksum uint64
	for index, value := range payload {
		if value != benchmarkPayloadByte(round, index) {
			return 0, fmt.Errorf("benchmark payload mismatch at %d", index)
		}
		checksum += uint64(value)
	}
	return checksum, nil
}

func printBenchmarkConfig(rolePair string, config benchmarkConfig) {
	fmt.Printf("protocol=websocket-h3 transport=h3 mode=binary-echo role_pair=%s connection_scope=persistent benchmark_scope=same-application-shape warmup=%d iterations=%d payload_bytes=%d stream_window=1048576 connection_window=8388608 steady_state_mtu=1280 quic_version=1 cipher=negotiated-unexposed cert_verify=true compression=false netz_gso=false netz_gro=false quic_go_gso=implementation-default quic_go_gro=implementation-default pacing=implementation-specific\n", rolePair, config.warmup, config.iterations, config.payloadBytes)
}

func printBenchmarkResult(rolePair string, config benchmarkConfig, elapsed time.Duration, checksum uint64) {
	roundtripsPerSecond := float64(config.iterations) * 1e9 / float64(elapsed.Nanoseconds())
	logicalMiBPerSecond := roundtripsPerSecond * float64(config.payloadBytes) * 2 / (1024 * 1024)
	fmt.Printf("record=result implementation=quic-go protocol=websocket-h3 transport=h3 mode=binary-echo role_pair=%s endpoint_role=client connection_scope=persistent benchmark_scope=same-application-shape warmup=%d iterations=%d payload_bytes=%d elapsed_ns=%d ns_per_roundtrip=%.3f roundtrips_per_s=%.3f logical_MiB_s=%.3f sent_bytes=%d received_bytes=%d checksum=%d complete=true\n", rolePair, config.warmup, config.iterations, config.payloadBytes, elapsed.Nanoseconds(), float64(elapsed.Nanoseconds())/float64(config.iterations), roundtripsPerSecond, logicalMiBPerSecond, uint64(config.iterations)*uint64(config.payloadBytes), uint64(config.iterations)*uint64(config.payloadBytes), checksum)
}

func printBenchmarkServerComplete(implementation, rolePair string, config benchmarkConfig, checksum uint64) {
	bytes := uint64(config.iterations) * uint64(config.payloadBytes)
	fmt.Printf("record=server-complete implementation=%s protocol=websocket-h3 transport=h3 mode=binary-echo role_pair=%s endpoint_role=server connection_scope=persistent warmup=%d iterations=%d payload_bytes=%d sent_bytes=%d received_bytes=%d checksum=%d server_complete=true\n", implementation, rolePair, config.warmup, config.iterations, config.payloadBytes, bytes, bytes, checksum)
}

func printMemory(rolePair, endpointRole string, config benchmarkConfig, before, after memorySnapshot) {
	fmt.Printf("record=memory implementation=quic-go protocol=websocket-h3 transport=h3 mode=binary-echo role_pair=%s endpoint_role=%s connection_scope=persistent warmup=%d iterations=%d payload_bytes=%d memory_scope=benchmark-run-after-argument-parse allocator_scope=go-runtime-heap alloc_count=%d free_count=%d total_allocated_bytes=%d heap_alloc_bytes_end=%d heap_sys_bytes_end=%d runtime_sys_bytes_end=%d gc_cycles=%d complete=true\n", rolePair, endpointRole, config.warmup, config.iterations, config.payloadBytes, after.mallocs-before.mallocs, after.frees-before.frees, after.totalAlloc-before.totalAlloc, after.heapAlloc, after.heapSys, after.sys, after.numGC-before.numGC)
}

func validOpcode(opcode byte) bool {
	switch opcode {
	case opContinuation, opText, opBinary, opClose, opPing, opPong:
		return true
	default:
		return false
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := writer.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func compressMessage(payload []byte) ([]byte, error) {
	var output bytes.Buffer
	compressor, err := flate.NewWriter(&output, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := compressor.Write(payload); err != nil {
		return nil, err
	}
	if err := compressor.Flush(); err != nil {
		return nil, err
	}
	const tail = "\x00\x00\xff\xff"
	encoded := output.Bytes()
	if !bytes.HasSuffix(encoded, []byte(tail)) {
		return nil, errors.New("permessage-deflate sync-flush tail missing")
	}
	// Clone before Close appends a final DEFLATE block to the same buffer. Each
	// call owns a fresh compressor, implementing both no-context-takeover flags.
	wire := append([]byte(nil), encoded[:len(encoded)-len(tail)]...)
	if err := compressor.Close(); err != nil {
		return nil, err
	}
	return wire, nil
}

func decompressMessage(payload []byte) ([]byte, error) {
	// RFC 7692 removes the sync-flush marker. Restore it and a final empty
	// block so Go's raw DEFLATE reader can finish the standalone message.
	encoded := make([]byte, 0, len(payload)+9)
	encoded = append(encoded, payload...)
	encoded = append(encoded, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff)
	reader := flate.NewReader(bytes.NewReader(encoded))
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil {
		return nil, err
	}
	if len(decoded) > 4096 {
		return nil, errors.New("inflated WebSocket message too large")
	}
	return decoded, nil
}

func parseClose(value frame) (uint16, string, error) {
	if !value.fin || value.opcode != opClose || len(value.payload) < 2 {
		return 0, "", errors.New("invalid close frame")
	}
	return binary.BigEndian.Uint16(value.payload[:2]), string(value.payload[2:]), nil
}

func verifyVersion(actual quic.Version, v2Only bool) {
	expected := quic.Version1
	if v2Only {
		expected = quic.Version2
	}
	if actual != expected {
		log.Fatalf("negotiated QUIC version %#x, want v%d", actual, versionNumber(v2Only))
	}
}

func versionNumber(v2Only bool) int {
	if v2Only {
		return 2
	}
	return 1
}

func localhostCertificate() (tls.Certificate, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
