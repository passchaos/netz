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
	"math/big"
	"net"
	"net/http"
	"os"
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

func main() {
	mode := flag.String("mode", "server", "server or client")
	address := flag.String("addr", "127.0.0.1:4433", "peer UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor for client mode")
	caOut := flag.String("ca-out", "", "PEM output path for server mode")
	v2Only := flag.Bool("v2-only", false, "use only QUIC v2")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*address, *caOut, *v2Only)
	case "client":
		runClient(*address, *caPath, *v2Only)
	default:
		log.Fatalf("unknown mode %q", *mode)
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
	result.payload = make([]byte, int(length))
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
	if !validOpcode(opcode) || len(payload) > maxFramePayload {
		return errors.New("invalid WebSocket frame")
	}
	if opcode >= opClose && (!options.fin || len(payload) > 125) {
		return errors.New("invalid control frame")
	}
	if options.rsv1 && (opcode == opContinuation || opcode >= opClose) {
		return errors.New("invalid compressed frame opcode")
	}
	header := []byte{opcode, 0}
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
		header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	default:
		header[1] |= 127
		header = binary.BigEndian.AppendUint64(header, uint64(len(payload)))
	}
	wirePayload := payload
	if options.masked {
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		header = append(header, mask[:]...)
		wirePayload = make([]byte, len(payload))
		for index, value := range payload {
			wirePayload[index] = value ^ mask[index%len(mask)]
		}
	}
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, wirePayload)
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
