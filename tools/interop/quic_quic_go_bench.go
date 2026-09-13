// Command quic_quic_go_bench provides the quic-go v0.59 half of netz's raw
// QUIC STREAM same-application-shape benchmark. It is built inside the audited
// local quicz fixture module.
package main

import (
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
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"
)

const (
	alpn       = "netz-raw-stream-bench"
	recordLen  = 64
	preludeLen = 16
	mtu        = 1280
)

type sender uint8

const (
	senderClient sender = 1
	senderServer sender = 2
)

type kind uint8

const (
	kindConfig    kind = 1
	kindConfigAck kind = 2
	kindReady     kind = 3
	kindDone      kind = 4
	kindDoneAck   kind = 5
	kindGo        kind = 6
)

type config struct {
	warmup         uint32
	iterations     uint32
	streams        uint16
	bytesPerStream uint64
	chunkBytes     uint32
	streamWindow   uint64
	timeout        time.Duration
}

type socketTraffic struct {
	sentDatagrams     uint64
	sentBytes         uint64
	receivedDatagrams uint64
	receivedBytes     uint64
}

type goMemorySnapshot struct {
	mallocs    uint64
	frees      uint64
	totalAlloc uint64
	heapAlloc  uint64
	heapSys    uint64
	sys        uint64
	numGC      uint32
}

func readGoMemory() goMemorySnapshot {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return goMemorySnapshot{
		mallocs: stats.Mallocs, frees: stats.Frees, totalAlloc: stats.TotalAlloc,
		heapAlloc: stats.HeapAlloc, heapSys: stats.HeapSys, sys: stats.Sys,
		numGC: stats.NumGC,
	}
}

func (current socketTraffic) since(previous socketTraffic) socketTraffic {
	return socketTraffic{
		sentDatagrams:     current.sentDatagrams - previous.sentDatagrams,
		sentBytes:         current.sentBytes - previous.sentBytes,
		receivedDatagrams: current.receivedDatagrams - previous.receivedDatagrams,
		receivedBytes:     current.receivedBytes - previous.receivedBytes,
	}
}

// countingUDPConn preserves quic-go's optimized OOB/ECN and recvmmsg paths
// while recording every UDP payload successfully handed to or received from
// the socket. ReadBatch must be explicit: quic-go otherwise constructs its own
// ipv4.PacketConn from SyscallConn and bypasses ReadFrom / ReadMsgUDP wrappers.
type countingUDPConn struct {
	*net.UDPConn
	batch             *ipv4.PacketConn
	sentDatagrams     atomic.Uint64
	sentBytes         atomic.Uint64
	receivedDatagrams atomic.Uint64
	receivedBytes     atomic.Uint64
}

func newCountingUDPConn(conn *net.UDPConn) *countingUDPConn {
	return &countingUDPConn{UDPConn: conn, batch: ipv4.NewPacketConn(conn)}
}

func (conn *countingUDPConn) stats() socketTraffic {
	return socketTraffic{
		sentDatagrams:     conn.sentDatagrams.Load(),
		sentBytes:         conn.sentBytes.Load(),
		receivedDatagrams: conn.receivedDatagrams.Load(),
		receivedBytes:     conn.receivedBytes.Load(),
	}
}

func (conn *countingUDPConn) recordSent(bytes int) {
	if bytes <= 0 {
		return
	}
	conn.sentDatagrams.Add(1)
	conn.sentBytes.Add(uint64(bytes))
}

func (conn *countingUDPConn) recordReceived(bytes int) {
	if bytes <= 0 {
		return
	}
	conn.receivedDatagrams.Add(1)
	conn.receivedBytes.Add(uint64(bytes))
}

func (conn *countingUDPConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, address, err := conn.UDPConn.ReadFrom(packet)
	conn.recordReceived(n)
	return n, address, err
}

func (conn *countingUDPConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	n, err := conn.UDPConn.WriteTo(packet, address)
	conn.recordSent(n)
	return n, err
}

func (conn *countingUDPConn) ReadMsgUDP(packet, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, address, err := conn.UDPConn.ReadMsgUDP(packet, oob)
	conn.recordReceived(n)
	return n, oobn, flags, address, err
}

func (conn *countingUDPConn) WriteMsgUDP(packet, oob []byte, address *net.UDPAddr) (int, int, error) {
	n, oobn, err := conn.UDPConn.WriteMsgUDP(packet, oob, address)
	conn.recordSent(n)
	return n, oobn, err
}

func (conn *countingUDPConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	n, err := conn.batch.ReadBatch(messages, flags)
	var bytes uint64
	for index := 0; index < n; index++ {
		bytes += uint64(messages[index].N)
	}
	if n > 0 {
		conn.receivedDatagrams.Add(uint64(n))
		conn.receivedBytes.Add(bytes)
	}
	return n, err
}

func (c config) rounds() uint32           { return c.warmup + c.iterations }
func (c config) totalBytes() uint64       { return c.bytesPerStream * uint64(c.streams) }
func (c config) connectionWindow() uint64 { return c.streamWindow * 8 }
func (c config) effectiveChunk() int      { return min(int(c.chunkBytes), mtu-128) }
func (c config) timeoutMS() uint32        { return uint32(c.timeout / time.Millisecond) }
func (c config) validate() error {
	if (c.streams != 1 && c.streams != 4) || c.iterations == 0 ||
		c.warmup > 4096 || c.iterations > 100000 || c.rounds() < c.warmup ||
		c.bytesPerStream == 0 || c.bytesPerStream > 1024*1024*1024 ||
		c.chunkBytes == 0 || uint64(c.chunkBytes) > c.bytesPerStream ||
		c.chunkBytes > 1024*1024 || c.streamWindow == 0 ||
		c.streamWindow > 1024*1024*1024 || c.connectionWindow()/8 != c.streamWindow ||
		c.timeout <= 0 || c.timeout > 10*time.Minute {
		return errors.New("invalid raw QUIC benchmark configuration")
	}
	return nil
}

func (c config) quicConfig() *quic.Config {
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1},
		HandshakeIdleTimeout:           c.timeout,
		MaxIdleTimeout:                 c.timeout,
		InitialStreamReceiveWindow:     c.streamWindow,
		MaxStreamReceiveWindow:         c.streamWindow,
		InitialConnectionReceiveWindow: c.connectionWindow(),
		MaxConnectionReceiveWindow:     c.connectionWindow(),
		MaxIncomingStreams:             4,
		MaxIncomingUniStreams:          int64(c.streams) + 4,
		InitialPacketSize:              mtu,
		DisablePathMTUDiscovery:        true,
	}
}

type record struct {
	kind          kind
	sender        sender
	round         uint32
	config        config
	receivedBytes uint64
	checksum      uint64
}

func (r record) encode() [recordLen]byte {
	var out [recordLen]byte
	copy(out[0:6], "NZQSB1")
	out[6] = byte(r.kind)
	out[7] = 1
	binary.BigEndian.PutUint32(out[8:12], r.round)
	binary.BigEndian.PutUint32(out[12:16], r.config.warmup)
	binary.BigEndian.PutUint32(out[16:20], r.config.iterations)
	binary.BigEndian.PutUint16(out[20:22], r.config.streams)
	out[22] = byte(r.sender)
	binary.BigEndian.PutUint64(out[24:32], r.config.bytesPerStream)
	binary.BigEndian.PutUint32(out[32:36], r.config.chunkBytes)
	binary.BigEndian.PutUint32(out[36:40], r.config.timeoutMS())
	binary.BigEndian.PutUint64(out[40:48], r.config.streamWindow)
	binary.BigEndian.PutUint64(out[48:56], r.receivedBytes)
	binary.BigEndian.PutUint64(out[56:64], r.checksum)
	return out
}

func decodeRecord(bytes *[recordLen]byte) (record, error) {
	if string(bytes[0:6]) != "NZQSB1" || bytes[7] != 1 || bytes[23] != 0 {
		return record{}, errors.New("invalid benchmark record")
	}
	c := config{
		warmup: binary.BigEndian.Uint32(bytes[12:16]), iterations: binary.BigEndian.Uint32(bytes[16:20]),
		streams: binary.BigEndian.Uint16(bytes[20:22]), bytesPerStream: binary.BigEndian.Uint64(bytes[24:32]),
		chunkBytes: binary.BigEndian.Uint32(bytes[32:36]), timeout: time.Duration(binary.BigEndian.Uint32(bytes[36:40])) * time.Millisecond,
		streamWindow: binary.BigEndian.Uint64(bytes[40:48]),
	}
	if err := c.validate(); err != nil {
		return record{}, err
	}
	r := record{
		kind: kind(bytes[6]), sender: sender(bytes[22]), round: binary.BigEndian.Uint32(bytes[8:12]), config: c,
		receivedBytes: binary.BigEndian.Uint64(bytes[48:56]), checksum: binary.BigEndian.Uint64(bytes[56:64]),
	}
	if r.kind < kindConfig || r.kind > kindGo || (r.sender != senderClient && r.sender != senderServer) {
		return record{}, errors.New("invalid benchmark record enum")
	}
	return r, nil
}

func main() {
	role := flag.String("role", "server", "server or client")
	address := flag.String("addr", "127.0.0.1:0", "listen or peer UDP address")
	ports := flag.String("ports", "", "comma-separated persistent benchmark ports")
	caPath := flag.String("ca", "", "PEM trust anchor for client mode")
	caOut := flag.String("ca-out", "", "PEM output path for server mode")
	mode := flag.String("mode", "throughput", "throughput, echo, or aggregate")
	rolePair := flag.String("role-pair", "", "persistent benchmark role pair")
	run := flag.Uint("run", 1, "outer benchmark run number")
	connections := flag.Uint("connections", 1, "parallel persistent connections")
	payloadBytes := flag.Uint("payload-bytes", 1024, "echo payload bytes")
	senderName := flag.String("sender", "client", "client or server")
	warmup := flag.Uint("warmup", 2, "warmup connection count")
	iterations := flag.Uint("iterations", 5, "measured connection count")
	streams := flag.Uint("streams", 1, "parallel unidirectional stream count")
	bytesPerStream := flag.Uint64("bytes-per-stream", 4*1024*1024, "payload bytes per stream")
	chunkBytes := flag.Uint("chunk-bytes", 16*1024, "requested application write chunk")
	streamWindow := flag.Uint64("stream-window", 1024*1024, "fixed stream receive window")
	timeoutMS := flag.Uint("timeout-ms", 30000, "per-sample timeout milliseconds")
	stats := flag.Bool("stats", false, "report Go runtime heap telemetry")
	churnFault := flag.String("churn", "", "raw QUIC churn fault: loss or reorder")
	proxyControlPort := flag.Uint("proxy-control-port", 0, "UDP fault proxy TCP control port")
	resetAfterBytes := flag.Uint("reset-after-bytes", 256, "churn payload prefix before reset")
	resetEvery := flag.Uint("reset-every", 2, "churn reset cadence")
	flag.Parse()
	if *warmup > math.MaxUint32 || *iterations > math.MaxUint32 || *streams > math.MaxUint16 ||
		*chunkBytes > math.MaxUint32 || *timeoutMS > math.MaxUint32 ||
		*proxyControlPort > math.MaxUint16 || *resetAfterBytes > math.MaxUint32 ||
		*resetEvery > math.MaxUint16 || *connections > math.MaxUint16 ||
		*payloadBytes > math.MaxUint32 || *run > math.MaxUint32 {
		log.Fatal("benchmark option exceeds wire type")
	}
	s := senderClient
	if *senderName == "server" {
		s = senderServer
	} else if *senderName != "client" {
		log.Fatal("invalid sender")
	}
	if *churnFault != "" {
		if *stats || *warmup != 2 || *iterations != 5 || *chunkBytes != 16*1024 {
			log.Fatal("churn does not accept benchmark-only options")
		}
		cc := rawChurnConfig{
			sender: s, fault: *churnFault, streams: uint16(*streams),
			bytesPerStream: *bytesPerStream, resetAfterBytes: uint32(*resetAfterBytes),
			resetEvery: uint16(*resetEvery), timeout: time.Duration(*timeoutMS) * time.Millisecond,
			streamWindow: *streamWindow,
		}
		if err := cc.validate(); err != nil {
			log.Fatal(err)
		}
		switch *role {
		case "server":
			if *proxyControlPort != 0 {
				log.Fatal("server churn does not accept -proxy-control-port")
			}
			runRawChurnServer(*address, *caOut, cc)
		case "client":
			if *proxyControlPort == 0 {
				log.Fatal("client churn requires -proxy-control-port")
			}
			runRawChurnClient(*address, *caPath, uint16(*proxyControlPort), cc)
		default:
			log.Fatal("invalid role")
		}
		return
	}
	if *mode != "throughput" {
		if *stats || *proxyControlPort != 0 {
			log.Fatal("persistent modes do not accept throughput-only options")
		}
		pc := persistentConfig{
			mode: *mode, rolePair: *rolePair, sender: s, run: uint32(*run),
			connections: uint16(*connections), warmup: uint32(*warmup),
			iterations: uint32(*iterations), streams: uint16(*streams),
			bytesPerStream: *bytesPerStream, payloadBytes: uint32(*payloadBytes),
			chunkBytes: uint32(*chunkBytes), streamWindow: *streamWindow,
			timeout: time.Duration(*timeoutMS) * time.Millisecond,
		}
		if err := pc.validate(); err != nil {
			log.Fatal(err)
		}
		switch *role {
		case "server":
			runPersistentServer(*address, *caOut, pc)
		case "client":
			runPersistentClient(*ports, *caPath, pc)
		default:
			log.Fatal("invalid role")
		}
		return
	}
	if *ports != "" || *rolePair != "" || *run != 1 || *connections != 1 || *payloadBytes != 1024 {
		log.Fatal("persistent options require -mode=echo or -mode=aggregate")
	}
	if *proxyControlPort != 0 {
		log.Fatal("-proxy-control-port requires -churn")
	}
	c := config{
		warmup: uint32(*warmup), iterations: uint32(*iterations), streams: uint16(*streams),
		bytesPerStream: *bytesPerStream, chunkBytes: uint32(*chunkBytes), streamWindow: *streamWindow,
		timeout: time.Duration(*timeoutMS) * time.Millisecond,
	}
	if err := c.validate(); err != nil {
		log.Fatal(err)
	}
	var memoryBefore goMemorySnapshot
	if *stats {
		memoryBefore = readGoMemory()
	}
	switch *role {
	case "server":
		runServer(*address, *caOut, c, s)
		if *stats {
			printGoMemory("netz-client+quic-go-server", "server", s, c, memoryBefore, readGoMemory())
		}
	case "client":
		runClient(*address, *caPath, c, s)
		if *stats {
			printGoMemory("quic-go-client+netz-server", "client", s, c, memoryBefore, readGoMemory())
		}
	default:
		log.Fatal("invalid role")
	}
}

func runServer(address, caOut string, c config, s sender) {
	if caOut == "" {
		log.Fatal("-ca-out is required")
	}
	cert, certPEM, err := localhostCertificate()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caOut, certPEM, 0o600); err != nil {
		log.Fatal(err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		log.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	counting := newCountingUDPConn(udp)
	transport := &quic.Transport{Conn: counting}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}, c.quicConfig())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("QUIC_GO_RAW_BENCH_ADDR=%s\n", address)
	printConfig(ifSender(s, "netz", "quic-go"), "netz-client+quic-go-server", c)
	for round := uint32(0); round < c.rounds(); round++ {
		trafficBefore := counting.stats()
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		conn, err := listener.Accept(ctx)
		cancel()
		if err != nil {
			log.Fatal(err)
		}
		if conn.ConnectionState().GSO {
			log.Fatal("quic-go GSO unexpectedly enabled")
		}
		if err := runServerRound(conn, c, s, round); err != nil {
			log.Fatal(err)
		}
		if round >= c.warmup {
			printSocketTraffic("quic-go", "netz-client+quic-go-server", "server", c, round-c.warmup+1, counting.stats().since(trafficBefore))
		}
	}
}

func runClient(address, caPath string, c config, s sender) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("parse CA bundle")
	}
	peer, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		log.Fatal(err)
	}
	printConfig(ifSender(s, "quic-go", "netz"), "quic-go-client+netz-server", c)
	for round := uint32(0); round < c.rounds(); round++ {
		udp, err := net.ListenUDP("udp4", nil)
		if err != nil {
			log.Fatal(err)
		}
		counting := newCountingUDPConn(udp)
		transport := &quic.Transport{Conn: counting}
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		conn, err := transport.Dial(ctx, peer, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}, c.quicConfig())
		cancel()
		if err != nil {
			transport.Close()
			log.Fatal(err)
		}
		if conn.ConnectionState().GSO {
			transport.Close()
			log.Fatal("quic-go GSO unexpectedly enabled")
		}
		result, err := runClientRound(conn, c, s, round)
		if err != nil {
			transport.Close()
			log.Fatal(err)
		}
		if s == senderClient && round >= c.warmup {
			printSample("quic-go", "quic-go-client+netz-server", c, round-c.warmup+1, result.elapsed, result.checksum)
		}
		if s == senderServer {
			if err := conn.CloseWithError(0, "benchmark complete"); err != nil {
				transport.Close()
				log.Fatal(err)
			}
		} else if err := waitForServerClose(conn, c.timeout); err != nil {
			transport.Close()
			log.Fatal(err)
		}
		if round >= c.warmup {
			printSocketTraffic("quic-go", "quic-go-client+netz-server", "client", c, round-c.warmup+1, counting.stats())
		}
		_ = transport.Close()
	}
}

type result struct {
	elapsed  time.Duration
	checksum uint64
}

func runClientRound(conn *quic.Conn, c config, s sender, round uint32) (result, error) {
	deadline := time.Now().Add(c.timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return result{}, err
	}
	if uint64(control.StreamID()) != 0 {
		return result{}, errors.New("unexpected control stream ID")
	}
	_ = control.SetDeadline(deadline)
	if err := writeRecord(control, record{kind: kindConfig, sender: s, round: round, config: c}, false); err != nil {
		return result{}, err
	}
	ack, err := readRecord(control, false)
	if err != nil {
		return result{}, err
	}
	if err := validateRecord(ack, kindConfigAck, s, round, c); err != nil {
		return result{}, err
	}
	if s == senderClient {
		return runSender(conn, control, c, s, round, deadline)
	}
	return runReceiver(conn, control, c, s, round, deadline)
}

func runServerRound(conn *quic.Conn, c config, s sender, round uint32) error {
	deadline := time.Now().Add(c.timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	_ = control.SetDeadline(deadline)
	request, err := readRecord(control, false)
	if err != nil {
		return err
	}
	if err := validateRecord(request, kindConfig, s, round, c); err != nil {
		return err
	}
	if err := writeRecord(control, record{kind: kindConfigAck, sender: s, round: round, config: c}, false); err != nil {
		return err
	}
	var r result
	if s == senderServer {
		r, err = runSender(conn, control, c, s, round, deadline)
	} else {
		r, err = runReceiver(conn, control, c, s, round, deadline)
	}
	if err != nil {
		return err
	}
	if s == senderServer && round >= c.warmup {
		printSample("quic-go", "netz-client+quic-go-server", c, round-c.warmup+1, r.elapsed, r.checksum)
	}
	if s == senderClient {
		return conn.CloseWithError(0, "benchmark complete")
	}
	return waitForServerClose(conn, c.timeout)
}

func waitForServerClose(conn *quic.Conn, timeout time.Duration) error {
	select {
	case <-conn.Context().Done():
		cause := context.Cause(conn.Context())
		var appErr *quic.ApplicationError
		if !errors.As(cause, &appErr) || appErr.ErrorCode != 0 ||
			appErr.ErrorMessage != "benchmark complete" {
			return fmt.Errorf("unexpected peer close: %w", cause)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("timed out waiting for server close")
	}
}

type sendState struct {
	stream  *quic.SendStream
	payload []byte
	err     error
}

func runSender(conn *quic.Conn, control *quic.Stream, c config, s sender, round uint32, deadline time.Time) (result, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	states := make([]sendState, c.streams)
	checksum := uint64(0)
	for index := range states {
		stream, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			return result{}, err
		}
		_ = stream.SetWriteDeadline(deadline)
		payload := make([]byte, c.bytesPerStream)
		checksum += fillPayload(payload, round, index)
		states[index] = sendState{stream: stream, payload: payload}
		prelude := makePrelude(round, uint16(index))
		if err := writeFull(stream, prelude[:]); err != nil {
			return result{}, err
		}
	}
	ready, err := readRecord(control, false)
	if err != nil {
		return result{}, err
	}
	if err := validateRecord(ready, kindReady, s, round, c); err != nil {
		return result{}, err
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for index := range states {
		wg.Add(1)
		go func(state *sendState) {
			defer wg.Done()
			<-start
			for offset := 0; offset < len(state.payload); {
				end := min(len(state.payload), offset+c.effectiveChunk())
				if err := writeFull(state.stream, state.payload[offset:end]); err != nil {
					state.err = err
					return
				}
				offset = end
			}
			state.err = state.stream.Close()
		}(&states[index])
	}
	started := time.Now()
	close(start)
	wg.Wait()
	for index := range states {
		if states[index].err != nil {
			return result{}, states[index].err
		}
	}
	done, err := readRecord(control, true)
	if err != nil {
		return result{}, err
	}
	if err := validateRecord(done, kindDone, s, round, c); err != nil {
		return result{}, err
	}
	if done.receivedBytes != c.totalBytes() || done.checksum != checksum {
		return result{}, errors.New("invalid DONE result")
	}
	elapsed := time.Since(started)
	if err := writeRecord(control, record{kind: kindDoneAck, sender: s, round: round, config: c, receivedBytes: done.receivedBytes, checksum: done.checksum}, true); err != nil {
		return result{}, err
	}
	return result{elapsed: elapsed, checksum: checksum}, nil
}

type receiveState struct {
	stream   *quic.ReceiveStream
	index    int
	buffer   []byte
	received uint64
	checksum uint64
	err      error
}

func runReceiver(conn *quic.Conn, control *quic.Stream, c config, s sender, round uint32, deadline time.Time) (result, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	states := make([]receiveState, c.streams)
	seen := make([]bool, c.streams)
	for count := 0; count < int(c.streams); count++ {
		stream, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return result{}, err
		}
		_ = stream.SetReadDeadline(deadline)
		var prelude [preludeLen]byte
		if _, err := io.ReadFull(stream, prelude[:]); err != nil {
			return result{}, err
		}
		index, err := decodePrelude(&prelude, round, c.streams)
		if err != nil || seen[index] {
			return result{}, errors.New("invalid data prelude")
		}
		expectedID := uint64(3 + index*4)
		if s == senderClient {
			expectedID = uint64(2 + index*4)
		}
		if uint64(stream.StreamID()) != expectedID {
			return result{}, errors.New("unexpected data stream ID")
		}
		seen[index] = true
		states[index] = receiveState{
			stream: stream, index: index, buffer: make([]byte, c.effectiveChunk()),
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for index := range states {
		wg.Add(1)
		go func(state *receiveState) {
			defer wg.Done()
			<-start
			for {
				n, err := state.stream.Read(state.buffer)
				if n > 0 {
					if state.received+uint64(n) > c.bytesPerStream {
						state.err = errors.New("payload too large")
						return
					}
					value, verifyErr := verifyPayload(state.buffer[:n], round, state.index, int(state.received))
					if verifyErr != nil {
						state.err = verifyErr
						return
					}
					state.checksum += value
					state.received += uint64(n)
				}
				if errors.Is(err, io.EOF) {
					if state.received != c.bytesPerStream {
						state.err = errors.New("early FIN")
					}
					return
				}
				if err != nil {
					state.err = err
					return
				}
			}
		}(&states[index])
	}
	if err := writeRecord(control, record{kind: kindReady, sender: s, round: round, config: c}, false); err != nil {
		return result{}, err
	}
	close(start)
	wg.Wait()
	total, checksum := uint64(0), uint64(0)
	for index := range states {
		if states[index].err != nil {
			return result{}, states[index].err
		}
		total += states[index].received
		checksum += states[index].checksum
	}
	done := record{kind: kindDone, sender: s, round: round, config: c, receivedBytes: total, checksum: checksum}
	if err := writeRecord(control, done, true); err != nil {
		return result{}, err
	}
	ack, err := readRecord(control, true)
	if err != nil {
		return result{}, err
	}
	if err := validateRecord(ack, kindDoneAck, s, round, c); err != nil {
		return result{}, err
	}
	if ack.receivedBytes != total || ack.checksum != checksum {
		return result{}, errors.New("invalid DONE_ACK result")
	}
	fmt.Printf("protocol=quic-stream receiver_complete=true round=%d received_bytes=%d checksum=%d\n", round, total, checksum)
	return result{checksum: checksum}, nil
}

func writeRecord(stream io.Writer, r record, fin bool) error {
	bytes := r.encode()
	if err := writeFull(stream, bytes[:]); err != nil {
		return err
	}
	if fin {
		if closer, ok := stream.(interface{ Close() error }); ok {
			return closer.Close()
		}
	}
	return nil
}

func readRecord(stream io.Reader, expectEOF bool) (record, error) {
	var bytes [recordLen]byte
	if _, err := io.ReadFull(stream, bytes[:]); err != nil {
		return record{}, err
	}
	if expectEOF {
		var extra [1]byte
		n, err := stream.Read(extra[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			return record{}, fmt.Errorf("expected control FIN n=%d err=%v", n, err)
		}
	}
	return decodeRecord(&bytes)
}

func validateRecord(r record, expectedKind kind, expectedSender sender, round uint32, c config) error {
	if r.kind != expectedKind || r.sender != expectedSender || r.round != round || r.config != c {
		return errors.New("benchmark control mismatch")
	}
	return nil
}

func makePrelude(round uint32, index uint16) [preludeLen]byte {
	var out [preludeLen]byte
	copy(out[:6], "NZQSD1")
	binary.BigEndian.PutUint32(out[6:10], round)
	binary.BigEndian.PutUint16(out[10:12], index)
	return out
}
func decodePrelude(bytes *[preludeLen]byte, round uint32, streams uint16) (int, error) {
	if string(bytes[:6]) != "NZQSD1" || binary.BigEndian.Uint32(bytes[6:10]) != round || binary.BigEndian.Uint32(bytes[12:16]) != 0 {
		return 0, errors.New("invalid prelude")
	}
	index := binary.BigEndian.Uint16(bytes[10:12])
	if index >= streams {
		return 0, errors.New("invalid prelude index")
	}
	return int(index), nil
}
func payloadByte(round uint32, streamIndex, offset int) byte {
	return byte(uint64(offset)*131 + uint64(streamIndex)*17 + uint64(round)*29)
}
func fillPayload(payload []byte, round uint32, streamIndex int) uint64 {
	var checksum uint64
	for i := range payload {
		payload[i] = payloadByte(round, streamIndex, i)
		checksum += uint64(payload[i])
	}
	return checksum
}
func verifyPayload(payload []byte, round uint32, streamIndex, offset int) (uint64, error) {
	var checksum uint64
	for i, value := range payload {
		if value != payloadByte(round, streamIndex, offset+i) {
			return 0, fmt.Errorf("payload mismatch stream=%d offset=%d", streamIndex, offset+i)
		}
		checksum += uint64(value)
	}
	return checksum, nil
}
func writeFull(writer io.Writer, bytes []byte) error {
	for len(bytes) > 0 {
		n, err := writer.Write(bytes)
		if n > 0 {
			bytes = bytes[n:]
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
func ifSender(s sender, whenClient, whenServer string) string {
	if s == senderClient {
		return whenClient
	}
	return whenServer
}
func printConfig(implementation, rolePair string, c config) {
	fmt.Printf("implementation=%s protocol=quic-stream direction=upload role_pair=%s connection_scope=fresh-per-sample benchmark_scope=same-application-shape warmup=%d iterations=%d streams=%d bytes_per_stream=%d application_chunk_requested=%d application_chunk_effective=%d stream_window=%d connection_window=%d steady_state_mtu=1280 quic_version=1 cipher=negotiated-unexposed cert_verify=true netz_gso=false netz_gro=false quic_go_gso=false quic_go_gro=false pacing=implementation-specific\n", implementation, rolePair, c.warmup, c.iterations, c.streams, c.bytesPerStream, c.chunkBytes, c.effectiveChunk(), c.streamWindow, c.connectionWindow())
}
func printSample(implementation, rolePair string, c config, sample uint32, elapsed time.Duration, checksum uint64) {
	mib := float64(c.totalBytes()) * 1e9 / float64(elapsed.Nanoseconds()) / (1024 * 1024)
	fmt.Printf("implementation=%s protocol=quic-stream direction=upload role_pair=%s connection_scope=fresh-per-sample benchmark_scope=same-application-shape sample=%d elapsed_ns=%d logical_MiB_s=%.3f streams=%d sent_bytes=%d received_bytes=%d checksum=%d complete=true\n", implementation, rolePair, sample, elapsed.Nanoseconds(), mib, c.streams, c.totalBytes(), c.totalBytes(), checksum)
}

func printSocketTraffic(implementation, rolePair, endpointRole string, c config, sample uint32, traffic socketTraffic) {
	fmt.Printf("implementation=%s protocol=quic-stream role_pair=%s endpoint_role=%s sample=%d streams=%d traffic_scope=connection socket_boundary=userspace-udp-payload udp_sent_datagrams=%d udp_sent_payload_bytes=%d udp_received_datagrams=%d udp_received_payload_bytes=%d logical_udp_segments=true complete=true\n", implementation, rolePair, endpointRole, sample, c.streams, traffic.sentDatagrams, traffic.sentBytes, traffic.receivedDatagrams, traffic.receivedBytes)
}

func printGoMemory(rolePair, endpointRole string, s sender, c config, before, after goMemorySnapshot) {
	fmt.Printf("implementation=quic-go protocol=quic-stream role_pair=%s endpoint_role=%s sender_role=%s streams=%d memory_scope=benchmark-run-after-argument-parse allocator_scope=go-runtime-heap alloc_count=%d free_count=%d total_allocated_bytes=%d heap_alloc_bytes_end=%d heap_sys_bytes_end=%d runtime_sys_bytes_end=%d gc_cycles=%d complete=true\n", rolePair, endpointRole, ifSender(s, "client", "server"), c.streams, after.mallocs-before.mallocs, after.frees-before.frees, after.totalAlloc-before.totalAlloc, after.heapAlloc, after.heapSys, after.sys, after.numGC-before.numGC)
}

const (
	persistentALPN        = "netz-raw-persistent-bench"
	persistentClose       = quic.ApplicationErrorCode(0)
	persistentCloseReason = "benchmark complete"
	persistentPrelude     = "NZQPE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

type persistentConfig struct {
	mode           string
	rolePair       string
	sender         sender
	run            uint32
	connections    uint16
	warmup         uint32
	iterations     uint32
	streams        uint16
	bytesPerStream uint64
	payloadBytes   uint32
	chunkBytes     uint32
	streamWindow   uint64
	timeout        time.Duration
}

func (c persistentConfig) validate() error {
	if !validPersistentRolePair(c.rolePair) || c.run == 0 ||
		c.connections == 0 || c.connections > 16 || c.warmup > 4096 ||
		c.iterations == 0 || c.iterations > 1000000 ||
		(c.streams != 1 && c.streams != 4) || c.bytesPerStream == 0 ||
		c.bytesPerStream > 1024*1024*1024 || c.payloadBytes == 0 ||
		c.payloadBytes > 4096 || c.chunkBytes == 0 ||
		uint64(c.chunkBytes) > c.bytesPerStream || c.streamWindow == 0 ||
		c.streamWindow > 1024*1024*1024 || c.timeout <= 0 ||
		c.timeout > 10*time.Minute {
		return errors.New("invalid persistent benchmark configuration")
	}
	if c.mode == "echo" {
		if c.connections != 1 || c.streams != 1 || c.sender != senderClient ||
			c.warmup+c.iterations < c.warmup {
			return errors.New("invalid persistent echo configuration")
		}
	} else if c.mode == "aggregate" {
		if c.warmup != 0 || c.iterations != 1 {
			return errors.New("aggregate uses one synchronized sample")
		}
	} else {
		return errors.New("invalid persistent benchmark mode")
	}
	return c.wire().validate()
}

func (c persistentConfig) wire() config {
	if c.mode == "echo" {
		return config{
			warmup: c.warmup, iterations: c.iterations, streams: 1,
			bytesPerStream: uint64(c.payloadBytes), chunkBytes: c.payloadBytes,
			streamWindow: c.streamWindow, timeout: c.timeout,
		}
	}
	return config{
		warmup: 0, iterations: 1, streams: c.streams,
		bytesPerStream: c.bytesPerStream, chunkBytes: c.chunkBytes,
		streamWindow: c.streamWindow, timeout: c.timeout,
	}
}

func (c persistentConfig) totalEchoRounds() uint32 { return c.warmup + c.iterations }
func (c persistentConfig) aggregateBytes() uint64 {
	return uint64(c.connections) * c.bytesPerStream * uint64(c.streams)
}

type persistentResult struct {
	bytes      uint64
	checksum   uint64
	finishedAt time.Time
	latencies  []uint64
}

type persistentServerEndpoint struct {
	udp       *net.UDPConn
	transport *quic.Transport
	listener  *quic.Listener
}

func runPersistentServer(address, caOut string, c persistentConfig) {
	if caOut == "" {
		log.Fatal("-ca-out is required")
	}
	certificate, certPEM, err := localhostCertificate()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caOut, certPEM, 0o600); err != nil {
		log.Fatal(err)
	}
	endpoints := make([]persistentServerEndpoint, c.connections)
	defer func() {
		for index := range endpoints {
			if endpoints[index].listener != nil {
				_ = endpoints[index].listener.Close()
			}
			if endpoints[index].transport != nil {
				_ = endpoints[index].transport.Close()
			}
		}
	}()
	ports := make([]string, c.connections)
	for index := range endpoints {
		udpAddr, err := net.ResolveUDPAddr("udp4", address)
		if err != nil {
			log.Fatal(err)
		}
		udp, err := net.ListenUDP("udp4", udpAddr)
		if err != nil {
			log.Fatal(err)
		}
		transport := &quic.Transport{Conn: udp}
		listener, err := transport.Listen(&tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{persistentALPN}, MinVersion: tls.VersionTLS13,
		}, c.wire().quicConfig())
		if err != nil {
			_ = transport.Close()
			log.Fatal(err)
		}
		endpoints[index] = persistentServerEndpoint{udp: udp, transport: transport, listener: listener}
		ports[index] = fmt.Sprint(udp.LocalAddr().(*net.UDPAddr).Port)
	}
	fmt.Printf("QUIC_GO_PERSISTENT_PORTS=%s\n", strings.Join(ports, ","))

	results := make(chan persistentResult, c.connections)
	errorsOut := make(chan error, c.connections)
	for index := range endpoints {
		go func(endpoint *persistentServerEndpoint, connectionIndex uint32) {
			result, err := runPersistentServerWorker(endpoint.listener, c, connectionIndex)
			results <- result
			errorsOut <- err
		}(&endpoints[index], uint32(index))
	}
	var bytes, checksum uint64
	for range endpoints {
		result := <-results
		bytes += result.bytes
		checksum += result.checksum
	}
	for range endpoints {
		if err := <-errorsOut; err != nil {
			log.Fatal(err)
		}
	}
	printPersistentServerComplete(c, bytes, checksum)
}

func runPersistentServerWorker(listener *quic.Listener, c persistentConfig, connectionIndex uint32) (persistentResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	conn, err := listener.Accept(ctx)
	cancel()
	if err != nil {
		return persistentResult{}, err
	}
	if err := validatePersistentHandshake(conn, false); err != nil {
		return persistentResult{}, err
	}
	if conn.ConnectionState().GSO {
		return persistentResult{}, errors.New("quic-go GSO unexpectedly enabled")
	}
	deadline := time.Now().Add(c.timeout)
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		return persistentResult{}, err
	}
	_ = control.SetDeadline(deadline)
	request, err := readRecord(control, false)
	if err != nil {
		return persistentResult{}, err
	}
	if err := validateRecord(request, kindConfig, c.sender, connectionIndex, c.wire()); err != nil {
		return persistentResult{}, err
	}
	if err := writeRecord(control, record{kind: kindConfigAck, sender: c.sender, round: connectionIndex, config: c.wire()}, false); err != nil {
		return persistentResult{}, err
	}
	var result persistentResult
	if c.mode == "echo" {
		result, err = goServerEcho(conn, control, c, deadline)
	} else {
		goRecord, readErr := readRecord(control, false)
		if readErr != nil {
			return persistentResult{}, readErr
		}
		if err := validateRecord(goRecord, kindGo, c.sender, connectionIndex, c.wire()); err != nil {
			return persistentResult{}, err
		}
		if c.sender == senderServer {
			base, runErr := runSender(conn, control, c.wire(), c.sender, connectionIndex, deadline)
			result = persistentResult{bytes: c.wire().totalBytes(), checksum: base.checksum}
			err = runErr
		} else {
			base, runErr := runReceiver(conn, control, c.wire(), c.sender, connectionIndex, deadline)
			result = persistentResult{bytes: c.wire().totalBytes(), checksum: base.checksum}
			err = runErr
		}
	}
	if err != nil {
		return persistentResult{}, err
	}
	if c.mode == "aggregate" && c.sender == senderClient {
		if err := conn.CloseWithError(persistentClose, persistentCloseReason); err != nil {
			return persistentResult{}, err
		}
	} else if c.mode == "aggregate" {
		if err := waitForPersistentClose(conn, c.timeout); err != nil {
			return persistentResult{}, err
		}
	}
	return result, nil
}

func runPersistentClient(portsText, caPath string, c persistentConfig) {
	ports, err := parsePersistentPorts(portsText, int(c.connections))
	if err != nil {
		log.Fatal(err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("parse CA bundle")
	}
	ready := make(chan error, c.connections)
	start := make(chan struct{})
	results := make(chan persistentResult, c.connections)
	errorsOut := make(chan error, c.connections)
	for index, port := range ports {
		go func(connectionIndex uint32, peer string) {
			result, err := runPersistentClientWorker(peer, roots, c, connectionIndex, ready, start)
			results <- persistentResult{bytes: result.bytes, checksum: result.checksum, finishedAt: result.finishedAt, latencies: result.latencies}
			errorsOut <- err
		}(uint32(index), "127.0.0.1:"+port)
	}
	for range ports {
		if err := <-ready; err != nil {
			close(start)
			log.Fatal(err)
		}
	}
	started := time.Now()
	close(start)
	var bytes, checksum uint64
	finished := started
	var latencies []uint64
	for range ports {
		result := <-results
		bytes += result.bytes
		checksum += result.checksum
		if result.finishedAt.After(finished) {
			finished = result.finishedAt
		}
		if result.latencies != nil {
			latencies = result.latencies
		}
	}
	for range ports {
		if err := <-errorsOut; err != nil {
			log.Fatal(err)
		}
	}
	printPersistentClientResult(c, latencies, uint64(finished.Sub(started)), bytes, checksum)
}

func runPersistentClientWorker(peer string, roots *x509.CertPool, c persistentConfig, connectionIndex uint32, ready chan<- error, start <-chan struct{}) (workerResult persistentResult, err error) {
	readySent := false
	defer func() {
		if err != nil && !readySent {
			ready <- err
		}
	}()
	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return persistentResult{}, err
	}
	transport := &quic.Transport{Conn: udp}
	defer transport.Close()
	peerAddress, err := net.ResolveUDPAddr("udp4", peer)
	if err != nil {
		return persistentResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	conn, err := transport.Dial(ctx, peerAddress, &tls.Config{
		RootCAs: roots, ServerName: "localhost",
		NextProtos: []string{persistentALPN}, MinVersion: tls.VersionTLS13,
	}, c.wire().quicConfig())
	cancel()
	if err != nil {
		return persistentResult{}, err
	}
	if err := validatePersistentHandshake(conn, true); err != nil {
		return persistentResult{}, err
	}
	if conn.ConnectionState().GSO {
		return persistentResult{}, errors.New("quic-go GSO unexpectedly enabled")
	}
	deadline := time.Now().Add(c.timeout)
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return persistentResult{}, err
	}
	_ = control.SetDeadline(deadline)
	if err := writeRecord(control, record{kind: kindConfig, sender: c.sender, round: connectionIndex, config: c.wire()}, false); err != nil {
		return persistentResult{}, err
	}
	ack, err := readRecord(control, false)
	if err != nil {
		return persistentResult{}, err
	}
	if err := validateRecord(ack, kindConfigAck, c.sender, connectionIndex, c.wire()); err != nil {
		return persistentResult{}, err
	}
	if c.mode == "echo" {
		return goClientEcho(conn, control, c, ready, &readySent, start, deadline)
	}
	readySent = true
	ready <- nil
	<-start
	if err := writeRecord(control, record{kind: kindGo, sender: c.sender, round: connectionIndex, config: c.wire()}, false); err != nil {
		return persistentResult{}, err
	}
	var base result
	if c.sender == senderClient {
		base, err = runSender(conn, control, c.wire(), c.sender, connectionIndex, deadline)
	} else {
		base, err = runReceiver(conn, control, c.wire(), c.sender, connectionIndex, deadline)
	}
	if err != nil {
		return persistentResult{}, err
	}
	finishedAt := time.Now()
	if c.sender == senderServer {
		if err := conn.CloseWithError(persistentClose, persistentCloseReason); err != nil {
			return persistentResult{}, err
		}
	} else if err := waitForPersistentClose(conn, c.timeout); err != nil {
		return persistentResult{}, err
	}
	return persistentResult{
		bytes: c.wire().totalBytes(), checksum: base.checksum, finishedAt: finishedAt,
	}, nil
}

func goClientEcho(conn *quic.Conn, control *quic.Stream, c persistentConfig, ready chan<- error, readySent *bool, start <-chan struct{}, deadline time.Time) (persistentResult, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return persistentResult{}, err
	}
	if uint64(stream.StreamID()) != 4 {
		return persistentResult{}, errors.New("unexpected echo stream ID")
	}
	_ = stream.SetDeadline(deadline)
	if err := writeFull(stream, []byte(persistentPrelude)); err != nil {
		return persistentResult{}, err
	}
	readyRecord, err := readRecord(control, false)
	if err != nil {
		return persistentResult{}, err
	}
	if err := validateRecord(readyRecord, kindReady, senderClient, 0, c.wire()); err != nil {
		return persistentResult{}, err
	}
	payload := make([]byte, c.payloadBytes)
	echoed := make([]byte, c.payloadBytes)
	latencies := make([]uint64, c.iterations)
	var checksum uint64
	for sequence := uint32(0); sequence < c.warmup; sequence++ {
		checksum += fillPersistentEchoPayload(payload, sequence)
		if err := goEchoOnce(stream, payload, echoed, false); err != nil {
			return persistentResult{}, err
		}
	}
	*readySent = true
	ready <- nil
	<-start
	for index := range latencies {
		sequence := c.warmup + uint32(index)
		checksum += fillPersistentEchoPayload(payload, sequence)
		started := time.Now()
		if err := goEchoOnce(stream, payload, echoed, index+1 == len(latencies)); err != nil {
			return persistentResult{}, err
		}
		latencies[index] = uint64(time.Since(started))
	}
	totalBytes := uint64(c.totalEchoRounds()) * uint64(c.payloadBytes)
	if err := writeRecord(control, record{kind: kindDone, sender: senderClient, round: 0, config: c.wire(), receivedBytes: totalBytes, checksum: checksum}, true); err != nil {
		return persistentResult{}, err
	}
	doneAck, err := readRecord(control, true)
	if err != nil {
		return persistentResult{}, err
	}
	if err := validateRecord(doneAck, kindDoneAck, senderClient, 0, c.wire()); err != nil || doneAck.receivedBytes != totalBytes || doneAck.checksum != checksum {
		return persistentResult{}, errors.New("invalid persistent echo completion")
	}
	return persistentResult{bytes: totalBytes, checksum: checksum, finishedAt: time.Now(), latencies: latencies}, nil
}

func goServerEcho(conn *quic.Conn, control *quic.Stream, c persistentConfig, deadline time.Time) (persistentResult, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return persistentResult{}, err
	}
	if uint64(stream.StreamID()) != 4 {
		return persistentResult{}, errors.New("unexpected echo stream ID")
	}
	_ = stream.SetDeadline(deadline)
	prelude := make([]byte, len(persistentPrelude))
	if _, err := io.ReadFull(stream, prelude); err != nil || string(prelude) != persistentPrelude {
		return persistentResult{}, errors.New("invalid persistent echo prelude")
	}
	if err := writeRecord(control, record{kind: kindReady, sender: senderClient, round: 0, config: c.wire()}, false); err != nil {
		return persistentResult{}, err
	}
	payload := make([]byte, c.payloadBytes)
	expected := make([]byte, c.payloadBytes)
	var checksum uint64
	for sequence := uint32(0); sequence < c.totalEchoRounds(); sequence++ {
		if _, err := io.ReadFull(stream, payload); err != nil {
			return persistentResult{}, err
		}
		checksum += fillPersistentEchoPayload(expected, sequence)
		if string(payload) != string(expected) {
			return persistentResult{}, errors.New("invalid persistent echo payload")
		}
		if sequence+1 == c.totalEchoRounds() {
			if err := requireEOF(stream); err != nil {
				return persistentResult{}, err
			}
		}
		if err := writeFull(stream, payload); err != nil {
			return persistentResult{}, err
		}
	}
	if err := stream.Close(); err != nil {
		return persistentResult{}, err
	}
	done, err := readRecord(control, true)
	if err != nil {
		return persistentResult{}, err
	}
	totalBytes := uint64(c.totalEchoRounds()) * uint64(c.payloadBytes)
	if err := validateRecord(done, kindDone, senderClient, 0, c.wire()); err != nil || done.receivedBytes != totalBytes || done.checksum != checksum {
		return persistentResult{}, errors.New("invalid persistent echo DONE")
	}
	if err := writeRecord(control, record{kind: kindDoneAck, sender: senderClient, round: 0, config: c.wire(), receivedBytes: totalBytes, checksum: checksum}, true); err != nil {
		return persistentResult{}, err
	}
	return persistentResult{bytes: totalBytes, checksum: checksum}, nil
}

func goEchoOnce(stream *quic.Stream, payload, echoed []byte, fin bool) error {
	if err := writeFull(stream, payload); err != nil {
		return err
	}
	if fin {
		if err := stream.Close(); err != nil {
			return err
		}
	}
	if _, err := io.ReadFull(stream, echoed); err != nil {
		return err
	}
	if string(payload) != string(echoed) {
		return errors.New("persistent echo mismatch")
	}
	if fin {
		return requireEOF(stream)
	}
	return nil
}

func requireEOF(reader io.Reader) error {
	var extra [1]byte
	n, err := reader.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected FIN n=%d err=%v", n, err)
	}
	return nil
}

func fillPersistentEchoPayload(payload []byte, sequence uint32) uint64 {
	var checksum uint64
	for index := range payload {
		payload[index] = byte(uint64(sequence)*17 + uint64(index)*131)
		checksum += uint64(payload[index])
	}
	return checksum
}

func waitForPersistentClose(conn *quic.Conn, timeout time.Duration) error {
	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		cause := context.Cause(conn.Context())
		if !errors.As(cause, &appErr) || !appErr.Remote ||
			appErr.ErrorCode != persistentClose || appErr.ErrorMessage != persistentCloseReason {
			return fmt.Errorf("unexpected persistent peer close: %w", cause)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("timed out waiting for persistent peer close")
	}
}

func validatePersistentHandshake(conn *quic.Conn, requirePeerCertificate bool) error {
	state := conn.ConnectionState()
	if state.Version != quic.Version1 || state.TLS.NegotiatedProtocol != persistentALPN ||
		!state.TLS.HandshakeComplete || (requirePeerCertificate && len(state.TLS.PeerCertificates) == 0) {
		return errors.New("invalid persistent benchmark handshake")
	}
	return nil
}

func parsePersistentPorts(text string, expected int) ([]string, error) {
	ports := strings.Split(text, ",")
	if len(ports) != expected {
		return nil, errors.New("persistent port count mismatch")
	}
	for _, port := range ports {
		if port == "" {
			return nil, errors.New("empty persistent port")
		}
	}
	return ports, nil
}

func validPersistentRolePair(value string) bool {
	return value == "netz-client+quic-go-server" ||
		value == "quic-go-client+quic-go-server" ||
		value == "quic-go-client+netz-server" ||
		value == "netz-client+netz-server"
}

func persistentClientImplementation(rolePair string) string {
	if strings.HasPrefix(rolePair, "netz-client") {
		return "netz"
	}
	return "quic-go"
}

func persistentServerImplementation(rolePair string) string {
	if strings.HasSuffix(rolePair, "netz-server") {
		return "netz"
	}
	return "quic-go"
}

func persistentPercentile(sorted []uint64, numerator, denominator int) uint64 {
	index := len(sorted) * numerator / denominator
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func printPersistentClientResult(c persistentConfig, latencies []uint64, elapsedNS, bytes, checksum uint64) {
	implementation := persistentClientImplementation(c.rolePair)
	if c.mode == "echo" {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		var totalNS uint64
		for _, latency := range latencies {
			totalNS += latency
		}
		fmt.Printf("record=result implementation=%s protocol=quic-stream mode=echo direction=roundtrip role_pair=%s result_owner=client run=%d connection_scope=persistent endpoint_topology=independent-udp benchmark_scope=same-application-shape warmup=%d iterations=%d connections=1 streams=1 payload_bytes=%d measured_bytes=%d total_bytes=%d checksum=%d total_elapsed_ns=%d mean_ns=%d min_ns=%d p50_ns=%d p90_ns=%d p99_ns=%d p999_ns=%d max_ns=%d cert_verify=true quic_version=1 gso=false gro=false sender_role=client completion_exchange_verified=true complete=true\n", implementation, c.rolePair, c.run, c.warmup, c.iterations, c.payloadBytes, uint64(c.iterations)*uint64(c.payloadBytes), bytes, checksum, totalNS, totalNS/uint64(c.iterations), latencies[0], persistentPercentile(latencies, 50, 100), persistentPercentile(latencies, 90, 100), persistentPercentile(latencies, 99, 100), persistentPercentile(latencies, 999, 1000), latencies[len(latencies)-1])
		return
	}
	if c.sender == senderServer {
		implementation = persistentServerImplementation(c.rolePair)
	}
	mib := float64(bytes) * 1e9 / float64(elapsedNS) / (1024 * 1024)
	fmt.Printf("record=result implementation=%s protocol=quic-stream mode=aggregate direction=%s role_pair=%s result_owner=client run=%d connection_scope=parallel-independent-endpoints endpoint_topology=one-udp-socket-per-connection benchmark_scope=same-application-shape timing_scope=stream-setup-through-verified-completion connections=%d streams=%d bytes_per_stream=%d transferred_bytes=%d checksum=%d elapsed_ns=%d logical_MiB_s=%.3f sender_role=%s cert_verify=true quic_version=1 gso=false gro=false completion_exchange_verified=true complete=true\n", implementation, ifSender(c.sender, "upload", "download"), c.rolePair, c.run, c.connections, c.streams, c.bytesPerStream, bytes, checksum, elapsedNS, mib, ifSender(c.sender, "client", "server"))
}

func printPersistentServerComplete(c persistentConfig, bytes, checksum uint64) {
	if c.mode == "echo" {
		fmt.Printf("record=server-complete implementation=%s protocol=quic-stream mode=echo direction=roundtrip role_pair=%s endpoint_role=server run=%d connection_scope=persistent endpoint_topology=independent-udp benchmark_scope=same-application-shape warmup=%d iterations=%d connections=1 streams=1 payload_bytes=%d total_bytes=%d checksum=%d sender_role=client connections_complete=1 cert_verify=true quic_version=1 gso=false gro=false completion_exchange_verified=true complete=true\n", persistentServerImplementation(c.rolePair), c.rolePair, c.run, c.warmup, c.iterations, c.payloadBytes, bytes, checksum)
		return
	}
	fmt.Printf("record=server-complete implementation=%s protocol=quic-stream mode=aggregate direction=%s role_pair=%s endpoint_role=server run=%d connection_scope=parallel-independent-endpoints endpoint_topology=one-udp-socket-per-connection benchmark_scope=same-application-shape warmup=0 iterations=1 connections=%d streams=%d bytes_per_stream=%d payload_bytes=%d transferred_bytes=%d checksum=%d sender_role=%s connections_complete=%d cert_verify=true quic_version=1 gso=false gro=false completion_exchange_verified=true complete=true\n", persistentServerImplementation(c.rolePair), ifSender(c.sender, "upload", "download"), c.rolePair, c.run, c.connections, c.streams, c.bytesPerStream, c.payloadBytes, bytes, checksum, ifSender(c.sender, "client", "server"), c.connections)
}

func localhostCertificate() (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "netz interop test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafTemplate := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, DNSNames: []string{"localhost"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
