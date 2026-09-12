package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	rawChurnALPN            = "netz-raw-stream-churn"
	rawChurnConfigLen       = 40
	rawChurnResultLen       = 48
	rawChurnPreludeLen      = 12
	rawChurnResetCodeBase   = uint64(0x4000)
	rawChurnKickLen         = mtu * 2
	rawChurnConfigAck       = "NZQCACK1"
	rawChurnReady           = "NZQCRDY1"
	rawChurnSiblingReady    = "NZQCSIB1"
	rawChurnResetSent       = "NZQCRST1"
	rawChurnResetsObserved  = "NZQCOBS1"
	rawChurnFinSent         = "NZQCFIN1"
	rawChurnResultAck       = "NZQCRAK1"
	rawChurnCloseReady      = "NZQCCLS1"
	rawChurnSiblingStart    = "raw-sibling-before-churn"
	rawChurnSiblingEnd      = "-after-churn"
	rawChurnSiblingResponse = "raw-sibling-survived"
)

var rawChurnKick = func() []byte {
	b := make([]byte, rawChurnKickLen)
	for i := range b {
		b[i] = 0xa7
	}
	return b
}()

type rawChurnConfig struct {
	sender          sender
	fault           string
	streams         uint16
	bytesPerStream  uint64
	resetAfterBytes uint32
	resetEvery      uint16
	timeout         time.Duration
	streamWindow    uint64
}

func (c rawChurnConfig) validate() error {
	if (c.sender != senderClient && c.sender != senderServer) ||
		(c.fault != "loss" && c.fault != "reorder") ||
		(c.streams != 32 && c.streams != 64) || c.bytesPerStream < uint64(c.resetAfterBytes) ||
		c.bytesPerStream > 1024*1024*1024 || c.resetAfterBytes == 0 ||
		c.resetEvery == 0 || c.resetEvery > c.streams || c.timeout <= 0 ||
		c.timeout > 10*time.Minute || c.streamWindow < c.bytesPerStream ||
		c.streamWindow > 1024*1024*1024 {
		return errors.New("invalid raw QUIC churn configuration")
	}
	return nil
}

func (c rawChurnConfig) encode() [rawChurnConfigLen]byte {
	var out [rawChurnConfigLen]byte
	copy(out[0:8], "NZQCHN1!")
	binary.BigEndian.PutUint16(out[8:10], c.streams)
	binary.BigEndian.PutUint16(out[10:12], c.resetEvery)
	binary.BigEndian.PutUint64(out[12:20], c.bytesPerStream)
	binary.BigEndian.PutUint32(out[20:24], c.resetAfterBytes)
	binary.BigEndian.PutUint32(out[24:28], uint32(c.timeout/time.Millisecond))
	out[28] = byte(c.sender)
	if c.fault == "loss" {
		out[29] = 1
	} else {
		out[29] = 2
	}
	binary.BigEndian.PutUint64(out[32:40], c.streamWindow)
	return out
}

func decodeRawChurnConfig(bytes *[rawChurnConfigLen]byte) (rawChurnConfig, error) {
	if string(bytes[0:8]) != "NZQCHN1!" || bytes[30] != 0 || bytes[31] != 0 {
		return rawChurnConfig{}, errors.New("invalid raw QUIC churn config")
	}
	fault := ""
	if bytes[29] == 1 {
		fault = "loss"
	} else if bytes[29] == 2 {
		fault = "reorder"
	}
	c := rawChurnConfig{
		sender: sender(bytes[28]), fault: fault, streams: binary.BigEndian.Uint16(bytes[8:10]),
		resetEvery: binary.BigEndian.Uint16(bytes[10:12]), bytesPerStream: binary.BigEndian.Uint64(bytes[12:20]),
		resetAfterBytes: binary.BigEndian.Uint32(bytes[20:24]), timeout: time.Duration(binary.BigEndian.Uint32(bytes[24:28])) * time.Millisecond,
		streamWindow: binary.BigEndian.Uint64(bytes[32:40]),
	}
	return c, c.validate()
}

func (c rawChurnConfig) quicConfig() *quic.Config {
	connectionWindow := c.streamWindow * (uint64(c.streams) + 4)
	return &quic.Config{
		Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: c.timeout, MaxIdleTimeout: c.timeout,
		InitialStreamReceiveWindow: c.streamWindow, MaxStreamReceiveWindow: c.streamWindow,
		InitialConnectionReceiveWindow: connectionWindow, MaxConnectionReceiveWindow: connectionWindow,
		MaxIncomingStreams: 4, MaxIncomingUniStreams: int64(c.streams) + 4,
		InitialPacketSize: mtu, DisablePathMTUDiscovery: true,
	}
}

type rawChurnResult struct {
	streams, fins, resets   uint16
	receivedBytes, checksum uint64
	resetMask, resetCodeSum uint64
}

func (r rawChurnResult) encode() [rawChurnResultLen]byte {
	var out [rawChurnResultLen]byte
	copy(out[0:8], "NZQCRSL1")
	binary.BigEndian.PutUint16(out[8:10], r.streams)
	binary.BigEndian.PutUint16(out[10:12], r.fins)
	binary.BigEndian.PutUint16(out[12:14], r.resets)
	binary.BigEndian.PutUint64(out[16:24], r.receivedBytes)
	binary.BigEndian.PutUint64(out[24:32], r.checksum)
	binary.BigEndian.PutUint64(out[32:40], r.resetMask)
	binary.BigEndian.PutUint64(out[40:48], r.resetCodeSum)
	return out
}

func decodeRawChurnResult(bytes *[rawChurnResultLen]byte) (rawChurnResult, error) {
	if string(bytes[0:8]) != "NZQCRSL1" || bytes[14] != 0 || bytes[15] != 0 {
		return rawChurnResult{}, errors.New("invalid raw QUIC churn result")
	}
	return rawChurnResult{
		streams: binary.BigEndian.Uint16(bytes[8:10]), fins: binary.BigEndian.Uint16(bytes[10:12]),
		resets: binary.BigEndian.Uint16(bytes[12:14]), receivedBytes: binary.BigEndian.Uint64(bytes[16:24]),
		checksum: binary.BigEndian.Uint64(bytes[24:32]), resetMask: binary.BigEndian.Uint64(bytes[32:40]),
		resetCodeSum: binary.BigEndian.Uint64(bytes[40:48]),
	}, nil
}

func rawChurnShouldReset(c rawChurnConfig, index int) bool {
	return (index+1)%int(c.resetEvery) == 0
}

func expectedRawChurnResult(c rawChurnConfig) rawChurnResult {
	r := rawChurnResult{streams: c.streams}
	for index := 0; index < int(c.streams); index++ {
		count := int(c.bytesPerStream)
		if rawChurnShouldReset(c, index) {
			count = int(c.resetAfterBytes)
			r.resets++
			r.resetMask |= 1 << index
			r.resetCodeSum += rawChurnResetCodeBase + uint64(index)
		} else {
			r.fins++
		}
		r.receivedBytes += uint64(count)
		for offset := 0; offset < count; offset++ {
			r.checksum += uint64(rawChurnPayloadByte(index, offset))
		}
	}
	return r
}

func rawChurnPayloadByte(index, offset int) byte {
	return byte(uint64(offset)*131 + uint64(index)*17)
}

func rawChurnPrelude(index int) [rawChurnPreludeLen]byte {
	var out [rawChurnPreludeLen]byte
	copy(out[0:8], "NZQCSTRM")
	binary.BigEndian.PutUint16(out[8:10], uint16(index))
	return out
}

func rawChurnStreamID(s sender, index int) uint64 {
	base := uint64(2)
	if s == senderServer {
		base = 3
	}
	return base + uint64(index)*4
}

type rawChurnSendState struct {
	stream *quic.SendStream
	index  int
}

func rawChurnPrepareSender(conn *quic.Conn, c rawChurnConfig, deadline time.Time) ([]rawChurnSendState, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	states := make([]rawChurnSendState, c.streams)
	prefix := make([]byte, c.resetAfterBytes)
	for index := range states {
		stream, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		if uint64(stream.StreamID()) != rawChurnStreamID(c.sender, index) {
			return nil, errors.New("unexpected raw churn stream ID")
		}
		_ = stream.SetWriteDeadline(deadline)
		prelude := rawChurnPrelude(index)
		if err := writeFull(stream, prelude[:]); err != nil {
			return nil, err
		}
		for offset := range prefix {
			prefix[offset] = rawChurnPayloadByte(index, offset)
		}
		if err := writeFull(stream, prefix); err != nil {
			return nil, err
		}
		states[index] = rawChurnSendState{stream: stream, index: index}
	}
	return states, nil
}

func rawChurnSendResets(states []rawChurnSendState, c rawChurnConfig) {
	for _, state := range states {
		if rawChurnShouldReset(c, state.index) {
			state.stream.CancelWrite(quic.StreamErrorCode(rawChurnResetCodeBase + uint64(state.index)))
		}
	}
}

func rawChurnSendFins(states []rawChurnSendState, c rawChurnConfig) error {
	chunk := make([]byte, min(int(c.bytesPerStream), mtu-128))
	for _, state := range states {
		if rawChurnShouldReset(c, state.index) {
			continue
		}
		for offset := int(c.resetAfterBytes); offset < int(c.bytesPerStream); {
			count := min(len(chunk), int(c.bytesPerStream)-offset)
			for index := 0; index < count; index++ {
				chunk[index] = rawChurnPayloadByte(state.index, offset+index)
			}
			if err := writeFull(state.stream, chunk[:count]); err != nil {
				return err
			}
			offset += count
		}
		if err := state.stream.Close(); err != nil {
			return err
		}
	}
	return nil
}

type rawChurnReceiveState struct {
	stream         *quic.ReceiveStream
	index          int
	prefixChecksum uint64
}

func rawChurnReceivePrefixes(conn *quic.Conn, c rawChurnConfig, deadline time.Time) ([]rawChurnReceiveState, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	states := make([]rawChurnReceiveState, c.streams)
	seen := make([]bool, c.streams)
	for count := 0; count < int(c.streams); count++ {
		stream, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return nil, err
		}
		_ = stream.SetReadDeadline(deadline)
		var prelude [rawChurnPreludeLen]byte
		if _, err := io.ReadFull(stream, prelude[:]); err != nil {
			return nil, err
		}
		if string(prelude[0:8]) != "NZQCSTRM" || prelude[10] != 0 || prelude[11] != 0 {
			return nil, errors.New("invalid raw churn prelude")
		}
		index := int(binary.BigEndian.Uint16(prelude[8:10]))
		if index >= int(c.streams) || seen[index] || uint64(stream.StreamID()) != rawChurnStreamID(c.sender, index) {
			return nil, errors.New("invalid raw churn stream identity")
		}
		seen[index] = true
		prefix := make([]byte, c.resetAfterBytes)
		if _, err := io.ReadFull(stream, prefix); err != nil {
			return nil, err
		}
		checksum, err := verifyRawChurnPayload(prefix, index, 0)
		if err != nil {
			return nil, err
		}
		states[index] = rawChurnReceiveState{stream: stream, index: index, prefixChecksum: checksum}
	}
	return states, nil
}

func rawChurnReceiveResets(states []rawChurnReceiveState, c rawChurnConfig, result *rawChurnResult) error {
	for _, state := range states {
		if !rawChurnShouldReset(c, state.index) {
			continue
		}
		var unexpected [1]byte
		n, err := state.stream.Read(unexpected[:])
		var streamErr *quic.StreamError
		if n != 0 || !errors.As(err, &streamErr) || !streamErr.Remote ||
			uint64(streamErr.StreamID) != rawChurnStreamID(c.sender, state.index) ||
			uint64(streamErr.ErrorCode) != rawChurnResetCodeBase+uint64(state.index) {
			return fmt.Errorf("invalid raw churn reset stream=%d n=%d err=%v", state.index, n, err)
		}
		result.resets++
		result.resetMask |= 1 << state.index
		result.resetCodeSum += rawChurnResetCodeBase + uint64(state.index)
	}
	return nil
}

func rawChurnReceiveFins(states []rawChurnReceiveState, c rawChurnConfig, result *rawChurnResult) error {
	buffer := make([]byte, mtu-128)
	for _, state := range states {
		if rawChurnShouldReset(c, state.index) {
			result.receivedBytes += uint64(c.resetAfterBytes)
			result.checksum += state.prefixChecksum
			continue
		}
		received := int(c.resetAfterBytes)
		checksum := state.prefixChecksum
		for {
			n, err := state.stream.Read(buffer)
			if n > 0 {
				if received+n > int(c.bytesPerStream) {
					return errors.New("raw churn payload too large")
				}
				value, verifyErr := verifyRawChurnPayload(buffer[:n], state.index, received)
				if verifyErr != nil {
					return verifyErr
				}
				checksum += value
				received += n
			}
			if errors.Is(err, io.EOF) {
				if received != int(c.bytesPerStream) {
					return errors.New("raw churn FIN ended early")
				}
				break
			}
			if err != nil {
				return err
			}
		}
		result.fins++
		result.receivedBytes += uint64(received)
		result.checksum += checksum
	}
	return nil
}

func verifyRawChurnPayload(bytes []byte, streamIndex, offset int) (uint64, error) {
	var checksum uint64
	for index, value := range bytes {
		if value != rawChurnPayloadByte(streamIndex, offset+index) {
			return 0, fmt.Errorf("raw churn payload mismatch stream=%d offset=%d", streamIndex, offset+index)
		}
		checksum += uint64(value)
	}
	return checksum, nil
}

type rawProxyStats struct {
	considered, dropped, held, reordered uint64
}

func (s rawProxyStats) minus(previous rawProxyStats) (rawProxyStats, error) {
	if s.considered < previous.considered || s.dropped < previous.dropped ||
		s.held < previous.held || s.reordered < previous.reordered {
		return rawProxyStats{}, errors.New("proxy counters regressed")
	}
	return rawProxyStats{s.considered - previous.considered, s.dropped - previous.dropped, s.held - previous.held, s.reordered - previous.reordered}, nil
}

func (s rawProxyStats) add(other rawProxyStats) rawProxyStats {
	return rawProxyStats{s.considered + other.considered, s.dropped + other.dropped, s.held + other.held, s.reordered + other.reordered}
}

type rawProxyControl struct {
	conn   net.Conn
	reader *bufio.Reader
}

func openRawProxyControl(port uint16, deadline time.Time) (*rawProxyControl, error) {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Until(deadline))
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	return &rawProxyControl{conn: conn, reader: bufio.NewReader(conn)}, nil
}

func (p *rawProxyControl) close() { _ = p.conn.Close() }

func (p *rawProxyControl) command(command, expected string) (rawProxyStats, error) {
	if _, err := io.WriteString(p.conn, command+"\n"); err != nil {
		return rawProxyStats{}, err
	}
	line, err := p.reader.ReadString('\n')
	if err != nil {
		return rawProxyStats{}, err
	}
	line = strings.TrimSuffix(line, "\n")
	if !strings.HasPrefix(line, expected) {
		return rawProxyStats{}, fmt.Errorf("invalid proxy response %q", line)
	}
	if expected == "armed" {
		return rawProxyStats{}, nil
	}
	var result rawProxyStats
	seen := uint8(0)
	for _, token := range strings.Fields(strings.TrimSpace(line[len(expected):])) {
		parts := strings.Split(token, "=")
		if len(parts) != 2 {
			return rawProxyStats{}, errors.New("invalid proxy counter")
		}
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return rawProxyStats{}, err
		}
		var bit uint8
		switch parts[0] {
		case "considered":
			bit, result.considered = 1, value
		case "dropped":
			bit, result.dropped = 2, value
		case "held":
			bit, result.held = 4, value
		case "reordered":
			bit, result.reordered = 8, value
		default:
			return rawProxyStats{}, errors.New("unknown proxy counter")
		}
		if seen&bit != 0 {
			return rawProxyStats{}, errors.New("duplicate proxy counter")
		}
		seen |= bit
	}
	if seen != 15 {
		return rawProxyStats{}, errors.New("missing proxy counter")
	}
	return result, nil
}

func validateRawChurnFaults(fault string, reset, fin rawProxyStats) error {
	if fault == "loss" {
		if reset.considered != 1 || fin.considered != 1 ||
			reset.dropped != 1 || fin.dropped != 1 || reset.held != 0 || fin.held != 0 ||
			reset.reordered != 0 || fin.reordered != 0 {
			return errors.New("loss did not affect both raw churn phases")
		}
	} else if reset.considered != 2 || fin.considered != 2 ||
		reset.held != 1 || fin.held != 1 || reset.reordered != 1 ||
		fin.reordered != 1 || reset.dropped != 0 || fin.dropped != 0 {
		return errors.New("reordering did not affect both raw churn phases")
	}
	return nil
}

func runRawChurnServer(address, caOut string, expected rawChurnConfig) {
	if caOut == "" {
		logFatalRawChurn(errors.New("-ca-out is required"))
	}
	cert, certPEM, err := localhostCertificate()
	if err != nil {
		logFatalRawChurn(err)
	}
	if err = os.WriteFile(caOut, certPEM, 0o600); err != nil {
		logFatalRawChurn(err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		logFatalRawChurn(err)
	}
	udp, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		logFatalRawChurn(err)
	}
	transport := &quic.Transport{Conn: udp}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{rawChurnALPN}, MinVersion: tls.VersionTLS13}, expected.quicConfig())
	if err != nil {
		logFatalRawChurn(err)
	}
	fmt.Printf("QUIC_GO_RAW_CHURN_ADDR=%s\n", udp.LocalAddr())
	ctx, cancel := context.WithTimeout(context.Background(), expected.timeout)
	conn, err := listener.Accept(ctx)
	cancel()
	if err != nil {
		logFatalRawChurn(err)
	}
	if err = runRawChurnServerConnection(conn, expected); err != nil {
		logFatalRawChurn(err)
	}
}

func runRawChurnClient(address, caPath string, proxyPort uint16, c rawChurnConfig) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		logFatalRawChurn(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		logFatalRawChurn(errors.New("parse CA bundle"))
	}
	peer, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		logFatalRawChurn(err)
	}
	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		logFatalRawChurn(err)
	}
	transport := &quic.Transport{Conn: udp}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	conn, err := transport.Dial(ctx, peer, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{rawChurnALPN}, MinVersion: tls.VersionTLS13}, c.quicConfig())
	cancel()
	if err != nil {
		logFatalRawChurn(err)
	}
	if err = runRawChurnClientConnection(conn, proxyPort, c); err != nil {
		logFatalRawChurn(err)
	}
}

func runRawChurnClientConnection(conn *quic.Conn, proxyPort uint16, c rawChurnConfig) error {
	deadline := time.Now().Add(c.timeout)
	proxy, err := openRawProxyControl(proxyPort, deadline)
	if err != nil {
		return err
	}
	defer proxy.close()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	_ = control.SetDeadline(deadline)
	if uint64(control.StreamID()) != 0 {
		return errors.New("unexpected churn control stream")
	}
	encodedConfig := c.encode()
	if err = writeFull(control, encodedConfig[:]); err != nil {
		return err
	}
	if err = readRawChurnMarker(control, rawChurnConfigAck); err != nil {
		return err
	}
	sibling, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	_ = sibling.SetDeadline(deadline)
	if uint64(sibling.StreamID()) != 4 {
		return errors.New("unexpected churn sibling stream")
	}
	if err = writeFull(sibling, []byte(rawChurnSiblingStart)); err != nil {
		return err
	}
	if err = readRawChurnMarker(control, rawChurnSiblingReady); err != nil {
		return err
	}
	var result rawChurnResult
	var resetFaults, finFaults rawProxyStats
	if c.sender == senderClient {
		result, resetFaults, finFaults, err = runRawChurnGoSender(conn, control, proxy, c, deadline)
	} else {
		result, resetFaults, finFaults, err = runRawChurnGoReceiver(conn, control, proxy, c, deadline)
	}
	if err != nil {
		return err
	}
	if err = writeFull(sibling, []byte(rawChurnSiblingEnd)); err != nil {
		return err
	}
	if err = sibling.Close(); err != nil {
		return err
	}
	response := make([]byte, len(rawChurnSiblingResponse))
	if _, err = io.ReadFull(sibling, response); err != nil {
		return err
	}
	if string(response) != rawChurnSiblingResponse {
		return errors.New("invalid churn sibling response")
	}
	if err = expectRawChurnEOF(sibling); err != nil {
		return err
	}
	if err = expectRawChurnEOF(control); err != nil {
		return err
	}
	if err = writeFull(control, []byte(rawChurnCloseReady)); err != nil {
		return err
	}
	if err = control.Close(); err != nil {
		return err
	}
	if err = waitForRawChurnClose(conn, c.timeout); err != nil {
		return err
	}
	stopped, err := proxy.command("stop", "stopped")
	if err != nil {
		return err
	}
	total := resetFaults.add(finFaults)
	if stopped != total {
		return errors.New("proxy counters changed after churn")
	}
	printRawChurnClientResult("quic-go", "quic-go-client+netz-server", c, result, total, resetFaults, finFaults, false)
	return nil
}

func runRawChurnServerConnection(conn *quic.Conn, expected rawChurnConfig) error {
	deadline := time.Now().Add(expected.timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	_ = control.SetDeadline(deadline)
	var configBytes [rawChurnConfigLen]byte
	if _, err = io.ReadFull(control, configBytes[:]); err != nil {
		return err
	}
	c, err := decodeRawChurnConfig(&configBytes)
	if err != nil || c != expected {
		return errors.New("raw churn config mismatch")
	}
	if err = writeFull(control, []byte(rawChurnConfigAck)); err != nil {
		return err
	}
	sibling, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	_ = sibling.SetDeadline(deadline)
	if uint64(sibling.StreamID()) != 4 {
		return errors.New("unexpected churn sibling stream")
	}
	start := make([]byte, len(rawChurnSiblingStart))
	if _, err = io.ReadFull(sibling, start); err != nil {
		return err
	}
	if string(start) != rawChurnSiblingStart {
		return errors.New("invalid churn sibling prefix")
	}
	if err = writeFull(control, []byte(rawChurnSiblingReady)); err != nil {
		return err
	}
	var result rawChurnResult
	if c.sender == senderServer {
		result, err = runRawChurnGoServerSender(conn, control, c, deadline)
	} else {
		result, err = runRawChurnGoServerReceiver(conn, control, c, deadline)
	}
	if err != nil {
		return err
	}
	end := make([]byte, len(rawChurnSiblingEnd))
	if _, err = io.ReadFull(sibling, end); err != nil {
		return err
	}
	if string(end) != rawChurnSiblingEnd {
		return errors.New("invalid churn sibling suffix")
	}
	if err = expectRawChurnEOF(sibling); err != nil {
		return err
	}
	if err = writeFull(sibling, []byte(rawChurnSiblingResponse)); err != nil {
		return err
	}
	if err = sibling.Close(); err != nil {
		return err
	}
	if err = control.Close(); err != nil {
		return err
	}
	if err = readRawChurnMarker(control, rawChurnCloseReady); err != nil {
		return err
	}
	if err = expectRawChurnEOF(control); err != nil {
		return err
	}
	if err = conn.CloseWithError(0, "churn complete"); err != nil {
		return err
	}
	printRawChurnServerResult("quic-go", "netz-client+quic-go-server", c, result, false)
	return nil
}

func runRawChurnGoSender(conn *quic.Conn, control *quic.Stream, proxy *rawProxyControl, c rawChurnConfig, deadline time.Time) (rawChurnResult, rawProxyStats, rawProxyStats, error) {
	states, err := rawChurnPrepareSender(conn, c, deadline)
	if err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = readRawChurnMarker(control, rawChurnReady); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if _, err = proxy.command("arm-once", "armed"); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	rawChurnSendResets(states, c)
	if err = writeFull(control, []byte(rawChurnResetSent)); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = writeFull(control, rawChurnKick); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = readRawChurnMarker(control, rawChurnResetsObserved); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	resetTotal, err := proxy.command("disarm", "disarmed")
	if err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if _, err = proxy.command("arm-once", "armed"); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = rawChurnSendFins(states, c); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = writeFull(control, []byte(rawChurnFinSent)); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = writeFull(control, rawChurnKick); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	var resultBytes [rawChurnResultLen]byte
	if _, err = io.ReadFull(control, resultBytes[:]); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	result, err := decodeRawChurnResult(&resultBytes)
	if err != nil || result != expectedRawChurnResult(c) {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, errors.New("raw churn result mismatch")
	}
	all, err := proxy.command("disarm", "disarmed")
	if err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	finFaults, err := all.minus(resetTotal)
	if err != nil || validateRawChurnFaults(c.fault, resetTotal, finFaults) != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, errors.New("raw churn fault counters invalid")
	}
	if err = writeFull(control, []byte(rawChurnResultAck)); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	return result, resetTotal, finFaults, nil
}

func runRawChurnGoReceiver(conn *quic.Conn, control *quic.Stream, proxy *rawProxyControl, c rawChurnConfig, deadline time.Time) (rawChurnResult, rawProxyStats, rawProxyStats, error) {
	states, err := rawChurnReceivePrefixes(conn, c, deadline)
	if err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if _, err = proxy.command("arm-once", "armed"); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = writeFull(control, []byte(rawChurnReady)); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	result := rawChurnResult{streams: c.streams}
	if err = rawChurnReceiveResets(states, c, &result); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = readRawChurnMarker(control, rawChurnResetSent); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = readRawChurnMarker(control, string(rawChurnKick)); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	resetTotal, err := proxy.command("disarm", "disarmed")
	if err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if _, err = proxy.command("arm-once", "armed"); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = writeFull(control, []byte(rawChurnResetsObserved)); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = rawChurnReceiveFins(states, c, &result); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = readRawChurnMarker(control, rawChurnFinSent); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = readRawChurnMarker(control, string(rawChurnKick)); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	all, err := proxy.command("disarm", "disarmed")
	if err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	finFaults, err := all.minus(resetTotal)
	if err != nil || validateRawChurnFaults(c.fault, resetTotal, finFaults) != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, errors.New("raw churn fault counters invalid")
	}
	if result != expectedRawChurnResult(c) {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, errors.New("raw churn receive result mismatch")
	}
	encoded := result.encode()
	if err = writeFull(control, encoded[:]); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	if err = readRawChurnMarker(control, rawChurnResultAck); err != nil {
		return rawChurnResult{}, rawProxyStats{}, rawProxyStats{}, err
	}
	return result, resetTotal, finFaults, nil
}

func runRawChurnGoServerSender(conn *quic.Conn, control *quic.Stream, c rawChurnConfig, deadline time.Time) (rawChurnResult, error) {
	states, err := rawChurnPrepareSender(conn, c, deadline)
	if err != nil {
		return rawChurnResult{}, err
	}
	if err = readRawChurnMarker(control, rawChurnReady); err != nil {
		return rawChurnResult{}, err
	}
	rawChurnSendResets(states, c)
	if err = writeFull(control, []byte(rawChurnResetSent)); err != nil {
		return rawChurnResult{}, err
	}
	if err = writeFull(control, rawChurnKick); err != nil {
		return rawChurnResult{}, err
	}
	if err = readRawChurnMarker(control, rawChurnResetsObserved); err != nil {
		return rawChurnResult{}, err
	}
	if err = rawChurnSendFins(states, c); err != nil {
		return rawChurnResult{}, err
	}
	if err = writeFull(control, []byte(rawChurnFinSent)); err != nil {
		return rawChurnResult{}, err
	}
	if err = writeFull(control, rawChurnKick); err != nil {
		return rawChurnResult{}, err
	}
	var resultBytes [rawChurnResultLen]byte
	if _, err = io.ReadFull(control, resultBytes[:]); err != nil {
		return rawChurnResult{}, err
	}
	result, err := decodeRawChurnResult(&resultBytes)
	if err != nil || result != expectedRawChurnResult(c) {
		return rawChurnResult{}, errors.New("raw churn result mismatch")
	}
	if err = writeFull(control, []byte(rawChurnResultAck)); err != nil {
		return rawChurnResult{}, err
	}
	return result, nil
}

func runRawChurnGoServerReceiver(conn *quic.Conn, control *quic.Stream, c rawChurnConfig, deadline time.Time) (rawChurnResult, error) {
	states, err := rawChurnReceivePrefixes(conn, c, deadline)
	if err != nil {
		return rawChurnResult{}, err
	}
	if err = writeFull(control, []byte(rawChurnReady)); err != nil {
		return rawChurnResult{}, err
	}
	result := rawChurnResult{streams: c.streams}
	if err = rawChurnReceiveResets(states, c, &result); err != nil {
		return rawChurnResult{}, err
	}
	if err = readRawChurnMarker(control, rawChurnResetSent); err != nil {
		return rawChurnResult{}, err
	}
	if err = readRawChurnMarker(control, string(rawChurnKick)); err != nil {
		return rawChurnResult{}, err
	}
	if err = writeFull(control, []byte(rawChurnResetsObserved)); err != nil {
		return rawChurnResult{}, err
	}
	if err = rawChurnReceiveFins(states, c, &result); err != nil {
		return rawChurnResult{}, err
	}
	if err = readRawChurnMarker(control, rawChurnFinSent); err != nil {
		return rawChurnResult{}, err
	}
	if err = readRawChurnMarker(control, string(rawChurnKick)); err != nil {
		return rawChurnResult{}, err
	}
	if result != expectedRawChurnResult(c) {
		return rawChurnResult{}, errors.New("raw churn receive result mismatch")
	}
	encoded := result.encode()
	if err = writeFull(control, encoded[:]); err != nil {
		return rawChurnResult{}, err
	}
	if err = readRawChurnMarker(control, rawChurnResultAck); err != nil {
		return rawChurnResult{}, err
	}
	return result, nil
}

func readRawChurnMarker(reader io.Reader, expected string) error {
	bytes := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return err
	}
	if string(bytes) != expected {
		return errors.New("invalid raw churn marker")
	}
	return nil
}

func expectRawChurnEOF(reader io.Reader) error {
	var extra [1]byte
	n, err := reader.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected raw churn FIN n=%d err=%v", n, err)
	}
	return nil
}

func waitForRawChurnClose(conn *quic.Conn, timeout time.Duration) error {
	select {
	case <-conn.Context().Done():
		cause := context.Cause(conn.Context())
		var appErr *quic.ApplicationError
		if !errors.As(cause, &appErr) || appErr.ErrorCode != 0 ||
			appErr.ErrorMessage != "churn complete" {
			return fmt.Errorf("unexpected raw churn peer close: %w", cause)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("timed out waiting for raw churn peer close")
	}
}

func printRawChurnClientResult(implementation, rolePair string, c rawChurnConfig, result rawChurnResult, total, reset, fin rawProxyStats, finalSize bool) {
	scope := "quic-go-client"
	if c.sender == senderServer {
		scope = "netz-server"
	}
	resetFaults, finFaults := reset.dropped, fin.dropped
	if c.fault == "reorder" {
		resetFaults, finFaults = reset.reordered, fin.reordered
	}
	fmt.Printf("raw QUIC churn client passed: implementation=%s role_pair=%s sender=%s fault=%s fault_scope=%s-outbound streams=%d fin=%d reset=%d bytes=%d checksum=%d reset_mask=0x%016x reset_code_sum=%d considered=%d dropped=%d held=%d reordered=%d reset_faults=%d fin_faults=%d reset_final_size_verified=%t sibling=true peer-close=true\n", implementation, rolePair, ifSender(c.sender, "client", "server"), c.fault, scope, result.streams, result.fins, result.resets, result.receivedBytes, result.checksum, result.resetMask, result.resetCodeSum, total.considered, total.dropped, total.held, total.reordered, resetFaults, finFaults, finalSize)
}

func printRawChurnServerResult(implementation, rolePair string, c rawChurnConfig, result rawChurnResult, finalSize bool) {
	scope := "netz-client"
	if c.sender == senderServer {
		scope = implementation + "-server"
	}
	fmt.Printf("raw QUIC churn server passed: implementation=%s role_pair=%s sender=%s fault=%s fault_scope=%s-outbound streams=%d fin=%d reset=%d bytes=%d checksum=%d reset_mask=0x%016x reset_code_sum=%d reset_final_size_verified=%t sibling=true\n", implementation, rolePair, ifSender(c.sender, "client", "server"), c.fault, scope, result.streams, result.fins, result.resets, result.receivedBytes, result.checksum, result.resetMask, result.resetCodeSum, finalSize)
}

func logFatalRawChurn(err error) {
	log.Fatal(err)
}
