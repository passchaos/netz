// Command quic_handshake_bench is the quic-go half of the fresh-connection
// certificate-verified QUIC handshake latency benchmark.
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
	"math/big"
	"net"
	"os"
	"sort"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	handshakeALPN   = "netz-handshake-bench"
	markerLen       = 16
	benchmarkClose  = quic.ApplicationErrorCode(67)
	benchmarkReason = "handshake benchmark complete"
)

type handshakeConfig struct {
	rolePair   string
	warmup     int
	iterations int
	run        int
	timeout    time.Duration
}

func (c handshakeConfig) total() int { return c.warmup + c.iterations }

func (c handshakeConfig) validate() error {
	validPair := c.rolePair == "netz-client+quic-go-server" ||
		c.rolePair == "quic-go-client+quic-go-server" ||
		c.rolePair == "quic-go-client+netz-server" ||
		c.rolePair == "netz-client+netz-server"
	if !validPair || c.warmup < 0 || c.warmup > 4096 ||
		c.iterations < 1 || c.iterations > 4096 || c.run < 1 ||
		c.timeout <= 0 || c.timeout > 10*time.Minute {
		return errors.New("invalid handshake benchmark configuration")
	}
	return nil
}

func main() {
	role := flag.String("role", "server", "server or client")
	address := flag.String("addr", "127.0.0.1:0", "listen or peer address")
	caPath := flag.String("ca", "", "PEM trust anchor for client")
	caOut := flag.String("ca-out", "", "PEM trust anchor output for server")
	rolePair := flag.String("role-pair", "", "complete implementation role pair")
	warmup := flag.Int("warmup", 10, "untimed fresh connections")
	iterations := flag.Int("iterations", 100, "measured fresh connections")
	run := flag.Int("run", 1, "outer sample number")
	timeoutMS := flag.Int("timeout-ms", 10000, "per-connection timeout")
	flag.Parse()
	c := handshakeConfig{
		rolePair: *rolePair, warmup: *warmup, iterations: *iterations, run: *run,
		timeout: time.Duration(*timeoutMS) * time.Millisecond,
	}
	if err := c.validate(); err != nil {
		log.Fatal(err)
	}
	switch *role {
	case "server":
		runHandshakeServer(*address, *caOut, c)
	case "client":
		runHandshakeClient(*address, *caPath, c)
	default:
		log.Fatal("invalid role")
	}
}

func benchmarkQUICConfig(timeout time.Duration) *quic.Config {
	return &quic.Config{
		Versions:             []quic.Version{quic.Version1},
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
		InitialPacketSize:    1200,
	}
}

func runHandshakeServer(address, caOut string, c handshakeConfig) {
	if caOut == "" {
		log.Fatal("-ca-out is required")
	}
	certificate, certPEM, err := handshakeCertificate()
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
	transport := &quic.Transport{Conn: udp}
	defer transport.Close()
	listener, err := transport.Listen(
		&tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{handshakeALPN}, MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519},
			CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		},
		benchmarkQUICConfig(c.timeout),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("QUIC_GO_HANDSHAKE_BENCH_PORT=%d\n", udp.LocalAddr().(*net.UDPAddr).Port)
	checksum := uint64(0)
	for round := 0; round < c.total(); round++ {
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		conn, err := listener.Accept(ctx)
		cancel()
		if err != nil {
			log.Fatal(err)
		}
		if err := validateGoHandshake(conn, false); err != nil {
			log.Fatal(err)
		}
		if err := serveGoEchoAndClose(conn, round, c.timeout); err != nil {
			log.Fatal(err)
		}
		checksum += uint64(round)
	}
	fmt.Printf(
		"record=server-complete implementation=quic-go protocol=quic-v1 mode=handshake role_pair=%s run=%d warmup=%d iterations=%d connections=%d echo_bytes=%d checksum=%d echo_verified=true peer_close=true complete=true\n",
		c.rolePair, c.run, c.warmup, c.iterations, c.total(), c.total()*32, checksum,
	)
}

func runHandshakeClient(address, caPath string, c handshakeConfig) {
	if caPath == "" {
		log.Fatal("-ca is required")
	}
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
	latencies := make([]uint64, c.iterations)
	measured := 0
	checksum := uint64(0)
	for round := 0; round < c.total(); round++ {
		udp, err := net.ListenUDP("udp4", nil)
		if err != nil {
			log.Fatal(err)
		}
		transport := &quic.Transport{Conn: udp}
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		started := time.Now()
		conn, err := transport.Dial(ctx, peer, &tls.Config{
			RootCAs: roots, ServerName: "localhost",
			NextProtos: []string{handshakeALPN}, MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519},
			CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		}, benchmarkQUICConfig(c.timeout))
		elapsed := uint64(time.Since(started))
		cancel()
		if err != nil {
			transport.Close()
			log.Fatal(err)
		}
		if err := validateGoHandshake(conn, true); err != nil {
			transport.Close()
			log.Fatal(err)
		}
		if err := goClientEchoAndClose(conn, round, c.timeout); err != nil {
			transport.Close()
			log.Fatal(err)
		}
		if err := transport.Close(); err != nil {
			log.Fatal(err)
		}
		checksum += uint64(round)
		if round >= c.warmup {
			latencies[measured] = elapsed
			measured++
			fmt.Printf("record=handshake-sample implementation=quic-go protocol=quic-v1 mode=handshake role_pair=%s run=%d sample=%d elapsed_ns=%d verified=true\n", c.rolePair, c.run, measured, elapsed)
		}
	}
	printGoResult(c, latencies, checksum)
}

func validateGoHandshake(conn *quic.Conn, requirePeerCertificate bool) error {
	state := conn.ConnectionState()
	if state.Version != quic.Version1 || state.TLS.NegotiatedProtocol != handshakeALPN ||
		!state.TLS.HandshakeComplete || state.TLS.CipherSuite != tls.TLS_AES_128_GCM_SHA256 ||
		(requirePeerCertificate && len(state.TLS.PeerCertificates) == 0) {
		return errors.New("invalid authenticated QUIC handshake")
	}
	return nil
}

func marker(round int) [markerLen]byte {
	var value [markerLen]byte
	copy(value[:8], "NZQHSB1\x00")
	binary.BigEndian.PutUint64(value[8:], uint64(round))
	return value
}

func serveGoEchoAndClose(conn *quic.Conn, round int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	if stream.StreamID() != 0 {
		return errors.New("unexpected stream ID")
	}
	_ = stream.SetDeadline(time.Now().Add(timeout))
	expected := marker(round)
	received, err := io.ReadAll(stream)
	if err != nil || string(received) != string(expected[:]) {
		return errors.New("invalid handshake benchmark marker")
	}
	if _, err := stream.Write(expected[:]); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		cause := context.Cause(conn.Context())
		if !errors.As(cause, &appErr) || !appErr.Remote ||
			appErr.ErrorCode != benchmarkClose || appErr.ErrorMessage != benchmarkReason {
			return fmt.Errorf("unexpected peer close: %w", cause)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("timed out waiting for peer close")
	}
}

func goClientEchoAndClose(conn *quic.Conn, round int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if stream.StreamID() != 0 {
		return errors.New("unexpected stream ID")
	}
	_ = stream.SetDeadline(time.Now().Add(timeout))
	expected := marker(round)
	if _, err := stream.Write(expected[:]); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	received, err := io.ReadAll(stream)
	if err != nil || string(received) != string(expected[:]) {
		return errors.New("invalid handshake benchmark echo")
	}
	return conn.CloseWithError(benchmarkClose, benchmarkReason)
}

func printGoResult(c handshakeConfig, latencies []uint64, checksum uint64) {
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	total := uint64(0)
	for _, latency := range latencies {
		total += latency
	}
	fmt.Printf("record=result implementation=quic-go protocol=quic-v1 mode=handshake role_pair=%s run=%d timing_scope=client-connect-only verification=certificate key_exchange=x25519 cipher=aes-128-gcm-sha256 warmup=%d iterations=%d connections=%d echo_bytes=%d checksum=%d total_elapsed_ns=%d p50_ns=%d p99_ns=%d echo_verified=true complete=true\n", c.rolePair, c.run, c.warmup, c.iterations, c.total(), c.total()*32, checksum, total, percentile(latencies, 50), percentile(latencies, 99))
}

func percentile(sorted []uint64, percent int) uint64 {
	index := len(sorted) * percent / 100
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func handshakeCertificate() (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "netz interop test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
		IsCA: true, MaxPathLenZero: true,
	}
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
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
