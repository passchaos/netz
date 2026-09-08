// Command http3_quic_go_bench provides the quic-go half of the netz HTTP/3
// same-application-shape benchmark. The runner builds it inside the audited
// quic-go module pinned by the local quicz fixture.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const mtu = 1280

type benchConfig struct {
	mode         string
	warmup       uint
	iterations   uint
	bodyBytes    uint64
	chunkBytes   uint64
	streamWindow uint64
	timeout      time.Duration
}

func main() {
	role := flag.String("role", "server", "server or client")
	address := flag.String("addr", "127.0.0.1:0", "listen or peer UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor for client mode")
	caOut := flag.String("ca-out", "", "PEM output path for server mode")
	mode := flag.String("bench-mode", "upload", "upload or download")
	warmup := flag.Uint("warmup", 10, "warmup request count")
	iterations := flag.Uint("iterations", 5, "measured request count")
	bodyBytes := flag.Uint64("body-bytes", 4*1024*1024, "logical body bytes per request")
	chunkBytes := flag.Uint64("chunk-bytes", 16*1024, "application read/write chunk bytes")
	streamWindow := flag.Uint64("stream-window", 1024*1024, "fixed QUIC stream receive window")
	timeoutMS := flag.Uint("timeout-ms", 30000, "per-operation timeout milliseconds")
	flag.Parse()
	config := benchConfig{
		mode: *mode, warmup: *warmup, iterations: *iterations,
		bodyBytes: *bodyBytes, chunkBytes: *chunkBytes,
		streamWindow: *streamWindow, timeout: time.Duration(*timeoutMS) * time.Millisecond,
	}
	if err := config.validate(); err != nil {
		log.Fatal(err)
	}
	switch *role {
	case "server":
		runServer(*address, *caOut, config)
	case "client":
		runClient(*address, *caPath, config)
	default:
		log.Fatalf("unknown role %q", *role)
	}
}

func (config benchConfig) validate() error {
	if config.mode != "upload" && config.mode != "download" {
		return fmt.Errorf("invalid benchmark mode %q", config.mode)
	}
	if config.warmup == 0 || config.iterations == 0 || config.bodyBytes == 0 ||
		config.chunkBytes == 0 || config.chunkBytes > config.bodyBytes ||
		config.streamWindow == 0 || config.timeout <= 0 {
		return errors.New("benchmark values must be positive and chunk <= body")
	}
	if uint64(config.warmup)+uint64(config.iterations) > 4096 {
		return errors.New("benchmark request count exceeds 4096")
	}
	if config.bodyBytes > 1024*1024*1024 || config.chunkBytes > 1024*1024 ||
		config.streamWindow > 1024*1024*1024 || config.timeout > 10*time.Minute {
		return errors.New("benchmark value exceeds supported bound")
	}
	return nil
}

func (config benchConfig) rounds() uint             { return config.warmup + config.iterations }
func (config benchConfig) connectionWindow() uint64 { return config.streamWindow * 8 }
func (config benchConfig) effectiveChunk() uint64   { return min(config.chunkBytes, mtu-128) }

func (config benchConfig) quicConfig() *quic.Config {
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1},
		HandshakeIdleTimeout:           config.timeout,
		MaxIdleTimeout:                 config.timeout,
		InitialStreamReceiveWindow:     config.streamWindow,
		MaxStreamReceiveWindow:         config.streamWindow,
		InitialConnectionReceiveWindow: config.connectionWindow(),
		MaxConnectionReceiveWindow:     config.connectionWindow(),
		MaxIncomingStreams:             int64(config.rounds()) + 8,
		MaxIncomingUniStreams:          16,
		InitialPacketSize:              mtu,
		DisablePathMTUDiscovery:        true,
	}
}

func runServer(address, caOut string, config benchConfig) {
	if caOut == "" {
		log.Fatal("-ca-out is required in server mode")
	}
	certificate, certificatePEM, err := localhostCertificate()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caOut, certificatePEM, 0o600); err != nil {
		log.Fatal(err)
	}
	payload, checksum := makePayload(config.bodyBytes)
	// Keep the upload scratch space outside the measured request while making
	// handler ownership explicit. The benchmark is intentionally sequential,
	// but net/http is free to overlap handler teardown across connections.
	uploadBuffers := make(chan []byte, 1)
	uploadBuffers <- make([]byte, config.effectiveChunk())
	served := make(chan error, 1)
	var completed atomic.Uint64
	server := &http3.Server{
		Addr:       address,
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13},
		QUICConfig: config.quicConfig(),
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/benchmark/ready" {
				if request.Method != http.MethodGet || request.ProtoMajor != 3 ||
					request.Host != "localhost" || request.ContentLength > 0 {
					served <- fmt.Errorf("invalid ready request: method=%s authority=%s proto=%s length=%d", request.Method, request.Host, request.Proto, request.ContentLength)
					return
				}
				if err := requireEmptyBody(request.Body); err != nil {
					served <- fmt.Errorf("invalid ready request body: %w", err)
					return
				}
				writer.Header().Set("X-Netz-Bench-Ready", "ok")
				writer.WriteHeader(http.StatusOK)
				return
			}
			if err := validateHeaders(request, config); err != nil {
				served <- err
				return
			}
			round, err := strconv.ParseUint(request.Header.Get("X-Netz-Bench-Round"), 10, 32)
			if err != nil || round != completed.Load() {
				served <- fmt.Errorf("unexpected benchmark round %q, want %d", request.Header.Get("X-Netz-Bench-Round"), completed.Load())
				return
			}
			var received uint64
			var receivedChecksum uint64
			if config.mode == "upload" {
				uploadBuffer := <-uploadBuffers
				defer func() { uploadBuffers <- uploadBuffer }()
				for {
					count, err := request.Body.Read(uploadBuffer)
					if count != 0 {
						if err := verifyPayload(uploadBuffer[:count], received, &receivedChecksum); err != nil {
							served <- err
							return
						}
						received += uint64(count)
					}
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						served <- err
						return
					}
				}
				if received != config.bodyBytes || receivedChecksum != checksum {
					served <- fmt.Errorf("upload mismatch bytes=%d checksum=%d", received, receivedChecksum)
					return
				}
			} else {
				if err := requireEmptyBody(request.Body); err != nil {
					served <- fmt.Errorf("unexpected download request body: %w", err)
					return
				}
			}
			if len(request.Trailer) != 0 {
				served <- fmt.Errorf("unexpected benchmark request trailers: %v", request.Trailer)
				return
			}
			setResultHeaders(writer, round, config.bodyBytes, checksum)
			if config.mode == "download" {
				writer.Header().Set("Content-Length", strconv.FormatUint(config.bodyBytes, 10))
			}
			writer.WriteHeader(http.StatusOK)
			if config.mode == "download" {
				for offset := uint64(0); offset < config.bodyBytes; {
					end := min(offset+config.effectiveChunk(), config.bodyBytes)
					if _, err := writer.Write(payload[offset:end]); err != nil {
						served <- err
						return
					}
					offset = end
				}
			}
			if completed.Add(1) == uint64(config.rounds()) {
				served <- nil
			}
		}),
	}
	errChan := make(chan error, 1)
	go func() { errChan <- server.ListenAndServe() }()
	fmt.Printf("QUIC_GO_HTTP3_BENCH_ADDR=%s\n", address)
	implementation := "netz"
	if config.mode == "download" {
		implementation = "quic-go"
	}
	printConfig(implementation, "netz-client+quic-go-server", config)
	select {
	case err := <-served:
		if err != nil {
			log.Fatal(err)
		}
	case err := <-errChan:
		log.Fatal(err)
	case <-time.After(config.timeout * time.Duration(config.rounds()+2)):
		log.Fatal("HTTP/3 benchmark server timed out")
	}
	time.Sleep(100 * time.Millisecond)
	_ = server.Close()
}

func runClient(address, caPath string, config benchConfig) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("parse CA bundle")
	}
	payload, expectedChecksum := makePayload(config.bodyBytes)
	readBuffer := make([]byte, config.effectiveChunk())
	implementation := "quic-go"
	if config.mode == "download" {
		implementation = "netz"
	}
	printConfig(implementation, "quic-go-client+netz-server", config)
	for round := uint(0); round < config.rounds(); round++ {
		transport := &http3.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13},
			QUICConfig:      config.quicConfig(),
		}
		client := &http.Client{Transport: transport}
		readyContext, cancelReady := context.WithTimeout(context.Background(), config.timeout)
		readyRequest, err := http.NewRequestWithContext(
			readyContext,
			http.MethodGet,
			"https://"+address+"/benchmark/ready",
			nil,
		)
		if err != nil {
			log.Fatal(err)
		}
		readyRequest.Host = "localhost"
		ready, err := client.Do(readyRequest)
		if err != nil {
			log.Fatal(err)
		}
		readyBytes, readyReadErr := io.Copy(io.Discard, ready.Body)
		_ = ready.Body.Close()
		cancelReady()
		if readyReadErr != nil || readyBytes != 0 || ready.StatusCode != http.StatusOK ||
			ready.Header.Get("X-Netz-Bench-Ready") != "ok" || len(ready.Trailer) != 0 {
			log.Fatal("benchmark ready request failed")
		}
		ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
		var body io.Reader
		method := http.MethodGet
		path := "/benchmark/download"
		if config.mode == "upload" {
			body = &chunkedReader{reader: bytes.NewReader(payload), max: int(config.effectiveChunk())}
			method = http.MethodPost
			path = "/benchmark/upload"
		}
		request, err := http.NewRequestWithContext(ctx, method, "https://"+address+path, body)
		if err != nil {
			log.Fatal(err)
		}
		request.Host = "localhost"
		if config.mode == "upload" {
			request.ContentLength = int64(config.bodyBytes)
		}
		setRequestHeaders(request, config, uint64(round))
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			log.Fatal(err)
		}
		var received uint64
		var checksum uint64
		for {
			count, err := response.Body.Read(readBuffer)
			if count != 0 {
				if config.mode == "download" {
					if err := verifyPayload(readBuffer[:count], received, &checksum); err != nil {
						log.Fatal(err)
					}
				}
				received += uint64(count)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			log.Fatalf("unexpected status %d", response.StatusCode)
		}
		if err := validateResultHeaders(response, uint64(round), config.bodyBytes, expectedChecksum); err != nil {
			log.Fatal(err)
		}
		if config.mode == "download" && response.ContentLength != int64(config.bodyBytes) {
			log.Fatalf("unexpected download content length %d", response.ContentLength)
		}
		if len(response.Trailer) != 0 {
			log.Fatal("unexpected benchmark response trailers")
		}
		if config.mode == "download" && (received != config.bodyBytes || checksum != expectedChecksum) {
			log.Fatalf("download mismatch bytes=%d checksum=%d", received, checksum)
		} else if config.mode == "upload" && received != 0 {
			log.Fatalf("unexpected upload response body bytes=%d", received)
		}
		elapsed := time.Since(started)
		if round >= config.warmup {
			printSample(implementation, "quic-go-client+netz-server", config, round-config.warmup+1, elapsed, expectedChecksum)
		}
		cancel()
		time.Sleep(100 * time.Millisecond)
		_ = transport.Close()
	}
}

type chunkedReader struct {
	reader *bytes.Reader
	max    int
}

func (reader *chunkedReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.max {
		buffer = buffer[:reader.max]
	}
	return reader.reader.Read(buffer)
}

func setRequestHeaders(request *http.Request, config benchConfig, round uint64) {
	request.Header.Set("X-Netz-Bench-Mode", config.mode)
	request.Header.Set("X-Netz-Bench-Round", strconv.FormatUint(round, 10))
	request.Header.Set("X-Netz-Bench-Bytes", strconv.FormatUint(config.bodyBytes, 10))
	request.Header.Set("X-Netz-Bench-Chunk", strconv.FormatUint(config.chunkBytes, 10))
	request.Header.Set("X-Netz-Bench-Window", strconv.FormatUint(config.streamWindow, 10))
}

func validateHeaders(request *http.Request, config benchConfig) error {
	method := http.MethodGet
	path := "/benchmark/download"
	if config.mode == "upload" {
		method, path = http.MethodPost, "/benchmark/upload"
	}
	if request.Method != method || request.URL.Path != path || request.ProtoMajor != 3 ||
		request.Host != "localhost" ||
		(config.mode == "upload" && request.ContentLength != int64(config.bodyBytes)) ||
		(config.mode == "download" && request.ContentLength > 0) ||
		request.Header.Get("X-Netz-Bench-Mode") != config.mode ||
		request.Header.Get("X-Netz-Bench-Bytes") != strconv.FormatUint(config.bodyBytes, 10) ||
		request.Header.Get("X-Netz-Bench-Chunk") != strconv.FormatUint(config.chunkBytes, 10) ||
		request.Header.Get("X-Netz-Bench-Window") != strconv.FormatUint(config.streamWindow, 10) {
		return fmt.Errorf("benchmark request mismatch method=%s path=%s headers=%v", request.Method, request.URL.Path, request.Header)
	}
	return nil
}

func requireEmptyBody(body io.Reader) error {
	var unexpected [1]byte
	count, err := body.Read(unexpected[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("bytes=%d err=%v", count, err)
	}
	return nil
}

func setResultHeaders(writer http.ResponseWriter, round, bytes, checksum uint64) {
	writer.Header().Set("X-Netz-Bench-Round", strconv.FormatUint(round, 10))
	writer.Header().Set("X-Netz-Bench-Bytes", strconv.FormatUint(bytes, 10))
	writer.Header().Set("X-Netz-Bench-Checksum", strconv.FormatUint(checksum, 10))
}

func validateResultHeaders(response *http.Response, round, bytes, checksum uint64) error {
	for name, expected := range map[string]uint64{
		"X-Netz-Bench-Round": round, "X-Netz-Bench-Bytes": bytes, "X-Netz-Bench-Checksum": checksum,
	} {
		value, err := strconv.ParseUint(response.Header.Get(name), 10, 64)
		if err != nil || value != expected {
			return fmt.Errorf("invalid %s=%q", name, response.Header.Get(name))
		}
	}
	return nil
}

func payloadByte(offset uint64) byte { return byte((offset * 131) & 0xff) }
func makePayload(size uint64) ([]byte, uint64) {
	payload := make([]byte, size)
	var checksum uint64
	for i := range payload {
		payload[i] = payloadByte(uint64(i))
		checksum += uint64(payload[i])
	}
	return payload, checksum
}
func verifyPayload(payload []byte, offset uint64, checksum *uint64) error {
	for i, value := range payload {
		if value != payloadByte(offset+uint64(i)) {
			return fmt.Errorf("payload mismatch at %d", offset+uint64(i))
		}
		*checksum += uint64(value)
	}
	return nil
}

func printConfig(implementation, rolePair string, config benchConfig) {
	fmt.Printf("implementation=%s protocol=http3 mode=%s role_pair=%s connection_scope=fresh-per-sample benchmark_scope=same-application-shape warmup=%d iterations=%d streams=1 body_bytes=%d application_chunk_requested=%d application_chunk_effective=%d stream_window=%d connection_window=%d steady_state_mtu=1280 quic_version=1 cipher=negotiated-unexposed cert_verify=true gso=implementation-default gro=implementation-default pacing=true\n", implementation, config.mode, rolePair, config.warmup, config.iterations, config.bodyBytes, config.chunkBytes, config.effectiveChunk(), config.streamWindow, config.connectionWindow())
}
func printSample(implementation, rolePair string, config benchConfig, sample uint, elapsed time.Duration, checksum uint64) {
	mib := float64(config.bodyBytes) * 1e9 / float64(elapsed.Nanoseconds()) / (1024 * 1024)
	fmt.Printf("implementation=%s protocol=http3 mode=%s role_pair=%s connection_scope=fresh-per-sample benchmark_scope=same-application-shape sample=%d elapsed_ns=%d logical_MiB_s=%.3f sent_bytes=%d received_bytes=%d checksum=%d status=200 complete=true\n", implementation, config.mode, rolePair, sample, elapsed.Nanoseconds(), mib, config.bodyBytes, config.bodyBytes, checksum)
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
		SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
