// Command http3_quic_go_bench provides the quic-go half of the netz HTTP/3
// same-application-shape benchmark. The runner builds it inside netz's audited,
// repository-owned quic-go module.
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
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"netz-quic-go-interop/internal/testcert"
)

const mtu = 1280

type benchConfig struct {
	mode         string
	version      uint
	streams      uint
	warmup       uint
	iterations   uint
	bodyBytes    uint64
	chunkBytes   uint64
	streamWindow uint64
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

func main() {
	role := flag.String("role", "server", "server or client")
	address := flag.String("addr", "127.0.0.1:0", "listen or peer UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor for client mode")
	caOut := flag.String("ca-out", "", "PEM output path for server mode")
	mode := flag.String("bench-mode", "upload", "upload or download")
	v2Only := flag.Bool("v2-only", false, "require QUIC v2")
	streams := flag.Uint("streams", 1, "parallel request stream count")
	warmup := flag.Uint("warmup", 10, "warmup request count")
	iterations := flag.Uint("iterations", 5, "measured request count")
	bodyBytes := flag.Uint64("body-bytes", 4*1024*1024, "logical body bytes per request")
	chunkBytes := flag.Uint64("chunk-bytes", 16*1024, "application read/write chunk bytes")
	streamWindow := flag.Uint64("stream-window", 1024*1024, "fixed QUIC stream receive window")
	timeoutMS := flag.Uint("timeout-ms", 30000, "per-operation timeout milliseconds")
	stats := flag.Bool("stats", false, "report Go runtime heap telemetry")
	flag.Parse()
	config := benchConfig{
		mode: *mode, version: 1, streams: *streams, warmup: *warmup, iterations: *iterations,
		bodyBytes: *bodyBytes, chunkBytes: *chunkBytes,
		streamWindow: *streamWindow, timeout: time.Duration(*timeoutMS) * time.Millisecond,
	}
	if *v2Only {
		config.version = 2
	}
	if err := config.validate(); err != nil {
		log.Fatal(err)
	}
	var before memorySnapshot
	if *stats {
		before = readMemory()
	}
	switch *role {
	case "server":
		runServer(*address, *caOut, config)
		if *stats {
			printMemory("netz-client+quic-go-server", "server", config, before, readMemory())
		}
	case "client":
		runClient(*address, *caPath, config)
		if *stats {
			printMemory("quic-go-client+netz-server", "client", config, before, readMemory())
		}
	default:
		log.Fatalf("unknown role %q", *role)
	}
}

func (config benchConfig) validate() error {
	if config.mode != "upload" && config.mode != "download" {
		return fmt.Errorf("invalid benchmark mode %q", config.mode)
	}
	if (config.version != 1 && config.version != 2) ||
		(config.streams != 1 && config.streams != 4 && config.streams != 16) ||
		config.warmup == 0 || config.iterations == 0 || config.bodyBytes == 0 ||
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
	if config.totalBytes()/uint64(config.streams) != config.bodyBytes ||
		config.connectionWindow()/max(uint64(config.streams), 8) != config.streamWindow {
		return errors.New("benchmark aggregate size overflow")
	}
	return nil
}

func (config benchConfig) rounds() uint       { return config.warmup + config.iterations }
func (config benchConfig) totalBytes() uint64 { return config.bodyBytes * uint64(config.streams) }
func (config benchConfig) connectionWindow() uint64 {
	return config.streamWindow * max(uint64(config.streams), 8)
}
func (config benchConfig) effectiveChunk() uint64 { return min(config.chunkBytes, mtu-128) }
func (config benchConfig) aggregateChecksum() uint64 {
	var checksum uint64
	for index := uint64(0); index < uint64(config.streams); index++ {
		checksum += streamChecksum(config.bodyBytes, index)
	}
	return checksum
}

func (config benchConfig) quicConfig() *quic.Config {
	version := quic.Version1
	if config.version == 2 {
		version = quic.Version2
	}
	return &quic.Config{
		Versions:                       []quic.Version{version},
		HandshakeIdleTimeout:           config.timeout,
		MaxIdleTimeout:                 config.timeout,
		InitialStreamReceiveWindow:     config.streamWindow,
		MaxStreamReceiveWindow:         config.streamWindow,
		InitialConnectionReceiveWindow: config.connectionWindow(),
		MaxConnectionReceiveWindow:     config.connectionWindow(),
		MaxIncomingStreams:             int64(config.streams) + 8,
		MaxIncomingUniStreams:          16,
		InitialPacketSize:              mtu,
		DisablePathMTUDiscovery:        true,
	}
}

type roundTracker struct {
	mu         sync.Mutex
	nextRound  uint64
	totalRound uint64
	streams    uint64
	rounds     map[uint64]*roundState
}

func (tracker *roundTracker) canClose(round uint64) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return round < tracker.totalRound && tracker.nextRound == round+1
}

type roundState struct {
	inFlight []bool
	done     []bool
	ready    chan struct{}
	started  uint64
	finished uint64
}

func newRoundTracker(config benchConfig) *roundTracker {
	return &roundTracker{
		totalRound: uint64(config.rounds()),
		streams:    uint64(config.streams),
		rounds:     make(map[uint64]*roundState),
	}
}

func (tracker *roundTracker) begin(round, index uint64) (<-chan struct{}, error) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if round >= tracker.totalRound {
		return nil, fmt.Errorf("unexpected benchmark round %d, want < %d", round, tracker.totalRound)
	}
	if round != tracker.nextRound {
		return nil, fmt.Errorf("unexpected benchmark round %d, want %d", round, tracker.nextRound)
	}
	if index >= tracker.streams {
		return nil, fmt.Errorf("unexpected benchmark index %d, want < %d", index, tracker.streams)
	}
	state := tracker.rounds[round]
	if state == nil {
		state = &roundState{
			inFlight: make([]bool, tracker.streams),
			done:     make([]bool, tracker.streams),
			ready:    make(chan struct{}),
		}
		tracker.rounds[round] = state
	}
	if state.inFlight[index] || state.done[index] {
		return nil, fmt.Errorf("duplicate benchmark request round=%d index=%d", round, index)
	}
	state.inFlight[index] = true
	state.started++
	if state.started == tracker.streams {
		close(state.ready)
	}
	return state.ready, nil
}

func (tracker *roundTracker) finish(round, index uint64) (bool, bool, error) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	state := tracker.rounds[round]
	if state == nil || index >= tracker.streams || !state.inFlight[index] || state.done[index] {
		return false, false, fmt.Errorf("invalid benchmark completion round=%d index=%d", round, index)
	}
	state.inFlight[index] = false
	state.done[index] = true
	state.finished++
	if state.finished != tracker.streams {
		return false, false, nil
	}
	if round != tracker.nextRound {
		return false, false, fmt.Errorf("out-of-order benchmark completion round=%d want=%d", round, tracker.nextRound)
	}
	delete(tracker.rounds, round)
	tracker.nextRound++
	return true, tracker.nextRound == tracker.totalRound, nil
}

func (tracker *roundTracker) status() string {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	state := tracker.rounds[tracker.nextRound]
	if state == nil {
		return fmt.Sprintf("next_round=%d started=0 finished=0", tracker.nextRound)
	}
	return fmt.Sprintf("next_round=%d started=%d finished=%d", tracker.nextRound, state.started, state.finished)
}

func runServer(address, caOut string, config benchConfig) {
	if caOut == "" {
		log.Fatal("-ca-out is required in server mode")
	}
	certificate, certificatePEM, err := testcert.Localhost()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caOut, certificatePEM, 0o600); err != nil {
		log.Fatal(err)
	}
	tracker := newRoundTracker(config)
	var requestBuffers sync.Pool
	requestBuffers.New = func() any {
		return make([]byte, config.effectiveChunk())
	}
	served := make(chan error, 1)
	var reportOnce sync.Once
	var benchmarkHandlers sync.WaitGroup
	report := func(err error) {
		reportOnce.Do(func() {
			served <- err
		})
	}
	server := &http3.Server{
		Addr:       address,
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13},
		QUICConfig: config.quicConfig(),
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/benchmark/ready" {
				if request.Method != http.MethodGet || request.ProtoMajor != 3 ||
					request.Host != "localhost" || request.ContentLength > 0 {
					report(fmt.Errorf("invalid ready request: method=%s authority=%s proto=%s length=%d", request.Method, request.Host, request.Proto, request.ContentLength))
					return
				}
				if err := requireEmptyBody(request.Body); err != nil {
					report(fmt.Errorf("invalid ready request body: %w", err))
					return
				}
				writer.Header().Set("X-Netz-Bench-Ready", "ok")
				writer.WriteHeader(http.StatusOK)
				return
			}
			benchmarkHandlers.Add(1)
			defer benchmarkHandlers.Done()
			if request.URL.Path == "/benchmark/close" {
				round, err := strconv.ParseUint(request.Header.Get("X-Netz-Bench-Round"), 10, 64)
				if err != nil || request.Method != http.MethodGet || request.ProtoMajor != 3 ||
					request.Host != "localhost" || request.ContentLength > 0 ||
					!tracker.canClose(round) {
					report(fmt.Errorf("invalid close request round=%q", request.Header.Get("X-Netz-Bench-Round")))
					return
				}
				if err := requireEmptyBody(request.Body); err != nil {
					report(err)
					return
				}
				writer.Header().Set("X-Netz-Bench-Close", "ok")
				writer.WriteHeader(http.StatusOK)
				if tracker.canClose(uint64(config.rounds() - 1)) {
					defer report(nil)
				}
				return
			}
			round, index, err := validateHeaders(request, config)
			if err != nil {
				report(err)
				return
			}
			ready, err := tracker.begin(round, index)
			if err != nil {
				report(err)
				return
			}
			select {
			case <-ready:
			case <-request.Context().Done():
				report(request.Context().Err())
				return
			}
			var received uint64
			var receivedChecksum uint64
			if config.mode == "upload" {
				uploadBuffer := requestBuffers.Get().([]byte)
				defer requestBuffers.Put(uploadBuffer)
				for {
					count, err := request.Body.Read(uploadBuffer)
					if count != 0 {
						if err := verifyPayload(uploadBuffer[:count], index, received, &receivedChecksum); err != nil {
							report(err)
							return
						}
						received += uint64(count)
					}
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						report(err)
						return
					}
				}
				if received != config.bodyBytes || receivedChecksum != streamChecksum(config.bodyBytes, index) {
					report(fmt.Errorf("upload mismatch round=%d index=%d bytes=%d checksum=%d", round, index, received, receivedChecksum))
					return
				}
			} else {
				if err := requireEmptyBody(request.Body); err != nil {
					report(fmt.Errorf("unexpected download request body: %w", err))
					return
				}
			}
			if len(request.Trailer) != 0 {
				report(fmt.Errorf("unexpected benchmark request trailers: %v", request.Trailer))
				return
			}
			streamChecksum := streamChecksum(config.bodyBytes, index)
			if config.mode == "upload" {
				streamChecksum = receivedChecksum
			}
			setResultHeaders(writer, config, round, index, config.bodyBytes, streamChecksum)
			if config.mode == "download" {
				writer.Header().Set("Content-Length", strconv.FormatUint(config.bodyBytes, 10))
			}
			writer.WriteHeader(http.StatusOK)
			if config.mode == "download" {
				writeBuffer := requestBuffers.Get().([]byte)
				defer requestBuffers.Put(writeBuffer)
				var writtenChecksum uint64
				for offset := uint64(0); offset < config.bodyBytes; {
					end := min(offset+uint64(len(writeBuffer)), config.bodyBytes)
					chunk := writeBuffer[:end-offset]
					fillPayload(chunk, index, offset, &writtenChecksum)
					if _, err := writer.Write(chunk); err != nil {
						report(err)
						return
					}
					offset = end
				}
				if writtenChecksum != streamChecksum {
					report(fmt.Errorf("download checksum mismatch round=%d index=%d wrote=%d expected=%d", round, index, writtenChecksum, streamChecksum))
					return
				}
			}
			roundDone, allDone, err := tracker.finish(round, index)
			if err != nil {
				report(err)
				return
			}
			if roundDone && round >= uint64(config.warmup) {
				printServerComplete("quic-go", "netz-client+quic-go-server", config, uint(round)-config.warmup+1, config.aggregateChecksum())
			}
			_ = allDone
		}),
	}
	errChan := make(chan error, 1)
	go func() { errChan <- server.ListenAndServe() }()
	fmt.Printf("QUIC_GO_HTTP3_BENCH_ADDR=%s\n", address)
	printConfig("quic-go", "netz-client+quic-go-server", "server", config)
	select {
	case err := <-served:
		if err != nil {
			log.Fatal(err)
		}
	case err := <-errChan:
		log.Fatal(err)
	case <-time.After(config.timeout * time.Duration(config.rounds()+2)):
		log.Fatalf("HTTP/3 benchmark server timed out: %s", tracker.status())
	}
	benchmarkHandlers.Wait()
	if err := server.Close(); err != nil {
		log.Fatal(err)
	}
	if err := <-errChan; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
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
	expectedAggregateChecksum := config.aggregateChecksum()
	implementation := "quic-go"
	if config.mode == "download" {
		implementation = "netz"
	}
	printConfig("quic-go", "quic-go-client+netz-server", "client", config)
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
		sampleContext, cancelSample := context.WithTimeout(context.Background(), config.timeout)
		startBarrier := make(chan struct{})
		results := make(chan streamResult, config.streams)
		var requestReady sync.WaitGroup
		requestReady.Add(int(config.streams))
		for index := uint64(0); index < uint64(config.streams); index++ {
			go runClientStream(client, address, config, uint64(round), index, sampleContext, startBarrier, &requestReady, results)
		}
		requestReady.Wait()
		started := time.Now()
		close(startBarrier)
		var aggregateChecksum uint64
		streamsFinished := 0
		seen := make([]bool, config.streams)
		for remaining := 0; remaining < int(config.streams); remaining++ {
			result := <-results
			if result.err != nil {
				cancelSample()
				log.Fatal(result.err)
			}
			if result.index >= uint64(config.streams) {
				cancelSample()
				log.Fatalf("invalid result index %d", result.index)
			}
			if seen[result.index] {
				cancelSample()
				log.Fatalf("duplicate result index %d", result.index)
			}
			seen[result.index] = true
			aggregateChecksum += result.checksum
			streamsFinished++
		}
		if streamsFinished != int(config.streams) {
			cancelSample()
			log.Fatalf("streams finished mismatch %d", streamsFinished)
		}
		if aggregateChecksum != expectedAggregateChecksum {
			cancelSample()
			log.Fatalf("aggregate checksum mismatch got=%d want=%d", aggregateChecksum, expectedAggregateChecksum)
		}
		elapsed := time.Since(started)
		cancelSample()
		closeContext, cancelClose := context.WithTimeout(context.Background(), config.timeout)
		if err := benchmarkCloseRequest(client, address, closeContext, uint64(round)); err != nil {
			cancelClose()
			log.Fatal(err)
		}
		cancelClose()
		if round >= config.warmup {
			printSample(implementation, "quic-go-client+netz-server", "client", config, round-config.warmup+1, elapsed, aggregateChecksum)
		}
		_ = transport.Close()
	}
}

func benchmarkCloseRequest(client *http.Client, address string, ctx context.Context, round uint64) error {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "https://"+address+"/benchmark/close", nil,
	)
	if err != nil {
		return err
	}
	request.Host = "localhost"
	request.Header.Set("X-Netz-Bench-Round", strconv.FormatUint(round, 10))
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	bytes, readErr := io.Copy(io.Discard, response.Body)
	if readErr != nil || bytes != 0 || response.StatusCode != http.StatusOK ||
		response.Header.Get("X-Netz-Bench-Close") != "ok" || len(response.Trailer) != 0 {
		return errors.New("benchmark close request failed")
	}
	return nil
}

type streamResult struct {
	index    uint64
	checksum uint64
	err      error
}

type patternReader struct {
	size   uint64
	index  uint64
	offset uint64
	max    int
}

func (reader *patternReader) Read(buffer []byte) (int, error) {
	if reader.offset >= reader.size {
		return 0, io.EOF
	}
	if len(buffer) > reader.max {
		buffer = buffer[:reader.max]
	}
	count := int(min(uint64(len(buffer)), reader.size-reader.offset))
	fillPayload(buffer[:count], reader.index, reader.offset, nil)
	reader.offset += uint64(count)
	return count, nil
}

func runClientStream(client *http.Client, address string, config benchConfig, round, index uint64, sampleContext context.Context, startBarrier <-chan struct{}, requestReady *sync.WaitGroup, results chan<- streamResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			results <- streamResult{index: index, err: fmt.Errorf("panic in stream %d: %v", index, recovered)}
		}
	}()
	var body io.Reader
	method := http.MethodGet
	path := "/benchmark/download"
	if config.mode == "upload" {
		body = &patternReader{size: config.bodyBytes, index: index, max: int(config.effectiveChunk())}
		method = http.MethodPost
		path = "/benchmark/upload"
	}
	request, err := http.NewRequestWithContext(sampleContext, method, "https://"+address+path, body)
	if err != nil {
		requestReady.Done()
		results <- streamResult{index: index, err: err}
		return
	}
	request.Host = "localhost"
	if config.mode == "upload" {
		request.ContentLength = int64(config.bodyBytes)
	}
	setRequestHeaders(request, config, round, index)
	requestReady.Done()
	<-startBarrier
	response, err := client.Do(request)
	if err != nil {
		results <- streamResult{index: index, err: err}
		return
	}
	defer func() { _ = response.Body.Close() }()
	readBuffer := make([]byte, config.effectiveChunk())
	var received uint64
	var checksum uint64
	for {
		count, err := response.Body.Read(readBuffer)
		if count != 0 {
			if config.mode == "download" {
				if err := verifyPayload(readBuffer[:count], index, received, &checksum); err != nil {
					results <- streamResult{index: index, err: err}
					return
				}
			}
			received += uint64(count)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			results <- streamResult{index: index, err: err}
			return
		}
	}
	if response.StatusCode != http.StatusOK {
		results <- streamResult{index: index, err: fmt.Errorf("unexpected status %d for stream %d", response.StatusCode, index)}
		return
	}
	expectedChecksum := streamChecksum(config.bodyBytes, index)
	if err := validateResultHeaders(response, config, round, index, config.bodyBytes, expectedChecksum); err != nil {
		results <- streamResult{index: index, err: err}
		return
	}
	if config.mode == "download" && response.ContentLength != int64(config.bodyBytes) {
		results <- streamResult{index: index, err: fmt.Errorf("unexpected download content length %d for stream %d", response.ContentLength, index)}
		return
	}
	if len(response.Trailer) != 0 {
		results <- streamResult{index: index, err: fmt.Errorf("unexpected benchmark response trailers for stream %d", index)}
		return
	}
	if config.mode == "download" {
		if received != config.bodyBytes || checksum != expectedChecksum {
			results <- streamResult{index: index, err: fmt.Errorf("download mismatch stream=%d bytes=%d checksum=%d", index, received, checksum)}
			return
		}
	} else if received != 0 {
		results <- streamResult{index: index, err: fmt.Errorf("unexpected upload response body bytes=%d stream=%d", received, index)}
		return
	}
	results <- streamResult{index: index, checksum: expectedChecksum}
}

func setRequestHeaders(request *http.Request, config benchConfig, round, index uint64) {
	request.Header.Set("X-Netz-Bench-Mode", config.mode)
	request.Header.Set("X-Netz-Bench-Round", strconv.FormatUint(round, 10))
	request.Header.Set("X-Netz-Bench-Stream-Index", strconv.FormatUint(index, 10))
	request.Header.Set("X-Netz-Bench-Streams", strconv.FormatUint(uint64(config.streams), 10))
	request.Header.Set("X-Netz-Bench-Bytes", strconv.FormatUint(config.bodyBytes, 10))
	request.Header.Set("X-Netz-Bench-Chunk", strconv.FormatUint(config.chunkBytes, 10))
	request.Header.Set("X-Netz-Bench-Window", strconv.FormatUint(config.streamWindow, 10))
}

type headerGetter interface {
	Get(string) string
}

func headerValue(headers headerGetter, names ...string) string {
	for _, name := range names {
		if value := headers.Get(name); value != "" {
			return value
		}
	}
	return ""
}

func parseHeaderUint(headers headerGetter, allowMissing bool, fallback uint64, names ...string) (uint64, error) {
	value := headerValue(headers, names...)
	if value == "" {
		if allowMissing {
			return fallback, nil
		}
		return 0, fmt.Errorf("missing header %q", names[0])
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q", names[0], value)
	}
	return parsed, nil
}

func validateHeaders(request *http.Request, config benchConfig) (uint64, uint64, error) {
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
		return 0, 0, fmt.Errorf("benchmark request mismatch method=%s path=%s headers=%v", request.Method, request.URL.Path, request.Header)
	}
	round, err := parseHeaderUint(request.Header, false, 0, "X-Netz-Bench-Round")
	if err != nil {
		return 0, 0, err
	}
	index, err := parseHeaderUint(request.Header, false, 0, "X-Netz-Bench-Stream-Index")
	if err != nil {
		return 0, 0, err
	}
	streams, err := parseHeaderUint(request.Header, false, 0, "X-Netz-Bench-Streams")
	if err != nil {
		return 0, 0, err
	}
	if streams != uint64(config.streams) {
		return 0, 0, fmt.Errorf("unexpected benchmark streams %d, want %d", streams, config.streams)
	}
	if index >= uint64(config.streams) {
		return 0, 0, fmt.Errorf("unexpected benchmark index %d, want < %d", index, config.streams)
	}
	return round, index, nil
}

func requireEmptyBody(body io.Reader) error {
	var unexpected [1]byte
	count, err := body.Read(unexpected[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("bytes=%d err=%v", count, err)
	}
	return nil
}

func setResultHeaders(writer http.ResponseWriter, config benchConfig, round, index, bytes, checksum uint64) {
	writer.Header().Set("X-Netz-Bench-Round", strconv.FormatUint(round, 10))
	writer.Header().Set("X-Netz-Bench-Stream-Index", strconv.FormatUint(index, 10))
	writer.Header().Set("X-Netz-Bench-Streams", strconv.FormatUint(uint64(config.streams), 10))
	writer.Header().Set("X-Netz-Bench-Bytes", strconv.FormatUint(bytes, 10))
	writer.Header().Set("X-Netz-Bench-Checksum", strconv.FormatUint(checksum, 10))
}

func validateResultHeaders(response *http.Response, config benchConfig, round, index, bytes, checksum uint64) error {
	for name, expected := range map[string]uint64{
		"X-Netz-Bench-Round": round, "X-Netz-Bench-Bytes": bytes, "X-Netz-Bench-Checksum": checksum,
	} {
		value, err := strconv.ParseUint(response.Header.Get(name), 10, 64)
		if err != nil || value != expected {
			return fmt.Errorf("invalid %s=%q", name, response.Header.Get(name))
		}
	}
	parsedIndex, err := parseHeaderUint(response.Header, false, 0, "X-Netz-Bench-Stream-Index")
	if err != nil {
		return err
	}
	if parsedIndex != index {
		return fmt.Errorf("invalid X-Netz-Bench-Stream-Index=%q", headerValue(response.Header, "X-Netz-Bench-Stream-Index", "X-Netz-Bench-Index"))
	}
	parsedStreams, err := parseHeaderUint(response.Header, false, 0, "X-Netz-Bench-Streams")
	if err != nil || parsedStreams != uint64(config.streams) {
		return fmt.Errorf("invalid X-Netz-Bench-Streams=%q", response.Header.Get("X-Netz-Bench-Streams"))
	}
	return nil
}

func payloadByte(index, offset uint64) byte { return byte((offset*131 + index*17) & 0xff) }

func fillPayload(buffer []byte, index, offset uint64, checksum *uint64) {
	for i := range buffer {
		value := payloadByte(index, offset+uint64(i))
		buffer[i] = value
		if checksum != nil {
			*checksum += uint64(value)
		}
	}
}

func streamChecksum(size, index uint64) uint64 {
	const fullPeriodChecksum = 255 * 256 / 2
	periods, remainder := size/256, size%256
	checksum := periods * fullPeriodChecksum
	for offset := uint64(0); offset < remainder; offset++ {
		checksum += uint64(payloadByte(index, offset))
	}
	return checksum
}

func verifyPayload(payload []byte, index, offset uint64, checksum *uint64) error {
	for i, value := range payload {
		if value != payloadByte(index, offset+uint64(i)) {
			return fmt.Errorf("payload mismatch at %d", offset+uint64(i))
		}
		*checksum += uint64(value)
	}
	return nil
}

func printConfig(implementation, rolePair, endpointRole string, config benchConfig) {
	fmt.Printf("record=config implementation=%s protocol=http3 mode=%s role_pair=%s endpoint_role=%s sender_role=%s client_io=%s server_io=%s connection_scope=fresh-per-sample benchmark_scope=same-application-shape body_deadline_scope=sample warmup=%d iterations=%d streams=%d body_bytes=%d application_chunk_requested=%d application_chunk_effective=%d stream_window=%d connection_window=%d timeout_ms=%d steady_state_mtu=1280 quic_version=%d cipher=negotiated-unexposed cert_verify=true gso=implementation-default gro=implementation-default pacing=true\n", implementation, config.mode, rolePair, endpointRole, senderRole(config), clientIO(rolePair), serverIO(rolePair), config.warmup, config.iterations, config.streams, config.bodyBytes, config.chunkBytes, config.effectiveChunk(), config.streamWindow, config.connectionWindow(), config.timeout/time.Millisecond, config.version)
}
func printSample(implementation, rolePair, endpointRole string, config benchConfig, sample uint, elapsed time.Duration, checksum uint64) {
	mib := float64(config.totalBytes()) * 1e9 / float64(elapsed.Nanoseconds()) / (1024 * 1024)
	fmt.Printf("record=result implementation=%s protocol=http3 mode=%s role_pair=%s result_owner=client endpoint_role=%s sender_role=%s client_io=%s server_io=%s connection_scope=fresh-per-sample benchmark_scope=same-application-shape body_deadline_scope=sample sample=%d streams=%d body_bytes=%d elapsed_ns=%d logical_MiB_s=%.3f sent_bytes=%d received_bytes=%d checksum=%d status=200 streams_finished=%d per_stream_verified=true quic_version=%d complete=true\n", implementation, config.mode, rolePair, endpointRole, senderRole(config), clientIO(rolePair), serverIO(rolePair), sample, config.streams, config.bodyBytes, elapsed.Nanoseconds(), mib, config.totalBytes(), config.totalBytes(), checksum, config.streams, config.version)
}

func printServerComplete(implementation, rolePair string, config benchConfig, sample uint, checksum uint64) {
	sent, received := uint64(0), uint64(0)
	if config.mode == "upload" {
		received = config.totalBytes()
	} else {
		sent = config.totalBytes()
	}
	fmt.Printf("record=server-complete implementation=%s protocol=http3 mode=%s role_pair=%s endpoint_role=server sender_role=%s client_io=%s server_io=%s connection_scope=fresh-per-sample benchmark_scope=same-application-shape body_deadline_scope=sample sample=%d streams=%d body_bytes=%d sent_bytes=%d received_bytes=%d checksum=%d status=200 streams_finished=%d per_stream_verified=true quic_version=%d complete=true\n", implementation, config.mode, rolePair, senderRole(config), clientIO(rolePair), serverIO(rolePair), sample, config.streams, config.bodyBytes, sent, received, checksum, config.streams, config.version)
}

func printMemory(rolePair, endpointRole string, config benchConfig, before, after memorySnapshot) {
	senderRole := "server"
	if config.mode == "upload" {
		senderRole = "client"
	}
	fmt.Printf("record=memory implementation=quic-go protocol=http3 mode=%s role_pair=%s endpoint_role=%s sender_role=%s client_io=%s server_io=%s streams=%d body_bytes=%d warmup=%d iterations=%d memory_scope=benchmark-run-after-argument-parse quic_version=%d allocator_scope=go-runtime-heap alloc_count=%d free_count=%d total_allocated_bytes=%d heap_alloc_bytes_end=%d heap_sys_bytes_end=%d runtime_sys_bytes_end=%d gc_cycles=%d complete=true\n", config.mode, rolePair, endpointRole, senderRole, clientIO(rolePair), serverIO(rolePair), config.streams, config.bodyBytes, config.warmup, config.iterations, config.version, after.mallocs-before.mallocs, after.frees-before.frees, after.totalAlloc-before.totalAlloc, after.heapAlloc, after.heapSys, after.sys, after.numGC-before.numGC)
}

func senderRole(config benchConfig) string {
	if config.mode == "upload" {
		return "client"
	}
	return "server"
}

func clientIO(rolePair string) string {
	if strings.HasPrefix(rolePair, "netz-client") {
		return "zio-std-io"
	}
	return "quic-go-netpoll"
}

func serverIO(rolePair string) string {
	if strings.HasSuffix(rolePair, "netz-server") {
		return "zio-std-io"
	}
	return "quic-go-netpoll"
}
