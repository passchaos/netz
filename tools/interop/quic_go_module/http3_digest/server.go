package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

func server(address, caPath, certPath, keyPath string, version int) error {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	packet, err := net.ListenPacket("udp4", address)
	if err != nil {
		return err
	}
	defer packet.Close()
	var connections atomic.Uint32
	results := make(chan error, len(paths))
	var sequence atomic.Uint32
	service := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}, QUICConfig: config(version), Logger: slog.Default()}
	service.ConnContext = func(ctx context.Context, connection *quic.Conn) context.Context {
		connections.Add(1)
		if connection.ConnectionState().TLS.Version != tls.VersionTLS13 || connection.ConnectionState().TLS.NegotiatedProtocol != "h3" || connection.ConnectionState().Version != config(version).Versions[0] {
			results <- errors.New("wrong TLS/ALPN/QUIC version")
		}
		return ctx
	}
	service.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		index := int(sequence.Add(1) - 1)
		if index >= len(paths) || request.URL.Path != paths[index] || request.ProtoMajor != 3 {
			results <- errors.New("unexpected request sequence")
			return
		}
		method := http.MethodGet
		if request.URL.Path == "/head" {
			method = http.MethodHead
		}
		if request.URL.Path == "/generated" || request.URL.Path == "/sliced" {
			method = http.MethodPost
		}
		if request.Method != method {
			results <- errors.New("unexpected request method")
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 65537))
		if err == nil && request.URL.Path == "/sliced" {
			if !bytes.Equal(body, payload) {
				err = errors.New("bad sliced request body")
			} else {
				err = verifyFields(body, request.Header.Values("Content-Digest"), request.Trailer.Values("Content-Digest"))
			}
		}
		if err == nil && request.URL.Path == "/generated" {
			if !bytes.Equal(body, generated) || request.Header.Get("Want-Content-Digest") != "sha-256=3, sha-512=10" {
				err = errors.New("bad generated request")
			} else {
				err = verifyFields(body, request.Header.Values("Content-Digest"), request.Trailer.Values("Content-Digest"))
			}
		}
		if err != nil {
			results <- err
			return
		}
		content, headers, trailers, err := reply(request.URL.Path)
		if err != nil {
			results <- err
			return
		}
		for name, values := range headers {
			writer.Header()[name] = values
		}
		for name := range trailers {
			writer.Header().Add("Trailer", name)
		}
		status := 200
		if request.URL.Path == "/range" {
			status = 206
		}
		writer.WriteHeader(status)
		if request.Method != http.MethodHead {
			for offset := 0; offset < len(content); offset += 511 {
				end := min(offset+511, len(content))
				if _, err = writer.Write(content[offset:end]); err != nil {
					break
				}
				if request.URL.Path == "/stream" {
					if err = writer.(interface{ FlushError() error }).FlushError(); err != nil {
						break
					}
				}
			}
		}
		for name, values := range trailers {
			writer.Header()[name] = values
		}
		results <- err
	})
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- service.Serve(packet) }()
	fmt.Printf("READY %d\n", packet.LocalAddr().(*net.UDPAddr).Port)
	for range paths {
		select {
		case err := <-results:
			if err != nil {
				service.Close()
				return err
			}
		case err := <-serveErrors:
			return err
		case <-time.After(15 * time.Second):
			service.Close()
			return errors.New("server transcript timeout")
		}
	}
	time.Sleep(250 * time.Millisecond)
	service.Close()
	if connections.Load() != 1 {
		return fmt.Errorf("connections=%d", connections.Load())
	}
	summary("quic-go-server", version, connections.Load())
	return nil
}
