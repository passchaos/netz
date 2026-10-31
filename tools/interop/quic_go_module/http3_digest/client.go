package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

func client(address, caPath string, version int) error {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("invalid CA")
	}
	var connections atomic.Uint32
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13},
		QUICConfig: config(version), DisableCompression: true}
	transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
		connections.Add(1)
		connection, err := quic.DialAddr(ctx, address, tlsConfig, quicConfig)
		if err != nil {
			return nil, err
		}
		state := connection.ConnectionState()
		if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != "h3" || state.Version != config(version).Versions[0] {
			connection.CloseWithError(0, "wrong negotiation")
			return nil, errors.New("wrong TLS/ALPN/QUIC version")
		}
		return connection, nil
	}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	for _, path := range paths {
		method := http.MethodGet
		var content io.Reader
		if path == "/head" {
			method = http.MethodHead
		} else if path == "/generated" || path == "/sliced" {
			data := generated
			if path == "/sliced" {
				data = payload
			}
			method, content = http.MethodPost, bytes.NewReader(data)
		}
		request, _ := http.NewRequest(method, "https://"+address+path, content)
		if path == "/generated" || path == "/sliced" {
			data := generated
			if path == "/sliced" {
				data = payload
			}
			request.Header.Set("Content-Digest", digestField(data, "sha-256"))
			request.Header.Set("Want-Content-Digest", "sha-256=3, sha-512=10")
			request.Trailer = http.Header{"Content-Digest": []string{digestField(data, "sha-512")}}
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		if response.ProtoMajor != 3 || (path != "/range" && response.StatusCode != 200) {
			return errors.New("wrong HTTP response status/protocol")
		}
		var stored bytes.Buffer
		h256, h512 := sha256.New(), sha512.New()
		reader := io.LimitReader(response.Body, 65537)
		buffer := make([]byte, 333)
		reads := 0
		for {
			count, readErr := reader.Read(buffer)
			if count != 0 {
				stored.Write(buffer[:count])
				h256.Write(buffer[:count])
				h512.Write(buffer[:count])
				reads++
			}
			if readErr != nil {
				if readErr != io.EOF {
					err = readErr
				}
				break
			}
		}
		body := stored.Bytes()
		response.Body.Close()
		if err != nil {
			return err
		}
		err = verifySums(map[string][]byte{"sha-256": h256.Sum(nil), "sha-512": h512.Sum(nil)}, response.Header.Values("Content-Digest"), response.Trailer.Values("Content-Digest"))
		if (path == "/stream" || path == "/sliced") && (reads < 2 || response.Trailer.Get("Content-Digest") != "sha-256=:"+base64.StdEncoding.EncodeToString(h256.Sum(nil))+":, sha-512=:"+base64.StdEncoding.EncodeToString(h512.Sum(nil))+":") {
			return errors.New("incremental digest or trailer mismatch")
		}
		if path == "/corrupt" {
			if !errors.Is(err, digestMismatch) {
				return fmt.Errorf("corruption not detected: %v", err)
			}
			continue
		}
		if err != nil {
			return err
		}
		switch path {
		case "/encoded":
			reader, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return err
			}
			decoded, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || !bytes.Equal(decoded, payload) {
				return errors.New("bad gzip content")
			}
		case "/head", "/range":
			if err := verifyFields(payload, response.Header.Values("Repr-Digest")); err != nil {
				return err
			}
			if path == "/head" && len(body) != 0 || path == "/range" && (response.StatusCode != 206 || !bytes.Equal(body, payload[8:72])) {
				return errors.New("wrong content/representation scope")
			}
		case "/trailer", "/stream", "/sliced":
			if !bytes.Equal(body, payload) || len(response.Trailer.Values("Content-Digest")) == 0 {
				return errors.New("missing body/trailers")
			}
		case "/generated":
			if !bytes.Equal(body, []byte("verified")) {
				return errors.New("generated request not verified")
			}
		case "/finish":
			if !bytes.Equal(body, []byte("done")) {
				return errors.New("reuse did not complete")
			}
		}
	}
	if connections.Load() != 1 {
		return fmt.Errorf("connections=%d", connections.Load())
	}
	summary("quic-go-client", version, connections.Load())
	return nil
}
