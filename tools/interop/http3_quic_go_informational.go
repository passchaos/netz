// Command http3_quic_go_informational is a one-request HTTP/3 1xx peer.
// The shell gate builds it with the audited quic-go module pinned by the local
// quicz fixture, without modifying that external checkout.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

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
	var negotiatedVersion atomic.Uint32
	server := &http3.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: quicConfig(v2Only),
		ConnContext: func(ctx context.Context, connection *quic.Conn) context.Context {
			negotiatedVersion.Store(uint32(connection.ConnectionState().Version))
			return ctx
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet ||
				request.URL.RequestURI() != "/informational?from=netz" ||
				request.ProtoMajor != 3 {
				served <- fmt.Errorf("unexpected request: method=%s target=%s proto=%s", request.Method, request.URL.RequestURI(), request.Proto)
				return
			}
			writer.Header().Set("Link", "</quic-go.css>")
			writer.WriteHeader(http.StatusEarlyHints)
			writer.Header().Del("Link")
			writer.Header().Set("X-Progress", "half")
			writer.WriteHeader(http.StatusProcessing)
			writer.Header().Del("X-Progress")
			writer.Header().Set("X-Quic-Go-Final", "yes")
			writer.WriteHeader(http.StatusOK)
			_, err := writer.Write([]byte("final"))
			served <- err
		}),
	}
	errChan := make(chan error, 1)
	go func() { errChan <- server.ListenAndServe() }()
	fmt.Printf("quic-go HTTP/3 informational server listening=%s ca_out=%s\n", address, caOut)
	select {
	case err := <-served:
		if err != nil {
			log.Fatal(err)
		}
	case err := <-errChan:
		log.Fatalf("serve HTTP/3: %v", err)
	case <-time.After(10 * time.Second):
		log.Fatal("timed out waiting for informational request")
	}
	time.Sleep(250 * time.Millisecond)
	if err := server.Close(); err != nil {
		log.Fatalf("close HTTP/3 server: %v", err)
	}
	wantVersion := quic.Version1
	version := 1
	if v2Only {
		wantVersion = quic.Version2
		version = 2
	}
	if negotiatedVersion.Load() != uint32(wantVersion) {
		log.Fatalf("negotiated QUIC version %#x, want v%d", negotiatedVersion.Load(), version)
	}
	fmt.Printf("quic-go HTTP/3 server sent informational responses to netz: version=%d statuses=103,102 final=200 body=5\n", version)
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
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
		},
		QUICConfig: quicConfig(v2Only),
	}
	defer transport.Close()
	client := &http.Client{Transport: transport}

	var statuses []int
	var headersValid = true
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			statuses = append(statuses, code)
			switch code {
			case http.StatusEarlyHints:
				headersValid = headersValid && header.Get("Link") == "</netz.css>"
			case http.StatusProcessing:
				headersValid = headersValid && header.Get("X-Progress") == "half"
			default:
				headersValid = false
			}
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		http.MethodGet,
		"https://"+address+"/informational?from=quic-go",
		nil,
	)
	if err != nil {
		log.Fatalf("build request: %v", err)
	}
	request.Host = "localhost"
	response, err := client.Do(request)
	if err != nil {
		log.Fatalf("HTTP/3 informational request: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("read response: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		log.Fatalf("close response: %v", err)
	}
	if len(statuses) != 2 || statuses[0] != 103 || statuses[1] != 102 ||
		!headersValid || response.StatusCode != 200 ||
		response.Header.Get("X-Netz-Final") != "yes" || string(body) != "final" {
		log.Fatalf("unexpected response: informational=%v valid_headers=%t status=%d headers=%v body=%q", statuses, headersValid, response.StatusCode, response.Header, body)
	}
	version := 1
	if v2Only {
		version = 2
	}
	fmt.Printf("quic-go HTTP/3 client received netz informational responses: version=%d statuses=103,102 final=200 body=5\n", version)
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
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
