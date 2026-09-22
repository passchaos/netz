// Command http3_quic_go_handlers verifies netz's shared-endpoint handler
// supervisor with two independent quic-go HTTP/3 connections.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "netz UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor")
	v2Only := flag.Bool("v2-only", false, "use only QUIC v2")
	flag.Parse()
	if *caPath == "" {
		log.Fatal("-ca is required")
	}
	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		log.Fatalf("read CA bundle: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("parse CA bundle")
	}

	type scenario struct{ path, body string }
	scenarios := []scenario{
		{path: "/handler-one", body: "quic-go-one"},
		{path: "/handler-two", body: "quic-go-two"},
	}
	errors := make(chan error, len(scenarios))
	var start sync.WaitGroup
	start.Add(1)
	for _, scenario := range scenarios {
		scenario := scenario
		go func() {
			start.Wait()
			config := &quic.Config{}
			if *v2Only {
				config.Versions = []quic.Version{quic.Version2}
			}
			transport := &http3.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13,
				},
				QUICConfig: config,
			}
			defer transport.Close()
			client := &http.Client{Transport: transport}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(
				ctx,
				http.MethodPost,
				"https://"+*address+scenario.path,
				bytes.NewBufferString(scenario.body),
			)
			if err != nil {
				errors <- fmt.Errorf("build %s: %w", scenario.path, err)
				return
			}
			request.Host = "localhost"
			response, err := client.Do(request)
			if err != nil {
				errors <- fmt.Errorf("request %s: %w", scenario.path, err)
				return
			}
			body, err := io.ReadAll(response.Body)
			if err == nil {
				err = response.Body.Close()
			}
			if err != nil {
				errors <- fmt.Errorf("read %s: %w", scenario.path, err)
				return
			}
			if response.StatusCode != http.StatusOK ||
				response.Header.Get("X-Netz-Handler") != "concurrent" ||
				string(body) != scenario.body ||
				response.Trailer.Get("X-Netz-Handler") != "complete" {
				errors <- fmt.Errorf("unexpected %s response: status=%d handler=%q body=%q trailers=%v", scenario.path, response.StatusCode, response.Header.Get("X-Netz-Handler"), body, response.Trailer)
				return
			}
			errors <- nil
		}()
	}
	start.Done()
	for range scenarios {
		if err := <-errors; err != nil {
			log.Fatal(err)
		}
	}
	version := 1
	if *v2Only {
		version = 2
	}
	fmt.Printf("quic-go HTTP/3 clients verified netz handler supervisor: version=%d connections=2 responses=2 bodies=2 trailers=2 concurrent=true client_io=quic-go-netpoll\n", version)
}
