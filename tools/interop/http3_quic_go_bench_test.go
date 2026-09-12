package main

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestLocalhostCertificateUsesSeparateServerLeaf(t *testing.T) {
	certificate, caPEM, err := localhostCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) != 2 {
		t.Fatalf("certificate chain length = %d, want 2", len(certificate.Certificate))
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(certificate.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatalf("invalid server leaf usage: is_ca=%t key_usage=%v", leaf.IsCA, leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("invalid server leaf EKU: %v", leaf.ExtKeyUsage)
	}
	if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("invalid CA usage: is_ca=%t key_usage=%v", ca.IsCA, ca.KeyUsage)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || len(rest) != 0 || string(block.Bytes) != string(certificate.Certificate[1]) {
		t.Fatal("returned trust PEM is not the chain CA")
	}
}

func multiStreamTestConfig() benchConfig {
	return benchConfig{
		mode: "upload", version: 1, streams: 4, warmup: 1, iterations: 2,
		bodyBytes: 1000, chunkBytes: 1000, streamWindow: 65536,
		timeout: time.Second,
	}
}

func TestMultiStreamConfigAndChecksum(t *testing.T) {
	c := multiStreamTestConfig()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.totalBytes() != 4000 || c.connectionWindow() != 8*65536 {
		t.Fatalf("unexpected aggregate shape bytes=%d window=%d", c.totalBytes(), c.connectionWindow())
	}
	if streamChecksum(c.bodyBytes, 0) == streamChecksum(c.bodyBytes, 1) {
		t.Fatal("stream-index payload checksums must differ for this shape")
	}
	invalid := c
	invalid.streams = 2
	if invalid.validate() == nil {
		t.Fatal("unsupported stream count accepted")
	}
	invalid = c
	invalid.version = 3
	if invalid.validate() == nil {
		t.Fatal("unsupported QUIC version accepted")
	}
	c.version = 2
	if versions := c.quicConfig().Versions; len(versions) != 1 || versions[0] != quic.Version2 {
		t.Fatalf("QUIC v2 config mismatch: %v", versions)
	}
}

func TestRoundTrackerBarrierAndUniqueness(t *testing.T) {
	tracker := newRoundTracker(multiStreamTestConfig())
	var ready <-chan struct{}
	for index := uint64(0); index < 4; index++ {
		channel, err := tracker.begin(0, index)
		if err != nil {
			t.Fatal(err)
		}
		ready = channel
		if index < 3 {
			select {
			case <-ready:
				t.Fatal("barrier released before every stream entered")
			default:
			}
		}
	}
	select {
	case <-ready:
	default:
		t.Fatal("barrier remained closed after every stream entered")
	}
	if _, err := tracker.begin(0, 0); err == nil {
		t.Fatal("duplicate stream index accepted")
	}
	for index := uint64(0); index < 4; index++ {
		roundDone, allDone, err := tracker.finish(0, index)
		if err != nil {
			t.Fatal(err)
		}
		if roundDone != (index == 3) || allDone {
			t.Fatalf("unexpected completion flags at index %d", index)
		}
	}
}
