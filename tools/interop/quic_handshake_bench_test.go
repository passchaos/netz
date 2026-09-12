package main

import (
	"testing"
	"time"
)

func TestHandshakeConfigValidation(t *testing.T) {
	valid := handshakeConfig{
		rolePair: "netz-client+quic-go-server", warmup: 10,
		iterations: 100, run: 1, timeout: 10 * time.Second,
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.iterations = 0
	if invalid.validate() == nil {
		t.Fatal("accepted zero measured iterations")
	}
}

func TestHandshakeMarkerIncludesRound(t *testing.T) {
	first := marker(0)
	second := marker(1)
	if first == second || string(first[:8]) != "NZQHSB1\x00" {
		t.Fatal("invalid handshake marker")
	}
}

func TestHandshakePercentileConvention(t *testing.T) {
	values := []uint64{1, 2, 3, 4, 5}
	if percentile(values, 50) != 3 || percentile(values, 99) != 5 {
		t.Fatal("unexpected percentile")
	}
}
