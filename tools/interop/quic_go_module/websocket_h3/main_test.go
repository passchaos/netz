package main

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestBenchmarkConfigSelectsQUICVersion(t *testing.T) {
	for _, test := range []struct {
		v2Only bool
		want   quic.Version
	}{
		{v2Only: false, want: quic.Version1},
		{v2Only: true, want: quic.Version2},
	} {
		config := benchmarkConfig{
			v2Only: test.v2Only, warmup: 1, iterations: 2,
			payloadBytes: 16, timeout: time.Second,
		}
		versions := benchmarkQUICConfig(config).Versions
		if len(versions) != 1 || versions[0] != test.want {
			t.Fatalf("v2Only=%t versions=%v, want [%v]", test.v2Only, versions, test.want)
		}
		wantNumber := 1
		if test.v2Only {
			wantNumber = 2
		}
		if config.versionNumber() != wantNumber {
			t.Fatalf("v2Only=%t version number=%d, want %d", test.v2Only, config.versionNumber(), wantNumber)
		}
	}
}
