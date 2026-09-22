package main

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

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
