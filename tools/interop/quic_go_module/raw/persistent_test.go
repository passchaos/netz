package main

import "testing"

func TestPersistentConfigAndChecksum(t *testing.T) {
	c := persistentConfig{
		mode: "aggregate", rolePair: "netz-client+quic-go-server",
		sender: senderClient, run: 1, connections: 4, warmup: 0,
		iterations: 1, streams: 4, bytesPerStream: 65536, payloadBytes: 1024,
		chunkBytes: 16384, streamWindow: 1048576, timeout: 30000000000,
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if got, want := c.aggregateBytes(), uint64(1048576); got != want {
		t.Fatalf("aggregate bytes=%d want=%d", got, want)
	}
	first := make([]byte, 1024)
	second := make([]byte, 1024)
	if got, want := fillPersistentEchoPayload(first, 0), uint64(130560); got != want {
		t.Fatalf("first checksum=%d want=%d", got, want)
	}
	if got, want := fillPersistentEchoPayload(second, 1), uint64(130560); got != want {
		t.Fatalf("second checksum=%d want=%d", got, want)
	}
	if string(first) == string(second) {
		t.Fatal("sequence-distinct payloads matched")
	}
	c.mode = "echo"
	c.connections = 1
	c.streams = 1
	c.iterations = 100001
	if err := c.validate(); err == nil {
		t.Fatal("oversized echo iteration count accepted")
	}
}

func TestPersistentStartRecordRoundTrip(t *testing.T) {
	c := config{
		warmup: 0, iterations: 1, streams: 4, bytesPerStream: 65536,
		chunkBytes: 16384, streamWindow: 1048576, timeout: 30000000000,
	}
	encoded := (record{kind: kindGo, sender: senderServer, round: 3, config: c}).encode()
	decoded, err := decodeRecord(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRecord(decoded, kindGo, senderServer, 3, c); err != nil {
		t.Fatal(err)
	}
}
