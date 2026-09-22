package main

import (
	"testing"
	"time"
)

func testRawChurnConfig() rawChurnConfig {
	return rawChurnConfig{
		sender: senderServer, fault: "reorder", streams: 32,
		bytesPerStream: 16 * 1024, resetAfterBytes: 256, resetEvery: 2,
		timeout: 30 * time.Second, streamWindow: 16 * 1024,
	}
}

func TestRawChurnConfigRoundTripAndReservedBytes(t *testing.T) {
	c := testRawChurnConfig()
	encoded := c.encode()
	decoded, err := decodeRawChurnConfig(&encoded)
	if err != nil || decoded != c {
		t.Fatalf("config round trip: decoded=%+v err=%v", decoded, err)
	}
	encoded[30] = 1
	if _, err := decodeRawChurnConfig(&encoded); err == nil {
		t.Fatal("nonzero reserved config byte accepted")
	}
}

func TestRawChurnExpectedResults(t *testing.T) {
	c := testRawChurnConfig()
	want := rawChurnResult{
		streams: 32, fins: 16, resets: 16, receivedBytes: 266240,
		checksum: 33945600, resetMask: 0xaaaaaaaa, resetCodeSum: 262400,
	}
	if got := expectedRawChurnResult(c); got != want {
		t.Fatalf("32-stream shape: got=%+v want=%+v", got, want)
	}
	c.streams = 64
	want = rawChurnResult{
		streams: 64, fins: 32, resets: 32, receivedBytes: 532480,
		checksum: 67891200, resetMask: 0xaaaaaaaaaaaaaaaa, resetCodeSum: 525312,
	}
	if got := expectedRawChurnResult(c); got != want {
		t.Fatalf("64-stream shape: got=%+v want=%+v", got, want)
	}
}

func TestRawChurnResultRoundTripAndReservedBytes(t *testing.T) {
	r := expectedRawChurnResult(testRawChurnConfig())
	encoded := r.encode()
	decoded, err := decodeRawChurnResult(&encoded)
	if err != nil || decoded != r {
		t.Fatalf("result round trip: decoded=%+v err=%v", decoded, err)
	}
	encoded[14] = 1
	if _, err := decodeRawChurnResult(&encoded); err == nil {
		t.Fatal("nonzero reserved result byte accepted")
	}
}

func TestRawChurnFaultAccountingRequiresBothPhases(t *testing.T) {
	if err := validateRawChurnFaults("loss", rawProxyStats{considered: 1, dropped: 1}, rawProxyStats{considered: 1, dropped: 1}); err != nil {
		t.Fatal(err)
	}
	if err := validateRawChurnFaults("loss", rawProxyStats{dropped: 1}, rawProxyStats{}); err == nil {
		t.Fatal("accepted FIN phase without a drop")
	}
	if err := validateRawChurnFaults("reorder", rawProxyStats{considered: 2, held: 1, reordered: 1}, rawProxyStats{considered: 2, held: 1, reordered: 1}); err != nil {
		t.Fatal(err)
	}
	if err := validateRawChurnFaults("reorder", rawProxyStats{considered: 2, held: 1}, rawProxyStats{considered: 2, held: 1, reordered: 1}); err == nil {
		t.Fatal("accepted unreleased reorder")
	}
}
