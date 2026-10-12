package sockettraffic

import "testing"

func TestStatsSinceAndAdd(t *testing.T) {
	previous := Stats{
		SentDatagrams: 2, SentBytes: 20,
		ReceivedDatagrams: 3, ReceivedBytes: 30,
	}
	current := Stats{
		SentDatagrams: 7, SentBytes: 75,
		ReceivedDatagrams: 11, ReceivedBytes: 118,
	}
	delta := current.Since(previous)
	want := Stats{
		SentDatagrams: 5, SentBytes: 55,
		ReceivedDatagrams: 8, ReceivedBytes: 88,
	}
	if delta != want {
		t.Fatalf("unexpected delta: got=%+v want=%+v", delta, want)
	}
	if total := previous.Add(want); total != current {
		t.Fatalf("unexpected sum: got=%+v want=%+v", total, current)
	}
}

func TestCountersIgnoreZeroProgress(t *testing.T) {
	conn := &UDPConn{}
	conn.recordSent(0)
	conn.recordReceived(0)
	if stats := conn.Stats(); stats != (Stats{}) {
		t.Fatalf("zero progress changed counters: %+v", stats)
	}
	conn.recordSent(11)
	conn.recordReceived(13)
	want := Stats{
		SentDatagrams: 1, SentBytes: 11,
		ReceivedDatagrams: 1, ReceivedBytes: 13,
	}
	if stats := conn.Stats(); stats != want {
		t.Fatalf("unexpected counters: got=%+v want=%+v", stats, want)
	}
}
