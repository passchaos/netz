package rawpeer

import (
	"testing"

	"github.com/quic-go/quic-go/qlog"
)

func TestTraceCallsPathResponseCallbackOnce(t *testing.T) {
	trace := &Trace{}
	calls := 0
	trace.SetPathResponseCallback(func() { calls++ })
	trace.RecordEvent(qlog.PacketSent{Frames: []qlog.Frame{{
		Frame: &qlog.StreamFrame{StreamID: 0, Length: 5},
	}}})
	if calls != 0 {
		t.Fatalf("callback calls after STREAM = %d, want 0", calls)
	}
	trace.RecordEvent(qlog.PacketSent{Frames: []qlog.Frame{{
		Frame: &qlog.PathResponseFrame{},
	}}})
	trace.RecordEvent(qlog.PacketSent{Frames: []qlog.Frame{{
		Frame: &qlog.PathResponseFrame{},
	}}})
	if calls != 1 {
		t.Fatalf("callback calls after PATH_RESPONSE packets = %d, want 1", calls)
	}
}

func TestTraceCountsReceivedPathChallenges(t *testing.T) {
	trace := &Trace{}
	trace.RecordEvent(qlog.PacketReceived{Frames: []qlog.Frame{
		{Frame: &qlog.PathChallengeFrame{}},
		{Frame: &qlog.StreamFrame{StreamID: 0, Length: 5}},
		{Frame: &qlog.PathChallengeFrame{}},
	}})
	if trace.PathChallenges() != 2 {
		t.Fatalf("path challenges = %d, want 2", trace.PathChallenges())
	}
}
