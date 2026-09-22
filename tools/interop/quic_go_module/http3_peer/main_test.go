package main

import (
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
)

func TestCancellationTraceArmsExactStopSendingDatagram(t *testing.T) {
	dropConn := &cancellationDropConn{}
	trace := &cancellationTrace{dropConn: dropConn}
	exact := qlog.PacketSent{Frames: []qlog.Frame{{Frame: &qlog.StopSendingFrame{
		StreamID: 0, ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled),
	}}}}
	trace.RecordEvent(exact)
	if trace.transmissions.Load() != 0 || dropConn.dropNext.Load() {
		t.Fatal("unarmed trace selected a packet")
	}
	trace.armed.Store(true)
	trace.RecordEvent(qlog.PacketSent{Frames: []qlog.Frame{
		{Frame: &qlog.StopSendingFrame{StreamID: 4, ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled)}},
		{Frame: &qlog.StopSendingFrame{StreamID: 0, ErrorCode: 7}},
	}})
	if trace.transmissions.Load() != 0 || dropConn.dropNext.Load() {
		t.Fatal("trace selected a nonmatching STOP_SENDING frame")
	}
	trace.RecordEvent(exact)
	if trace.transmissions.Load() != 1 || !dropConn.dropNext.Load() {
		t.Fatal("trace did not select the first matching STOP_SENDING packet")
	}
	packet := []byte{1, 2, 3}
	if written, err := dropConn.WriteTo(packet, nil); err != nil || written != len(packet) {
		t.Fatalf("drop write = (%d, %v), want (%d, nil)", written, err, len(packet))
	}
	if dropConn.dropped.Load() != 1 || dropConn.dropNext.Load() {
		t.Fatal("selected packet was not consumed as the only drop")
	}
	trace.RecordEvent(exact)
	if trace.transmissions.Load() != 2 || dropConn.dropNext.Load() {
		t.Fatal("trace did not count a matching retransmission")
	}
}
