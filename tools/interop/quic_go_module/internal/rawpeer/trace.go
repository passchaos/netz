package rawpeer

import (
	"sync"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type Trace struct {
	mu             sync.Mutex
	onPathResponse func()
	pathChallenges int
}

func (t *Trace) AddProducer() qlogwriter.Recorder { return t }
func (t *Trace) SupportsSchemas(string) bool      { return true }
func (t *Trace) Close() error                     { return nil }

func (t *Trace) SetPathResponseCallback(callback func()) {
	t.mu.Lock()
	t.onPathResponse = callback
	t.mu.Unlock()
}

func (t *Trace) RecordEvent(event qlogwriter.Event) {
	var callback func()
	t.mu.Lock()
	if value, ok := event.(qlog.PacketSent); ok {
		for _, frame := range value.Frames {
			if _, ok := frame.Frame.(*qlog.PathResponseFrame); ok {
				callback = t.onPathResponse
				t.onPathResponse = nil
			}
		}
	} else if value, ok := event.(qlog.PacketReceived); ok {
		for _, frame := range value.Frames {
			if _, ok := frame.Frame.(*qlog.PathChallengeFrame); ok {
				t.pathChallenges++
			}
		}
	}
	t.mu.Unlock()
	if callback != nil {
		callback()
	}
}

func (t *Trace) PathChallenges() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pathChallenges
}
