package rawpeer

import (
	"errors"
	"net"
	"testing"
	"time"
)

func udpPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	return first, second
}

func TestDropPacketConnDropsExactlyArmedWrites(t *testing.T) {
	sender, receiver := udpPair(t)
	defer sender.Close()
	defer receiver.Close()
	dropper := &DropPacketConn{PacketConn: sender}
	if !dropper.ArmOnce(2) || dropper.ArmOnce(1) {
		t.Fatal("write fault arming was not one-shot")
	}
	for _, payload := range []string{"drop-1", "drop-2", "deliver"} {
		if _, err := dropper.WriteTo([]byte(payload), receiver.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	if dropper.Dropped() != 2 {
		t.Fatalf("dropped = %d, want 2", dropper.Dropped())
	}
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	count, _, err := receiver.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "deliver" {
		t.Fatalf("payload = %q, want deliver", buffer[:count])
	}
}

func TestDropPacketConnDropsExactlyArmedReads(t *testing.T) {
	receiver, sender := udpPair(t)
	defer receiver.Close()
	defer sender.Close()
	dropper := &DropPacketConn{PacketConn: receiver}
	if !dropper.ArmReadOnce(2) || dropper.ArmReadOnce(1) {
		t.Fatal("read fault arming was not one-shot")
	}
	for _, payload := range []string{"drop-1", "drop-2", "deliver"} {
		if _, err := sender.WriteToUDP([]byte(payload), receiver.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	count, _, err := dropper.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "deliver" || dropper.ReadDropped() != 2 {
		t.Fatalf("payload = %q, dropped = %d", buffer[:count], dropper.ReadDropped())
	}
}

func TestSwitchablePacketConnChangesTupleAndWakesReader(t *testing.T) {
	first, peer := udpPair(t)
	defer peer.Close()
	switcher := NewSwitchablePacketConn(first)
	defer switcher.Close()
	original := switcher.LocalAddr().String()
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		count, _, err := switcher.ReadFrom(buffer)
		if err == nil && string(buffer[:count]) != "rebound" {
			err = &net.AddrError{Err: "unexpected payload", Addr: string(buffer[:count])}
		}
		done <- err
	}()
	replacement, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	switcher.Switch(replacement, 0)
	if switcher.LocalAddr().String() == original {
		t.Fatal("source tuple did not change")
	}
	if _, err := peer.WriteToUDP([]byte("rebound"), replacement.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not move to replacement socket")
	}
}

func TestSwitchablePacketConnCloseWakesReader(t *testing.T) {
	connection, peer := udpPair(t)
	defer peer.Close()
	switcher := NewSwitchablePacketConn(connection)
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, _, err := switcher.ReadFrom(buffer)
		done <- err
	}()
	if err := switcher.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake blocked reader")
	}
}
