// Package sockettraffic records userspace UDP payload traffic without hiding
// the optimized socket methods used by quic-go.
package sockettraffic

import (
	"net"
	"sync/atomic"

	"golang.org/x/net/ipv4"
)

// Stats is one snapshot of successfully sent and received UDP payloads.
type Stats struct {
	SentDatagrams     uint64
	SentBytes         uint64
	ReceivedDatagrams uint64
	ReceivedBytes     uint64
}

// Since returns the wrapping-counter delta from a previous snapshot.
func (current Stats) Since(previous Stats) Stats {
	return Stats{
		SentDatagrams:     current.SentDatagrams - previous.SentDatagrams,
		SentBytes:         current.SentBytes - previous.SentBytes,
		ReceivedDatagrams: current.ReceivedDatagrams - previous.ReceivedDatagrams,
		ReceivedBytes:     current.ReceivedBytes - previous.ReceivedBytes,
	}
}

// Add combines independent socket snapshots.
func (current Stats) Add(other Stats) Stats {
	return Stats{
		SentDatagrams:     current.SentDatagrams + other.SentDatagrams,
		SentBytes:         current.SentBytes + other.SentBytes,
		ReceivedDatagrams: current.ReceivedDatagrams + other.ReceivedDatagrams,
		ReceivedBytes:     current.ReceivedBytes + other.ReceivedBytes,
	}
}

// UDPConn preserves quic-go's OOB/ECN and recvmmsg interfaces while recording
// complete UDP payloads at the userspace socket boundary. Callers comparing
// logical datagrams must disable UDP GSO.
type UDPConn struct {
	*net.UDPConn
	batch             *ipv4.PacketConn
	sentDatagrams     atomic.Uint64
	sentBytes         atomic.Uint64
	receivedDatagrams atomic.Uint64
	receivedBytes     atomic.Uint64
}

func New(conn *net.UDPConn) *UDPConn {
	return &UDPConn{UDPConn: conn, batch: ipv4.NewPacketConn(conn)}
}

func (conn *UDPConn) Stats() Stats {
	return Stats{
		SentDatagrams:     conn.sentDatagrams.Load(),
		SentBytes:         conn.sentBytes.Load(),
		ReceivedDatagrams: conn.receivedDatagrams.Load(),
		ReceivedBytes:     conn.receivedBytes.Load(),
	}
}

func (conn *UDPConn) recordSent(bytes int) {
	if bytes <= 0 {
		return
	}
	conn.sentDatagrams.Add(1)
	conn.sentBytes.Add(uint64(bytes))
}

func (conn *UDPConn) recordReceived(bytes int) {
	if bytes <= 0 {
		return
	}
	conn.receivedDatagrams.Add(1)
	conn.receivedBytes.Add(uint64(bytes))
}

func (conn *UDPConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, address, err := conn.UDPConn.ReadFrom(packet)
	conn.recordReceived(n)
	return n, address, err
}

func (conn *UDPConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	n, err := conn.UDPConn.WriteTo(packet, address)
	conn.recordSent(n)
	return n, err
}

func (conn *UDPConn) ReadMsgUDP(packet, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, address, err := conn.UDPConn.ReadMsgUDP(packet, oob)
	conn.recordReceived(n)
	return n, oobn, flags, address, err
}

func (conn *UDPConn) WriteMsgUDP(packet, oob []byte, address *net.UDPAddr) (int, int, error) {
	n, oobn, err := conn.UDPConn.WriteMsgUDP(packet, oob, address)
	conn.recordSent(n)
	return n, oobn, err
}

func (conn *UDPConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	n, err := conn.batch.ReadBatch(messages, flags)
	var bytes uint64
	for index := 0; index < n; index++ {
		bytes += uint64(messages[index].N)
	}
	if n > 0 {
		conn.receivedDatagrams.Add(uint64(n))
		conn.receivedBytes.Add(bytes)
	}
	return n, err
}
