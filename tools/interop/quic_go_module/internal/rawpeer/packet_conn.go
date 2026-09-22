package rawpeer

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// BasicPacketConn deliberately exposes only net.PacketConn. It keeps every
// path on quic-go's basic socket implementation, so ECN and OOB capabilities
// cannot change underneath a connection when it migrates to a wrapped socket.
type BasicPacketConn struct {
	net.PacketConn
}

type DropPacketConn struct {
	net.PacketConn
	writeRemaining atomic.Int64
	writeDropped   atomic.Uint64
	writeArmed     atomic.Bool
	readRemaining  atomic.Int64
	readDropped    atomic.Uint64
	readArmed      atomic.Bool
}

func (c *DropPacketConn) ArmOnce(count int64) bool {
	if !c.writeArmed.CompareAndSwap(false, true) {
		return false
	}
	c.writeRemaining.Store(count)
	return true
}

func (c *DropPacketConn) Dropped() uint64 { return c.writeDropped.Load() }

func (c *DropPacketConn) ArmReadOnce(count int64) bool {
	if !c.readArmed.CompareAndSwap(false, true) {
		return false
	}
	c.readRemaining.Store(count)
	return true
}

func (c *DropPacketConn) ReadDropped() uint64 { return c.readDropped.Load() }

func (c *DropPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		n, address, err := c.PacketConn.ReadFrom(payload)
		if err != nil {
			return n, address, err
		}
		for {
			remaining := c.readRemaining.Load()
			if remaining <= 0 {
				return n, address, nil
			}
			if c.readRemaining.CompareAndSwap(remaining, remaining-1) {
				c.readDropped.Add(1)
				break
			}
		}
	}
}

func (c *DropPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	for {
		remaining := c.writeRemaining.Load()
		if remaining <= 0 {
			return c.PacketConn.WriteTo(payload, address)
		}
		if c.writeRemaining.CompareAndSwap(remaining, remaining-1) {
			c.writeDropped.Add(1)
			return len(payload), nil
		}
	}
}

// SwitchablePacketConn keeps quic-go on one transport while replacing the
// socket's source port, matching a NAT rebinding rather than active migration.
type SwitchablePacketConn struct {
	mu        sync.RWMutex
	current   net.PacketConn
	all       []net.PacketConn
	closed    atomic.Bool
	closeOnce sync.Once
	remaining atomic.Int64
	dropped   atomic.Uint64
}

func NewSwitchablePacketConn(connection net.PacketConn) *SwitchablePacketConn {
	return &SwitchablePacketConn{current: connection, all: []net.PacketConn{connection}}
}

func (c *SwitchablePacketConn) Switch(connection net.PacketConn, dropWrites int64) {
	c.mu.Lock()
	previous := c.current
	c.current = connection
	c.all = append(c.all, connection)
	c.mu.Unlock()
	c.remaining.Store(dropWrites)
	// Wake a read already blocked on the old socket. ReadFrom treats the
	// resulting timeout as a signal to load the newly selected socket.
	_ = previous.SetReadDeadline(time.Now())
}

func (c *SwitchablePacketConn) Dropped() uint64 { return c.dropped.Load() }

func (c *SwitchablePacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		c.mu.RLock()
		connection := c.current
		c.mu.RUnlock()
		_ = connection.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
		n, address, err := connection.ReadFrom(payload)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			continue
		}
		return n, address, err
	}
}

func (c *SwitchablePacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	for {
		remaining := c.remaining.Load()
		if remaining <= 0 {
			break
		}
		if c.remaining.CompareAndSwap(remaining, remaining-1) {
			c.dropped.Add(1)
			return len(payload), nil
		}
	}
	c.mu.RLock()
	connection := c.current
	c.mu.RUnlock()
	return connection.WriteTo(payload, address)
}

func (c *SwitchablePacketConn) Close() error {
	var first error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.mu.Lock()
		connections := append([]net.PacketConn(nil), c.all...)
		c.mu.Unlock()
		for _, connection := range connections {
			if err := connection.Close(); err != nil &&
				!errors.Is(err, net.ErrClosed) && first == nil {
				first = err
			}
		}
	})
	return first
}

func (c *SwitchablePacketConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current.LocalAddr()
}

func (c *SwitchablePacketConn) SetDeadline(deadline time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var first error
	for _, connection := range c.all {
		if err := connection.SetDeadline(deadline); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *SwitchablePacketConn) SetReadDeadline(deadline time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var first error
	for _, connection := range c.all {
		if err := connection.SetReadDeadline(deadline); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *SwitchablePacketConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current.SetWriteDeadline(deadline)
}
