// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type listenerFailurePacket struct {
	data []byte
	err  error
}

type listenerFailureConn struct {
	net.PacketConn
	inbound chan listenerFailurePacket
	written chan struct{}
	once    sync.Once
}

func (c *listenerFailureConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	packet := <-c.inbound
	return copy(buf, packet.data), c.LocalAddr(), packet.err
}

func (c *listenerFailureConn) WriteTo(buf []byte, _ net.Addr) (int, error) {
	c.once.Do(func() { close(c.written) })
	return len(buf), nil
}

func TestListenerFailureCancelsTransactionsAndNotifies(t *testing.T) {
	for _, test := range []struct {
		name   string
		packet listenerFailurePacket
	}{
		{name: "transport read error", packet: listenerFailurePacket{err: io.ErrUnexpectedEOF}},
		{name: "inbound handling error", packet: listenerFailurePacket{data: []byte("invalid TURN packet")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			conn := &listenerFailureConn{PacketConn: raw, inbound: make(chan listenerFailurePacket, 1), written: make(chan struct{})}
			notified := make(chan error, 1)
			c, err := NewClient(&ClientConfig{
				Conn:           conn,
				STUNServerAddr: raw.LocalAddr().String(),
				// A pending transaction would otherwise wait for retransmission timeouts.
				RTO:             time.Hour,
				OnListenerError: func(err error) { notified <- err },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.Listen(); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { _, err := c.SendBindingRequest(); result <- err }()
			select {
			case <-conn.written:
			case <-time.After(time.Second):
				t.Fatal("transaction was not sent")
			}
			conn.inbound <- test.packet
			select {
			case err := <-notified:
				if err == nil {
					t.Fatal("missing listener error")
				}
				if test.packet.err != nil && !errors.Is(err, test.packet.err) {
					t.Fatalf("error = %v", err)
				}
				if c.trMap.Size() != 0 {
					t.Fatal("pending transaction retained after listener exit")
				}
			case <-time.After(time.Second):
				t.Fatal("listener failure was not reported promptly")
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("pending transaction succeeded after receiver stopped")
				}
			case <-time.After(time.Second):
				t.Fatal("pending transaction was not canceled")
			}
		})
	}
}
