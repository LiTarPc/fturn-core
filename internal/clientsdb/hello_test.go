package clientsdb

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestClientHelloRoundTrip(t *testing.T) {
	for _, mode := range []byte{ModeUDP, ModeTCP} {
		for _, stream := range []uint32{0, 1, 4, 0xffffffff} {
			for _, id := range []string{"client", strings.Repeat("a", 255)} {
				left, right := net.Pipe()
				writeDone := make(chan error, 1)
				go func() { writeDone <- WriteClientHello(left, id, mode, stream) }()
				gotID, gotMode, gotStream, err := ReadClientHello(right)
				_ = left.Close()
				_ = right.Close()
				if err != nil || gotID != id || gotMode != mode || gotStream != stream {
					t.Fatalf("hello=%q/%d/%d err=%v", gotID, gotMode, gotStream, err)
				}
				if err := <-writeDone; err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestClientHelloRejectsTruncatedExtension(t *testing.T) {
	for _, extra := range []int{2, 3, 4, 6} {
		left, right := net.Pipe()
		go func() { _, _ = left.Write(append([]byte{1, 'a'}, make([]byte, extra)...)) }()
		_, _, _, err := ReadClientHello(right)
		_ = left.Close()
		_ = right.Close()
		if err == nil {
			t.Fatalf("accepted extension length %d", extra)
		}
	}
}

type shortHelloConn struct{ net.Conn }

func (shortHelloConn) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestClientHelloDetectsShortWrite(t *testing.T) {
	if err := WriteClientHello(shortHelloConn{}, "client", ModeUDP, 3); err != io.ErrShortWrite {
		t.Fatalf("short write err=%v", err)
	}
}

func TestClientStreamRejectsInvalidID(t *testing.T) {
	for _, id := range []int{-1, 0} {
		if err := WriteClientStream(nil, "client", ModeUDP, id); err == nil {
			t.Fatalf("accepted invalid stream id %d", id)
		}
	}
}
