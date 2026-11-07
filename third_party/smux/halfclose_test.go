package smux

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestHalfCloseRetainsUnreadReply(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			a, b := net.Pipe()
			cfg := DefaultConfig()
			cfg.Version = version
			cfg.KeepAliveDisabled = true
			c, e := Client(a, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			s, e := Server(b, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			request, e := c.OpenStream()
			if e != nil {
				t.Fatal(e)
			}
			_ = request.SetDeadline(time.Now().Add(3 * time.Second))
			response, e := s.AcceptStream()
			if e != nil {
				t.Fatal(e)
			}
			_ = response.SetDeadline(time.Now().Add(3 * time.Second))
			finished := make(chan error, 1)
			want := bytes.Repeat([]byte("late-reply"), 8192)
			go func() {
				_, e := io.ReadAll(response)
				if e == nil {
					_, e = response.Write(want)
				}
				if e == nil {
					e = response.CloseWrite()
				}
				finished <- e
			}()
			if _, e = request.Write([]byte("request")); e != nil {
				t.Fatal(e)
			}
			if e = request.CloseWrite(); e != nil {
				t.Fatal(e)
			}
			time.Sleep(20 * time.Millisecond)
			got, e := io.ReadAll(request)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("reply bytes=%d want=%d", len(got), len(want))
			}
			if e = <-finished; e != nil {
				t.Fatal(e)
			}
		})
	}
}
