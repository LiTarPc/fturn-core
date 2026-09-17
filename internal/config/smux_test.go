package config

import (
	"io"
	"strings"
	"testing"

	"github.com/samosvalishe/free-turn-proxy/internal/transport/kcpmux"
)

func TestParseServerSmuxProfileDefault(t *testing.T) {
	s, err := ParseServer([]string{"-connect", "x:1", "-mode", "tcp"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if s.Smux.Profile != kcpmux.SmuxProfileMedium {
		t.Fatalf("Smux.Profile=%q, want %q", s.Smux.Profile, kcpmux.SmuxProfileMedium)
	}
	if got := kcpmux.SmuxFrameSize(s.Smux.Profile); got != 16*1024 {
		t.Fatalf("Smux frame=%d, want %d", got, 16*1024)
	}
}

func TestParseServerSmuxProfiles(t *testing.T) {
	cases := []struct {
		name    string
		profile kcpmux.SmuxProfile
		frame   int
	}{
		{"low", kcpmux.SmuxProfileLow, 8 * 1024},
		{"medium", kcpmux.SmuxProfileMedium, 16 * 1024},
		{"high", kcpmux.SmuxProfileHigh, 32 * 1024},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParseServer([]string{
				"-connect", "x:1",
				"-mode", "tcp",
				"-smux-profile", string(tc.profile),
			}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if s.Smux.Profile != tc.profile {
				t.Fatalf("Smux.Profile=%q, want %q", s.Smux.Profile, tc.profile)
			}
			if got := kcpmux.SmuxFrameSize(s.Smux.Profile); got != tc.frame {
				t.Fatalf("Smux frame=%d, want %d", got, tc.frame)
			}
		})
	}
}

func TestParseServerSmuxProfileInvalid(t *testing.T) {
	_, err := ParseServer([]string{
		"-connect", "x:1",
		"-mode", "tcp",
		"-smux-profile", "turbo",
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-smux-profile") {
		t.Fatalf("expected smux profile validation error, got %v", err)
	}
}
