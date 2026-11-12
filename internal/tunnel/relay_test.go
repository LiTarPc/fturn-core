package tunnel

import (
	"github.com/LiTarPc/fturn-core/internal/transport/limits"
	"testing"
)

func TestValidateRelayPayloadEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Config
		bad  bool
	}{
		{"default", Config{MTU: 1280}, false}, {"upper_bound", Config{MTU: limits.TunnelMTU}, false}, {"oversized", Config{MTU: 9000}, true},
		{"awg_data_padding", Config{MTU: limits.TunnelMTU, Amnezia: AmneziaParams{S4: 1}}, true},
		{"awg_junk", Config{MTU: 1280, Amnezia: AmneziaParams{Jmax: limits.UDPApplication + 1}}, true},
		{"awg_handshake_padding", Config{MTU: 1280, Amnezia: AmneziaParams{S1: limits.UDPApplication}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.ValidateRelay(); (err != nil) != tc.bad {
				t.Fatalf("ValidateRelay=%v", err)
			}
		})
	}
}
