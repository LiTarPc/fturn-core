package config

import (
	"github.com/LiTarPc/fturn-core/internal/tunnel"
	"testing"
)

func TestRegressionOversizedTunnelMTURejected(t *testing.T) {
	c := validClient()
	c.Tunnel = TunnelOpts{Mode: tunnel.ModeWG, Config: "[Interface]", MTU: 9000}
	if err := Validate(c); err == nil {
		t.Error("9000-byte tunnel MTU accepted despite fixed relay buffers 1600/2048")
	}
}
