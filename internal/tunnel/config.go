package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/LiTarPc/fturn-core/internal/transport/limits"
)

// DefaultMTU - безопасный MTU для WireGuard поверх TURN без фрагментации.
const DefaultMTU = 1280

const KeyLen = 32

// Key - 32-байтный ключ WireGuard.
type Key [KeyLen]byte

func (k Key) IsZero() bool { return k == Key{} }

// Peer описывает конфигурацию удалённого узла туннеля.
type Peer struct {
	PublicKey    Key
	PresharedKey Key
	AllowedIPs   []netip.Prefix
	Endpoint     string
	Keepalive    string
}

type Config struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	Peers      []Peer
	Amnezia    AmneziaParams
}

// AmneziaParams содержит параметры обфускации протокола AmneziaWG.
type AmneziaParams struct {
	Jc   int
	Jmin int
	Jmax int

	S1 int
	S2 int
	S3 int
	S4 int

	H1 string
	H2 string
	H3 string
	H4 string

	I [5]string
}

func (p AmneziaParams) Enabled() bool { return p != AmneziaParams{} }

// Defaults возвращает конфигурацию туннеля с дефолтным MTU.
func Defaults() Config {
	return Config{MTU: DefaultMTU}
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("tunnel: nil config")
	}
	if c.PrivateKey.IsZero() {
		return errors.New("tunnel: PrivateKey is required")
	}
	if len(c.Peers) == 0 {
		return errors.New("tunnel: at least one peer is required")
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		if p.PublicKey.IsZero() {
			return fmt.Errorf("tunnel: peer[%d]: PublicKey is required", i)
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("tunnel: peer[%d]: AllowedIPs is required", i)
		}
		if err := ValidateRange(p.Keepalive); err != nil {
			return fmt.Errorf("tunnel: peer[%d]: keepalive: %w", i, err)
		}
	}
	if c.MTU <= 0 {
		return errors.New("tunnel: MTU must be positive")
	}
	return c.Amnezia.validate()
}

func (p AmneziaParams) validate() error {
	if !p.Enabled() {
		return nil
	}
	// Параметры junk (Jc, Jmin, Jmax) должны задаваться совместно.
	junk := []int{p.Jc, p.Jmin, p.Jmax}
	set := 0
	for _, v := range junk {
		if v > 0 {
			set++
		}
	}
	if set != 0 && set != len(junk) {
		return errors.New("tunnel: amnezia Jc/Jmin/Jmax must be set together")
	}
	if p.Jmin > p.Jmax {
		return errors.New("tunnel: amnezia Jmin must not exceed Jmax")
	}
	for _, v := range []int{p.S1, p.S2, p.S3, p.S4} {
		if v < 0 {
			return errors.New("tunnel: amnezia padding must not be negative")
		}
	}
	return nil
}

// ValidateRange проверяет формат диапазона ("N" или "LO-HI"); пустая строка - не задан.
func ValidateRange(s string) error {
	if s == "" {
		return nil
	}
	lo, hi, hasHi := strings.Cut(s, "-")
	low, err := strconv.ParseUint(lo, 10, 32)
	if err != nil {
		return fmt.Errorf("bad lower bound %q", lo)
	}
	if !hasHi {
		return nil
	}
	high, err := strconv.ParseUint(hi, 10, 32)
	if err != nil {
		return fmt.Errorf("bad upper bound %q", hi)
	}
	if high < low {
		return fmt.Errorf("upper bound %d below lower %d", high, low)
	}
	return nil
}

// ValidateRelay enforces the payload limit of existing TURN/DTLS relay servers.
// Direct WG/AWG mode can use a different MTU and does not call this method.
func (c *Config) ValidateRelay() error {
	if c.MTU <= 0 || c.MTU > limits.TunnelMTU {
		return fmt.Errorf("tunnel: relay MTU must be 1..%d", limits.TunnelMTU)
	}
	p := c.Amnezia
	padded := (c.MTU + 15) &^ 15
	if p.S4 > limits.UDPApplication-32-padded {
		return fmt.Errorf("tunnel: MTU and AWG S4 exceed relay payload %d", limits.UDPApplication)
	}
	if p.Jmax > limits.UDPApplication || p.S1 > limits.UDPApplication-148 || p.S2 > limits.UDPApplication-92 || p.S3 > limits.UDPApplication-64 {
		return fmt.Errorf("tunnel: AWG junk/padding exceeds relay payload %d", limits.UDPApplication)
	}
	return nil
}
