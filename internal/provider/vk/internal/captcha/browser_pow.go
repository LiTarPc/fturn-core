// Browser PoW support adapted from hackdiaz-dev/free-turn-proxy v4.1.0,
// commit 465486ba96c4c2ff93443682ec900510b2e0ff9e (HBL; see third_party/licenses/free-turn-proxy-HBL.txt).
package captcha

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"strconv"
	"strings"
)

var ErrInvalidBrowserPow = errors.New("invalid or mismatched browser PoW")

func validateBrowserPow(value string, p powParams) (resultValue string, resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = ErrInvalidBrowserPow
		}
	}()
	if len(value) > 128*1024 {
		return "", ErrInvalidBrowserPow
	}
	if p.Difficulty <= 0 || p.Difficulty > sha256.Size*2 {
		return "", fmt.Errorf("invalid browser pow difficulty %d", p.Difficulty)
	}
	if !strings.HasPrefix(value, p.Prefix) {
		return "", errors.New("browser pow prefix does not match captcha page")
	}
	var result powResult
	payload, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, p.Prefix))
	if decodeErr != nil {
		return "", ErrInvalidBrowserPow
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return "", ErrInvalidBrowserPow
	}
	if result.Error != "" || result.DurationMs < 0 {
		return "", ErrInvalidBrowserPow
	}
	if len(result.Hash) != 64 || result.Nonce < 0 || !strings.HasPrefix(result.Hash, strings.Repeat("0", p.Difficulty)) {
		return "", errors.New("browser pow hash does not satisfy captcha difficulty")
	}
	sum := sha256.Sum256([]byte(p.Input + strconv.Itoa(result.Nonce)))
	if hex.EncodeToString(sum[:]) != result.Hash {
		return "", errors.New("browser pow does not match captcha page input")
	}
	var telemetryObject map[string]json.RawMessage
	if len(result.Telemetry) == 0 || json.Unmarshal(result.Telemetry, &telemetryObject) != nil || telemetryObject == nil {
		return "", errors.New("browser pow has no telemetry")
	}
	telHash, err := telemetryHash(result.Telemetry)
	if err != nil {
		return "", fmt.Errorf("browser pow telemetry: %w", err)
	}
	if result.TelHash != telHash {
		return "", errors.New("browser pow telemetry hash mismatch")
	}
	return value, nil
}

func profileFromBrowserPow(profile browserprofile.Profile, value string) browserprofile.Profile {
	var envelope struct {
		Telemetry struct {
			UA struct {
				Result struct {
					UserAgent     string `json:"userAgent"`
					UserAgentData *struct {
						Brands   []browserprofile.Brand `json:"brands"`
						Platform string                 `json:"platform"`
						Mobile   bool                   `json:"mobile"`
					} `json:"userAgentData"`
				} `json:"result"`
			} `json:"ua"`
		} `json:"telemetry"`
	}
	if json.Unmarshal([]byte(DecodePowEnvelope(value)), &envelope) != nil {
		return profile
	}
	ua := envelope.Telemetry.UA.Result
	if ua.UserAgent != "" && len(ua.UserAgent) <= 1024 && !strings.ContainsAny(ua.UserAgent, "\r\n") {
		profile.UserAgent = ua.UserAgent
	}
	if data := ua.UserAgentData; data != nil {
		if len(data.Brands) > 0 {
			brands := make([]string, 0, len(data.Brands))
			for _, brand := range data.Brands {
				brands = append(brands, fmt.Sprintf("%q;v=%q", brand.Brand, brand.Version))
			}
			profile.SecChUa = strings.Join(brands, ", ")
		}
		profile.SecChUaPlatform = fmt.Sprintf("%q", data.Platform)
		if data.Mobile {
			profile.SecChUaMobile = "?1"
		} else {
			profile.SecChUaMobile = "?0"
		}
	}
	return profile
}
