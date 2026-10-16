package vkauth

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	"github.com/LiTarPc/fturn-core/internal/statedir"
)

const (
	captchaLimitPause        = 5 * time.Minute
	servicePause             = time.Minute
	captchaPauseFile         = "vk_auth_pause.json"
	pauseRate         uint32 = 1
	pauseService      uint32 = 2
)

var pauseMu sync.Mutex

type pauseState struct {
	Until         int64  `json:"until"`
	Kind          uint32 `json:"kind,omitempty"`
	RateStreak    uint32 `json:"rateStreak,omitempty"`
	ServiceStreak uint32 `json:"serviceStreak,omitempty"`
}

type cooldownStore struct{ paths []string }

func newCooldownStore(personaPaths []string) cooldownStore {
	s := cooldownStore{}
	for _, p := range personaPaths {
		s.paths = append(s.paths, filepath.Join(filepath.Dir(p), captchaPauseFile))
	}
	return s
}
func (s cooldownStore) load() pauseState {
	var state pauseState
	now := time.Now().Unix()
	for _, b := range statedir.ReadEach(s.paths) {
		if len(b) > 1024 {
			continue
		}
		var candidate pauseState
		// Retain expired failure history for a day; reject corrupt future dates.
		if json.Unmarshal(b, &candidate) != nil || candidate.Until < now-86400 || candidate.Until > now+10*365*86400 {
			continue
		}
		if candidate.Until > state.Until {
			state.Until = candidate.Until
			state.Kind = candidate.Kind
		}
		state.RateStreak = max(state.RateStreak, min(candidate.RateStreak, 32))
		state.ServiceStreak = max(state.ServiceStreak, min(candidate.ServiceStreak, 32))
	}
	return state
}
func (s cooldownStore) save(state pauseState) (pauseState, bool) {
	if len(s.paths) == 0 {
		return state, true
	}
	pauseMu.Lock()
	defer pauseMu.Unlock()
	old := s.load()
	if old.Until > state.Until {
		state.Until = old.Until
		state.Kind = old.Kind
	}
	state.RateStreak = max(state.RateStreak, old.RateStreak)
	state.ServiceStreak = max(state.ServiceStreak, old.ServiceStreak)
	data, err := json.Marshal(state)
	return state, err == nil && statedir.WriteFirst(s.paths, data)
}
func (s cooldownStore) clear() bool {
	if len(s.paths) == 0 {
		return true
	}
	pauseMu.Lock()
	defer pauseMu.Unlock()
	// A concurrent client may already have received another provider refusal.
	if s.load().Until > time.Now().Unix() {
		return true
	}
	return statedir.WriteFirst(s.paths, []byte(`{"until":0}`))
}
func (c *Client) restorePause(state pauseState) {
	c.rateLimitStreak.Store(max(c.rateLimitStreak.Load(), state.RateStreak))
	c.serviceFailureStreak.Store(max(c.serviceFailureStreak.Load(), state.ServiceStreak))
	if state.Until > c.captchaPause.Load() {
		c.pauseKind.Store(state.Kind)
		c.captchaPause.Store(state.Until)
		c.lockout.Store(max(state.Until, c.lockout.Load()))
	}
}
func (c *Client) authPauseError() error {
	c.restorePause(c.cooldown.load())
	if c.captchaPause.Load() <= time.Now().Unix() {
		return nil
	}
	reason := captcha.ErrRateLimited
	if c.pauseKind.Load() == pauseService {
		reason = captcha.ErrUnavailable
	}
	return errors.Join(ErrCaptchaWaitRequired, reason)
}
func (c *Client) pauseAuth(streamID int, kind uint32, cause error) error {
	c.restorePause(c.cooldown.load())
	var pause time.Duration
	var streak uint32
	label := "CAPTCHA_RATE_LIMIT"
	reason := captcha.ErrRateLimited
	if kind == pauseService {
		streak = c.serviceFailureStreak.Add(1)
		pause = min(servicePause*time.Duration(1<<min(streak-1, 4)), 15*time.Minute)
		label = "AUTH_SERVICE_UNAVAILABLE"
		reason = captcha.ErrUnavailable
	} else {
		streak = c.rateLimitStreak.Add(1)
		pause = min(captchaLimitPause*time.Duration(1<<min(streak-1, 4)), time.Hour)
	}
	until := time.Now().Add(pause).Unix()
	if retry := captcha.RetryDeadline(cause); !retry.IsZero() {
		until = max(until, retry.Unix()+1)
	}
	until = max(until, c.captchaPause.Load())
	state, ok := c.cooldown.save(pauseState{Until: until, Kind: kind, RateStreak: c.rateLimitStreak.Load(), ServiceStreak: c.serviceFailureStreak.Load()})
	c.pauseKind.Store(state.Kind)
	c.captchaPause.Store(state.Until)
	c.lockout.Store(max(state.Until, c.lockout.Load()))
	if !ok {
		c.log.Warnf("[Messenger Auth] Could not persist auth pause")
	}
	c.log.Warnf("[STREAM %d] [Messenger Auth] %s pause_until=%d streak=%d; persona kept, manual fallback skipped; cause=%v", streamID, label, state.Until, streak, cause)
	// A finite pause remains recoverable even with no connected streams.
	return errors.Join(ErrCaptchaWaitRequired, reason, cause)
}
func (c *Client) authSucceeded() {
	c.rateLimitStreak.Store(0)
	c.serviceFailureStreak.Store(0)
	if !c.cooldown.clear() {
		c.log.Warnf("[Messenger Auth] Could not clear auth failure history")
	}
}
