package vkauth

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

func temporaryProviderError() error {
	return captcha.ResponseError("captchaNotRobot.check", 200, "", map[string]any{"error": map[string]any{"error_code": 10, "subcode": 5}})
}

func TestTenConcurrentReconnectsShareOneServiceRefusal(t *testing.T) {
	for _, streams := range []int32{0, 2} {
		t.Run(string(rune('0'+streams)), func(t *testing.T) {
			var automatic, manual, chains atomic.Int32
			c := New(Config{StreamsPerCache: 1, StatePaths: statePaths(t), FingerprintSeed: "fixed-install", StreamsAlive: func() int32 { return streams }})
			// The refusal must be returned before the ordinary per-fetch throttle.
			c.minFetchIntervalFn = func() time.Duration { return time.Hour }
			c.autoSolver = func(context.Context, *captcha.Error, int, tlsclient.HttpClient, browserprofile.Profile) (string, error) {
				automatic.Add(1)
				return "", temporaryProviderError()
			}
			c.manualSolve = func(context.Context, *captcha.Error, net.Dialer, browserprofile.Profile) (string, error) {
				manual.Add(1)
				return "", errors.New("unexpected manual solver")
			}
			c.tokenChain = func(ctx context.Context, _ string, id int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
				chains.Add(1)
				_, err := c.solveCaptcha(ctx, nil, c.currentPersona(), id, "link", "name", "token", testCaptchaErr())
				return "", "", nil, err
			}
			kept := c.currentPersona()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			start := make(chan struct{})
			results := make(chan error, 10)
			var wg sync.WaitGroup
			for id := 1; id <= 10; id++ {
				wg.Go(func() { <-start; _, _, _, err := c.GetCredentials(ctx, "link", id); results <- err })
			}
			close(start)
			wg.Wait()
			close(results)
			for err := range results {
				if !errors.Is(err, ErrCaptchaWaitRequired) || !errors.Is(err, captcha.ErrUnavailable) || errors.Is(err, ErrFatalCaptchaNoStreams) || errors.Is(err, ErrPersonaBurned) {
					t.Errorf("err=%v", err)
				}
			}
			if automatic.Load() != 1 || chains.Load() != 1 || manual.Load() != 0 {
				t.Fatalf("auto=%d chains=%d manual=%d", automatic.Load(), chains.Load(), manual.Load())
			}
			if c.currentPersona().VisitorID != kept.VisitorID || c.captchaAttempt != 0 || c.serviceFailureStreak.Load() != 1 {
				t.Fatal("persona, attempts or refusal count changed unexpectedly")
			}
		})
	}
}

func expireAuthPause(t *testing.T, c *Client) {
	t.Helper()
	state := c.cooldown.load()
	state.Until = time.Now().Add(-time.Second).Unix()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range c.cooldown.paths {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c.captchaPause.Store(state.Until)
	c.lockout.Store(state.Until)
}

func TestServiceFailureHistorySurvivesRestartAndResetsOnSuccess(t *testing.T) {
	cfg := Config{FingerprintSeed: "fixed-install", StatePaths: statePaths(t)}
	c := New(cfg)
	_ = c.pauseAuth(1, pauseService, temporaryProviderError())
	restarted := New(cfg)
	calls := 0
	restarted.tokenChain = func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		calls++
		return "", "", nil, temporaryProviderError()
	}
	_, _, _, err := restarted.fetch(context.Background(), "link", 1)
	if !errors.Is(err, captcha.ErrUnavailable) || calls != 0 || restarted.serviceFailureStreak.Load() != 1 {
		t.Fatalf("restart err=%v calls=%d", err, calls)
	}
	expireAuthPause(t, restarted)
	_, _, _, err = restarted.fetch(context.Background(), "link", 1)
	remaining := time.Until(time.Unix(restarted.LockoutUntilUnix(), 0))
	if !errors.Is(err, captcha.ErrUnavailable) || calls != 1 || restarted.serviceFailureStreak.Load() != 2 || remaining < 119*time.Second {
		t.Fatalf("err=%v calls=%d streak=%d remaining=%v", err, calls, restarted.serviceFailureStreak.Load(), remaining)
	}
	expireAuthPause(t, restarted)
	restarted.tokenChain = func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		return "u", "p", []string{"relay"}, nil
	}
	if _, _, _, err := restarted.fetch(context.Background(), "link", 1); err != nil {
		t.Fatal(err)
	}
	afterSuccess := New(cfg)
	if afterSuccess.serviceFailureStreak.Load() != 0 || afterSuccess.authPauseError() != nil {
		t.Fatal("success did not clear persisted failure history")
	}
}

func TestCachedTurnCredentialsRemainAvailableDuringPause(t *testing.T) {
	c := newTestClient(t, func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		return "u", "p", []string{"relay"}, nil
	})
	if _, _, _, err := c.GetCredentials(context.Background(), "link", 1); err != nil {
		t.Fatal(err)
	}
	_ = c.pauseAuth(20, pauseService, temporaryProviderError())
	c.tokenChain = func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		t.Fatal("cached credentials caused another authorization")
		return "", "", nil, nil
	}
	user, _, _, err := c.GetCredentials(context.Background(), "link", 1)
	if err != nil || user != "u" {
		t.Fatalf("user=%s err=%v", user, err)
	}
}

func TestCooldownIgnoresCorruptRecordsAndNeverShortensPause(t *testing.T) {
	path := filepath.Join(t.TempDir(), captchaPauseFile)
	store := cooldownStore{paths: []string{path}}
	for _, body := range []string{`invalid`, `{"until":9999999999999}`, `{"until":1}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if state := store.load(); state.Until != 0 {
			t.Fatalf("accepted %s", body)
		}
	}
	until := time.Now().Add(time.Hour).Unix()
	if _, ok := store.save(pauseState{Until: until, Kind: pauseService, ServiceStreak: 3}); !ok {
		t.Fatal("save failed")
	}
	if _, ok := store.save(pauseState{Until: until - 60, Kind: pauseRate, RateStreak: 1}); !ok {
		t.Fatal("second save failed")
	}
	state := store.load()
	if state.Until != until || state.Kind != pauseService || state.ServiceStreak != 3 || state.RateStreak != 1 {
		t.Fatalf("state=%+v", state)
	}
}

func TestRateLimitRemainsRecoverableWithNoStreams(t *testing.T) {
	c := New(Config{StreamsAlive: func() int32 { return 0 }})
	err := c.pauseAuth(1, pauseRate, captcha.ErrRateLimited)
	if !errors.Is(err, ErrCaptchaWaitRequired) || errors.Is(err, ErrFatalCaptchaNoStreams) {
		t.Fatalf("err=%v", err)
	}
}

func TestServiceRetryAfterIsHonored(t *testing.T) {
	c := New(Config{})
	cause := captcha.ResponseError("captchaNotRobot.check", 200, "3600", map[string]any{"error": map[string]any{"error_code": 10}})
	_ = c.pauseAuth(1, pauseService, cause)
	if time.Until(time.Unix(c.LockoutUntilUnix(), 0)) < time.Hour {
		t.Fatal("server retry deadline shortened")
	}
}

func TestBusinessErrorStillReachesLinkClassifier(t *testing.T) {
	c := New(Config{})
	client := &authResponseClient{respond: func(*fhttp.Request) *fhttp.Response {
		return authTestResponse(200, `{"error":{"error_code":9000,"error_msg":"not valid"}}`)
	}}
	_, err := c.fetchCallToken(context.Background(), client, c.currentPersona(), 1, "bad-link", "name", "token", VKCredentials{})
	if !errors.Is(err, ErrInvalidJoinLink) || len(client.calls) != 1 {
		t.Fatalf("err=%v requests=%d", err, len(client.calls))
	}
}
