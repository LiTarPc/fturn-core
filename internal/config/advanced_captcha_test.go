package config

import (
	"io"
	"strings"
	"testing"
)

func TestAdvancedCaptchaOptInAndManualPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name             string
		args             []string
		advanced, manual bool
	}{
		{"default", nil, false, false},
		{"advanced", []string{"-advanced-captcha"}, true, false},
		{"disabled auto", []string{"-advanced-captcha", "-auto-captcha=false"}, true, true},
		{"explicit manual", []string{"-advanced-captcha", "-manual-captcha"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-peer", "127.0.0.1:56000", "-links", "fixture"}, tc.args...)
			cfg, err := ParseClient(args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.VK.AdvancedCaptcha != tc.advanced || cfg.VK.ManualCaptcha != tc.manual {
				t.Fatalf("advanced=%v manual=%v", cfg.VK.AdvancedCaptcha, cfg.VK.ManualCaptcha)
			}
		})
	}
	for _, fields := range []string{`"advancedCaptcha":true,"autoCaptcha":false`, `"advancedCaptcha":true,"manualCaptcha":true`} {
		cfg, err := ParseClientJSON([]byte(`{"peer":"127.0.0.1:56000","vk":{"links":["fixture"],`+fields+`}}`), "")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.VK.ManualCaptcha || !cfg.VK.AdvancedCaptcha {
			t.Fatal("JSON manual precedence lost")
		}
	}
	if !strings.Contains(DefaultClientJSON(), `"autoCaptcha": true`) {
		t.Fatal("automatic mode no longer defaults to enabled")
	}
}
