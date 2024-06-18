package cfg_test

import (
	"bytes"
	"errors"
	"path"
	"testing"

	"github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/cfg"
)

var (
	DEFAULT_CONFIG, _ = cfg.MergedConfig(path.Join("..", "..", "config", "crowdsec-cloudflare-worker-bouncer.yaml"))
)

// Basic tests to check for nil pointers and empty config
func TestConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml []byte
		err  error
	}{
		{
			name: "Default Config Test",
			yaml: DEFAULT_CONFIG,
		},
		{
			name: "Empty yaml",
			yaml: []byte(""),
			err:  cfg.EmptyConfigError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cfg.NewConfig(bytes.NewReader([]byte(tt.yaml)))
			if err != nil {
				if tt.err == nil {
					t.Fatalf("unexpected error: %s", err)
				}

				if !errors.Is(tt.err, err) {
					t.Fatalf("expected error %s, got %s", tt.err, err)
				}
				return
			}
		})
	}
}
