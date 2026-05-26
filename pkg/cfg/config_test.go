package cfg_test

import (
	"bytes"
	"errors"
	"path"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go"
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
			err:  cfg.ErrEmptyConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cfg.NewConfig(bytes.NewReader(tt.yaml))
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

func TestCreateWorkerParams_AEBinding(t *testing.T) {
	w := &cfg.CloudflareWorkerCreateParams{
		AnalyticsDataset: "crowdsec_cloudflare_bouncer",
	}

	params := w.CreateWorkerParams("script", "kv-ns-id", []byte(`{}`), "test-account")

	binding, ok := params.Bindings[cfg.AEWorkerBindingName]
	if !ok {
		t.Fatal("AE binding missing from CreateWorkerParams")
	}

	aeBinding, ok := binding.(cloudflare.WorkerAnalyticsEngineBinding)
	if !ok {
		t.Fatalf("AE binding is %T, want WorkerAnalyticsEngineBinding", binding)
	}

	if aeBinding.Dataset != "crowdsec_cloudflare_bouncer" {
		t.Fatalf("AE dataset = %q, want %q", aeBinding.Dataset, "crowdsec_cloudflare_bouncer")
	}
}

func TestCreateWorkerParams_AccountNameBinding(t *testing.T) {
	w := &cfg.CloudflareWorkerCreateParams{}

	params := w.CreateWorkerParams("script", "kv-ns-id", []byte(`{}`), "Acme Corp")

	binding, ok := params.Bindings["ACCOUNT_NAME"]
	if !ok {
		t.Fatal("ACCOUNT_NAME binding missing from CreateWorkerParams")
	}

	ptBinding, ok := binding.(cloudflare.WorkerPlainTextBinding)
	if !ok {
		t.Fatalf("ACCOUNT_NAME binding is %T, want WorkerPlainTextBinding", binding)
	}

	if ptBinding.Text != "Acme Corp" {
		t.Fatalf("ACCOUNT_NAME = %q, want %q", ptBinding.Text, "Acme Corp")
	}
}

func TestSetDefaults_AnalyticsDataset(t *testing.T) {
	yamlCfg := []byte(`
crowdsec_config:
  lapi_url: http://localhost:8080/
  lapi_key: test-key
  update_frequency: 10s
cloudflare_config:
  accounts:
    - id: acc1
      token: tok1
      zones:
        - zone_id: zone1
          actions: ["ban"]
          default_action: ban
          routes_to_protect: ["*example.com/*"]
`)

	config, err := cfg.NewConfig(bytes.NewReader(yamlCfg))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	if config.CloudflareConfig.Worker.AnalyticsDataset != "crowdsec_cloudflare_bouncer" {
		t.Fatalf("AnalyticsDataset = %q, want %q", config.CloudflareConfig.Worker.AnalyticsDataset, "crowdsec_cloudflare_bouncer")
	}
}

func TestObservabilityConfig_NilByDefault(t *testing.T) {
	yamlCfg := []byte(`
crowdsec_config:
  lapi_url: http://localhost:8080/
  lapi_key: test-key
  update_frequency: 10s
cloudflare_config:
  accounts:
    - id: acc1
      token: tok1
      zones:
        - zone_id: zone1
          actions: ["ban"]
          default_action: ban
          routes_to_protect: ["*example.com/*"]
`)

	config, err := cfg.NewConfig(bytes.NewReader(yamlCfg))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	if config.CloudflareConfig.Worker.Observability != nil {
		t.Fatal("Observability should be nil by default")
	}
}

func TestObservabilityConfig_ParsesFromYAML(t *testing.T) {
	yamlCfg := []byte(`
crowdsec_config:
  lapi_url: http://localhost:8080/
  lapi_key: test-key
  update_frequency: 10s
cloudflare_config:
  worker:
    observability:
      enabled: true
      head_sampling_rate: 0.5
      traces:
        enabled: true
        head_sampling_rate: 0.1
  accounts:
    - id: acc1
      token: tok1
      zones:
        - zone_id: zone1
          actions: ["ban"]
          default_action: ban
          routes_to_protect: ["*example.com/*"]
`)

	config, err := cfg.NewConfig(bytes.NewReader(yamlCfg))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	obs := config.CloudflareConfig.Worker.Observability
	if obs == nil {
		t.Fatal("Observability should not be nil")
	}
	if obs.Enabled == nil || !*obs.Enabled {
		t.Error("Enabled should be true")
	}
	if obs.HeadSamplingRate == nil || *obs.HeadSamplingRate != 0.5 {
		t.Errorf("HeadSamplingRate = %v, want 0.5", obs.HeadSamplingRate)
	}

	if obs.Traces == nil {
		t.Fatal("Traces should not be nil")
	}
	if obs.Traces.Enabled == nil || !*obs.Traces.Enabled {
		t.Error("Traces.Enabled should be true")
	}
	if obs.Traces.HeadSamplingRate == nil || *obs.Traces.HeadSamplingRate != 0.1 {
		t.Errorf("Traces.HeadSamplingRate = %v, want 0.1", obs.Traces.HeadSamplingRate)
	}
}

func TestObservabilityConfig_InvalidSamplingRate(t *testing.T) {
	yamlCfg := []byte(`
crowdsec_config:
  lapi_url: http://localhost:8080/
  lapi_key: test-key
  update_frequency: 10s
cloudflare_config:
  worker:
    observability:
      enabled: true
      head_sampling_rate: 5.0
  accounts:
    - id: acc1
      token: tok1
      zones:
        - zone_id: zone1
          actions: ["ban"]
          default_action: ban
          routes_to_protect: ["*example.com/*"]
`)

	_, err := cfg.NewConfig(bytes.NewReader(yamlCfg))
	if err == nil {
		t.Fatal("expected error for invalid sampling rate")
	}
	if !strings.Contains(err.Error(), "head_sampling_rate must be between 0 and 1") {
		t.Errorf("unexpected error: %v", err)
	}
}

// configWith builds a minimal valid bouncer config. A non-empty accountName is
// injected as account_name; a non-empty dataset as worker.analytics_dataset.
func configWith(accountName, dataset string) []byte {
	worker := ""
	if dataset != "" {
		worker = "  worker:\n    analytics_dataset: \"" + dataset + "\"\n"
	}
	name := ""
	if accountName != "" {
		name = "      account_name: \"" + accountName + "\"\n"
	}
	return []byte("\n" +
		"crowdsec_config:\n" +
		"  lapi_url: http://localhost:8080/\n" +
		"  lapi_key: test-key\n" +
		"  update_frequency: 10s\n" +
		"cloudflare_config:\n" +
		worker +
		"  accounts:\n" +
		"    - id: acc1\n" +
		"      token: tok1\n" +
		name +
		"      zones:\n" +
		"        - zone_id: zone1\n" +
		"          actions: [\"ban\"]\n" +
		"          default_action: ban\n" +
		"          routes_to_protect: [\"*example.com/*\"]\n")
}

func TestAccountName_RejectsInjectionCharacters(t *testing.T) {
	// Each payload carries a character that can break out of the AE SQL string
	// literal ( ' or \ ); validation must reject all of them at config load.
	cases := map[string]string{
		"single quote": `O'Brien`,
		"backslash":    `foo\\bar`,
		"injection":    `foo'; DROP TABLE users; --`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := cfg.NewConfig(bytes.NewReader(configWith(payload, "")))
			if err == nil || !strings.Contains(err.Error(), "invalid account_name") {
				t.Fatalf("expected 'invalid account_name' rejection for %q, got: %v", payload, err)
			}
		})
	}
}

func TestAccountName_AcceptsRealisticNames(t *testing.T) {
	for _, name := range []string{"acme-prod", "Acme Corp", "Internal & External (prod)", "Acme + Co.", "owner@example.com"} {
		t.Run(name, func(t *testing.T) {
			if _, err := cfg.NewConfig(bytes.NewReader(configWith(name, ""))); err != nil {
				t.Errorf("NewConfig rejected valid name %q: %v", name, err)
			}
		})
	}
}

func TestAccountName_EmptyDefaultsToDefault(t *testing.T) {
	// An omitted account_name must become "default" so the AE query's
	// index1 filter matches the worker's `env.ACCOUNT_NAME || "default"`.
	c, err := cfg.NewConfig(bytes.NewReader(configWith("", "")))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if got := c.CloudflareConfig.Accounts[0].Name; got != "default" {
		t.Errorf("empty account_name = %q, want \"default\"", got)
	}
}

func TestAnalyticsDataset_RejectsInvalidIdentifiers(t *testing.T) {
	for _, ds := range []string{"foo-bar", "foo bar", "1starts-with-digit", "foo;DROP", "foo'bar"} {
		t.Run(ds, func(t *testing.T) {
			_, err := cfg.NewConfig(bytes.NewReader(configWith("", ds)))
			if err == nil || !strings.Contains(err.Error(), "invalid analytics_dataset") {
				t.Fatalf("expected 'invalid analytics_dataset' rejection for %q, got: %v", ds, err)
			}
		})
	}
}
