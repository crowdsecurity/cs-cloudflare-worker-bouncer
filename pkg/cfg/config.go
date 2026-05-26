package cfg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/csyaml"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	VarNameForActionsByDomain = "ACTIONS_BY_DOMAIN"
	ErrEmptyConfig            = errors.New("empty config")
)

// validAccountName / validAnalyticsDataset enforce that values interpolated into
// the AE SQL query cannot break out of a ClickHouse string literal or identifier
// context. Rejecting at config load eliminates the need for runtime escaping.
var (
	validAccountName      = regexp.MustCompile(`^[\p{L}\p{N} ._\-()&+@:,]*$`)
	validAnalyticsDataset = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,63}$`)
)

// KVWorkerBindingName and AEWorkerBindingName are the worker env binding names hardcoded in the
// compiled worker JS. They must not be changed without also updating the worker source.
const (
	KVWorkerBindingName = "CROWDSECCFBOUNCERNS"
	AEWorkerBindingName = "CROWDSECCFBOUNCER_AE"
)

type TurnstileConfig struct {
	Enabled              bool          `yaml:"enabled"`
	RotateSecretKey      bool          `yaml:"rotate_secret_key"`
	RotateSecretKeyEvery time.Duration `yaml:"rotate_secret_key_every"`
	Mode                 string        `yaml:"mode"`
	SecretKey            string        `yaml:"-"`
	SiteKey              string        `yaml:"-"`
}

type ZoneConfig struct {
	ID              string          `yaml:"zone_id"`
	Actions         []string        `yaml:"actions,omitempty"`
	DefaultAction   string          `yaml:"default_action,omitempty"`
	RoutesToProtect []string        `yaml:"routes_to_protect,omitempty"`
	Turnstile       TurnstileConfig `yaml:"turnstile,omitempty"`
	Domain          string          `yaml:"-"`
}

type AccountConfig struct {
	ID          string        `yaml:"id"`
	BanTemplate string        `yaml:"ban_template"`
	ZoneConfigs []*ZoneConfig `yaml:"zones"`
	Token       string        `yaml:"token"`
	Name        string        `yaml:"account_name"`
}

// YAML struct derived from cloudflare.CreateWorkerParams
// https://github.com/cloudflare/cloudflare-go/blob/056b65c6e956a7119d0d89b27a659ea63b1c0506/workers.go#L24
type CloudflareWorkerCreateParams struct {
	ScriptName              string                     `yaml:"script_name"`
	Logpush                 *bool                      `yaml:"logpush"`
	Tags                    []string                   `yaml:"tags"`
	CompatibilityDate       string                     `yaml:"compatibility_date"`
	CompatibilityFlags      []string                   `yaml:"compatibility_flags"`
	LogOnly                 bool                       `yaml:"log_only"`
	KVNameSpaceName         string                     `yaml:"kv_namespace_name,omitempty"`          // CF resource title used for create/delete lookup; change when sharing a Cloudflare account with another bouncer instance
	AnalyticsDataset        string                     `yaml:"analytics_dataset,omitempty"`          // CF Analytics Engine dataset name for metrics
	DecisionsSyncScriptName string                     `yaml:"decisions_sync_script_name,omitempty"` // CF worker script name; change when sharing a Cloudflare account with another bouncer instance
	Observability           *WorkerObservabilityConfig `yaml:"observability,omitempty"`              // Workers Observability (logs + traces); nil = skip
}

type WorkerObservabilityConfig struct {
	Enabled          *bool               `yaml:"enabled"`
	HeadSamplingRate *float64            `yaml:"head_sampling_rate"`
	Traces           *WorkerTracesConfig `yaml:"traces,omitempty"`
}

type WorkerTracesConfig struct {
	Enabled          *bool    `yaml:"enabled"`
	HeadSamplingRate *float64 `yaml:"head_sampling_rate"`
}

func (w *CloudflareWorkerCreateParams) setDefaults() {
	if w.ScriptName == "" {
		w.ScriptName = "crowdsec-cloudflare-worker-bouncer"
	}
	if w.KVNameSpaceName == "" {
		w.KVNameSpaceName = "CROWDSECCFBOUNCERNS"
	}
	if w.AnalyticsDataset == "" {
		w.AnalyticsDataset = "crowdsec_cloudflare_bouncer"
	}
	if w.DecisionsSyncScriptName == "" {
		w.DecisionsSyncScriptName = "crowdsec-decisions-sync-worker"
	}
}

func (w *CloudflareWorkerCreateParams) CreateWorkerParams(workerScript string, id string, varActionsForZoneByDomain []byte, accountName string) cloudflare.CreateWorkerParams {
	bindings := map[string]cloudflare.WorkerBinding{
		KVWorkerBindingName: cloudflare.WorkerKvNamespaceBinding{NamespaceID: id},
		VarNameForActionsByDomain: cloudflare.WorkerPlainTextBinding{
			Text: string(varActionsForZoneByDomain),
		},
		"LOG_ONLY": cloudflare.WorkerPlainTextBinding{
			Text: fmt.Sprintf("%t", w.LogOnly),
		},
		AEWorkerBindingName: cloudflare.WorkerAnalyticsEngineBinding{
			Dataset: w.AnalyticsDataset,
		},
		"ACCOUNT_NAME": cloudflare.WorkerPlainTextBinding{
			Text: accountName,
		},
	}
	return cloudflare.CreateWorkerParams{
		Script:             workerScript,
		ScriptName:         w.ScriptName,
		Bindings:           bindings,
		Module:             true,
		Logpush:            w.Logpush,
		Tags:               w.Tags,
		CompatibilityDate:  w.CompatibilityDate,
		CompatibilityFlags: w.CompatibilityFlags,
	}
}

type DecisionsSyncWorkerConfig struct {
	Cron string `yaml:"cron"` // Cron schedule for autonomous decisions sync (e.g., "*/5 * * * *" for every 5 minutes)
}

type CloudflareConfig struct {
	Worker              CloudflareWorkerCreateParams `yaml:"worker"`
	DecisionsSyncWorker DecisionsSyncWorkerConfig    `yaml:"decisions_sync_worker,omitempty"`
	Accounts            []AccountConfig              `yaml:"accounts"`
}

type CrowdSecConfig struct {
	CrowdSecLAPIUrl             string   `yaml:"lapi_url"`
	CrowdSecLAPIKey             string   `yaml:"lapi_key"`
	CrowdsecUpdateFrequencyYAML string   `yaml:"update_frequency"`
	IncludeScenariosContaining  []string `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining  []string `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom    []string `yaml:"only_include_decisions_from"`
	KeyPath                     string   `yaml:"key_path"`
	CertPath                    string   `yaml:"cert_path"`
	CAPath                      string   `yaml:"ca_cert_path"`
}

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type BouncerConfig struct {
	CloudflareConfig CloudflareConfig `yaml:"cloudflare_config"`
	CrowdSecConfig   CrowdSecConfig   `yaml:"crowdsec_config"`
	Daemon           bool             `yaml:"daemon"`
	Logging          LoggingConfig    `yaml:",inline"`
	PrometheusConfig PrometheusConfig `yaml:"prometheus"`
}

func MergedConfig(configPath string) ([]byte, error) {
	patcher := csyaml.NewPatcher(configPath, ".local")
	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// NewConfig creates bouncerConfig from the file at provided path
func NewConfig(reader io.Reader) (*BouncerConfig, error) {
	config := &BouncerConfig{}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	configBuff := csstring.StrictExpand(string(content), os.LookupEnv)

	if len(configBuff) == 0 {
		return nil, ErrEmptyConfig
	}

	err = yaml.Unmarshal([]byte(configBuff), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if err = config.Logging.setup("crowdsec-cloudflare-worker-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	accountIDSet := make(map[string]bool) // for verifying that each account ID is unique
	zoneIDSet := make(map[string]bool)    // for verifying that each zoneID is unique
	validAction := map[string]bool{"captcha": true, "ban": true}
	validChoiceMsg := "valid choices are either of 'ban', 'captcha'"

	for i := range config.CloudflareConfig.Accounts {
		account := &config.CloudflareConfig.Accounts[i]
		if _, ok := accountIDSet[account.ID]; ok {
			return nil, fmt.Errorf("the account '%s' is duplicated", account.ID)
		}
		accountIDSet[account.ID] = true

		if account.Token == "" {
			return nil, fmt.Errorf("the account '%s' is missing token", account.ID)
		}

		// Mirror the worker's `env.ACCOUNT_NAME || "default"` fallback: an empty
		// name would query `index1 = ''` and never match what the worker writes.
		if account.Name == "" {
			account.Name = "default"
		}
		if !validAccountName.MatchString(account.Name) {
			return nil, fmt.Errorf("account '%s' has invalid account_name %q: permitted characters are letters, digits, spaces, and . _ - ( ) & + @ : ,", account.ID, account.Name)
		}

		for _, zone := range account.ZoneConfigs {
			if !slices.Contains(zone.Actions, zone.DefaultAction) {
				zone.Actions = append(zone.Actions, zone.DefaultAction)
			}
			if len(zone.Actions) == 0 {
				return nil, fmt.Errorf("account %s 's zone %s has no action", account.ID, zone.ID)
			}
			for _, a := range zone.Actions {
				if _, ok := validAction[a]; !ok {
					return nil, fmt.Errorf("invalid actions '%s', %s", a, validChoiceMsg)
				}
				if a == "captcha" && !zone.Turnstile.Enabled {
					return nil, fmt.Errorf("turnstile must be enabled for zone %s to support captcha action", zone.ID)
				}
			}
			if _, ok := zoneIDSet[zone.ID]; ok {
				return nil, fmt.Errorf("zone id %s is duplicated", zone.ID)
			}
			zoneIDSet[zone.ID] = true
		}
	}
	config.CloudflareConfig.Worker.setDefaults() // set defaults for worker

	if !validAnalyticsDataset.MatchString(config.CloudflareConfig.Worker.AnalyticsDataset) {
		return nil, fmt.Errorf("invalid analytics_dataset %q: must match %s", config.CloudflareConfig.Worker.AnalyticsDataset, validAnalyticsDataset.String())
	}

	if obs := config.CloudflareConfig.Worker.Observability; obs != nil {
		if r := obs.HeadSamplingRate; r != nil && (*r < 0 || *r > 1) {
			return nil, fmt.Errorf("observability head_sampling_rate must be between 0 and 1, got %f", *r)
		}
		if obs.Traces != nil {
			if r := obs.Traces.HeadSamplingRate; r != nil && (*r < 0 || *r > 1) {
				return nil, fmt.Errorf("observability traces head_sampling_rate must be between 0 and 1, got %f", *r)
			}
		}
	}

	return config, nil
}

func lineComment(l string, zoneByID map[string]cloudflare.Zone, accountByID map[string]cloudflare.Account) string {
	words := strings.Split(l, " ")
	lastWord := words[len(words)-1]

	if zone, ok := zoneByID[lastWord]; ok {
		return zone.Name
	}

	if strings.Contains(l, "ban_template") {
		return "template to use for ban action, set empty to use default"
	}

	if strings.Contains(l, "exclude_scenarios_containing") {
		return "ignore IPs banned for triggering scenarios containing either of provided word"
	}
	if strings.Contains(l, "include_scenarios_containing") {
		return "ignore IPs banned for triggering scenarios not containing either of provided word"
	}
	if strings.Contains(l, "only_include_decisions_from") {
		return `only include IPs banned due to decisions orginating from provided sources. eg value ["cscli", "crowdsec"]`
	}
	if strings.Contains(l, "actions:") {
		return `supported actions for this zone. eg value ["ban", "captcha"]`
	}
	if strings.Contains(l, "turnstile:") {
		return `Turnstile must be enabled if captcha action is used.`
	}
	if strings.Contains(l, "kv_namespace_name:") {
		return `KV namespace title used to create/locate the decision store; change when running multiple bouncers on the same Cloudflare account`
	}
	if strings.Contains(l, "decisions_sync_script_name:") {
		return `Decisions sync worker script name; change when running multiple bouncers on the same Cloudflare account`
	}
	if strings.Contains(l, "decisions_sync_worker:") {
		return `Configuration for autonomous decisions sync worker`
	}
	if strings.Contains(l, "cron:") {
		return `Cron schedule for syncing decisions (e.g., "*/5 * * * *" for every 5 minutes)`
	}
	if strings.Contains(l, "analytics_dataset:") {
		return `Workers Analytics Engine dataset name that the worker writes metric data points to`
	}
	if strings.Contains(l, "observability:") {
		return `Workers Observability (logs/traces) configuration; omit to leave Cloudflare defaults in place`
	}
	if strings.Contains(l, "head_sampling_rate:") {
		return `Sampling rate for head-based observability (0.0 to 1.0)`
	}
	return ""
}

func ConfigTokens(tokens string, baseConfigPath string) (string, error) {
	baseConfig := &BouncerConfig{}
	hasBaseConfig := true
	configBuff, err := os.ReadFile(baseConfigPath)
	if err != nil {
		hasBaseConfig = false
	}

	if hasBaseConfig {
		err = yaml.Unmarshal(configBuff, &baseConfig)
		if err != nil {
			return "", err
		}
	} else {
		setDefaults(baseConfig)
	}

	accountConfigs := make([]AccountConfig, 0)
	zoneByID := make(map[string]cloudflare.Zone)
	accountByID := make(map[string]cloudflare.Account)
	accountIDXByID := make(map[string]int)
	ctx := context.Background()
	for token := range strings.SplitSeq(tokens, ",") {
		api, err := cloudflare.NewWithAPIToken(token)
		if err != nil {
			return "", fmt.Errorf("failed to create cloudflare api client: %w", err)
		}
		accounts, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{})
		if err != nil {
			return "", fmt.Errorf("failed to list accounts: %w", err)
		}
		zones, err := api.ListZones(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to list zones: %w", err)
		}
		for _, account := range accounts {
			accountByID[account.ID] = account
			if _, ok := accountIDXByID[account.ID]; !ok {
				// The Cloudflare-supplied account name flows into the AE SQL
				// query, so it must satisfy validAccountName. A name that
				// doesn't (e.g. "O'Brien") would generate a config that
				// NewConfig rejects on the next startup — fall back to the
				// account ID, which is always a safe identifier.
				name := strings.Replace(account.Name, "'s Account", "", -1)
				if !validAccountName.MatchString(name) {
					log.Warnf("Cloudflare account name %q contains unsupported characters; using account ID %q as account_name", account.Name, account.ID)
					name = account.ID
				}
				accountConfigs = append(accountConfigs, AccountConfig{
					ID:          account.ID,
					Name:        name,
					ZoneConfigs: make([]*ZoneConfig, 0),
					Token:       token,
					BanTemplate: "",
				})
				accountIDXByID[account.ID] = len(accountConfigs) - 1
			}

		}

		for _, zone := range zones {
			has_a_record := false
			records, _, err := api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{})

			if err != nil {
				return "", fmt.Errorf("failed to list dns records for zone %s: %w (make sure your token has read permissions the Zone/DNS item)", zone.Name, err)
			}

			for _, record := range records {
				if record.Type == "A" || record.Type == "AAAA" {
					has_a_record = true
					break
				}
			}

			if !has_a_record {
				log.Infof("Skipping zone %s as it does not have any A or AAAA records", zone.Name)
				continue
			}

			zoneByID[zone.ID] = zone
			accountIDX := accountIDXByID[zone.Account.ID]
			accountConfigs[accountIDX].ZoneConfigs = append(accountConfigs[accountIDX].ZoneConfigs, &ZoneConfig{
				ID:            zone.ID,
				Actions:       []string{"captcha"},
				DefaultAction: "captcha",
				Turnstile: TurnstileConfig{
					Enabled:              true,
					RotateSecretKey:      true,
					RotateSecretKeyEvery: time.Hour * 24 * 7,
					Mode:                 "managed",
				},
				RoutesToProtect: []string{fmt.Sprintf("*%s/*", zone.Name)},
			})
		}
	}
	// Preserve Worker and DecisionsSyncWorker config, only update Accounts
	baseConfig.CloudflareConfig.Accounts = accountConfigs
	// Set default cron schedule if not already set
	if baseConfig.CloudflareConfig.DecisionsSyncWorker.Cron == "" {
		baseConfig.CloudflareConfig.DecisionsSyncWorker.Cron = "*/5 * * * *"
	}
	data, err := yaml.Marshal(baseConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	lineString := string(data)
	lines := strings.Split(lineString, "\n")
	if hasBaseConfig {
		lines = append([]string{
			fmt.Sprintf("# Config generated by using %s as base", baseConfigPath),
		},
			lines...,
		)
	} else {
		lines = append([]string{
			fmt.Sprintf("# Base config %s not found, please fill crowdsec credentials. ", baseConfigPath),
		},
			lines...,
		)
	}
	for i, line := range lines {
		comment := lineComment(line, zoneByID, accountByID)
		if comment != "" {
			lines[i] = line + " # " + comment
		}
	}

	return strings.Join(lines, "\n"), nil
}

func setDefaults(cfg *BouncerConfig) {
	cfg.CrowdSecConfig.CrowdSecLAPIUrl = "http://localhost:8080/"
	cfg.CrowdSecConfig.CrowdsecUpdateFrequencyYAML = "10s"
	cfg.Logging.setDefaults()

	cfg.Daemon = true
	cfg.PrometheusConfig = PrometheusConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    "2112",
	}
	cfg.CloudflareConfig.Worker.setDefaults()
	cfg.CloudflareConfig.DecisionsSyncWorker.Cron = "*/5 * * * *" // Default: every 5 minutes
}
