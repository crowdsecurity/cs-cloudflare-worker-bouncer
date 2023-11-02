package cfg

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
	"gopkg.in/yaml.v3"
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
	ID          string       `yaml:"id"`
	BanTemplate string       `yaml:"ban_template"`
	ZoneConfigs []ZoneConfig `yaml:"zones"`
	Token       string       `yaml:"token"`
	Name        string       `yaml:"account_name"`
}

type CloudflareConfig struct {
	Accounts []AccountConfig `yaml:"accounts"`
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
	patcher := yamlpatch.NewPatcher(configPath, ".local")
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

	for _, account := range config.CloudflareConfig.Accounts {
		if _, ok := accountIDSet[account.ID]; ok {
			return nil, fmt.Errorf("the account '%s' is duplicated", account.ID)
		}
		accountIDSet[account.ID] = true

		if account.Token == "" {
			return nil, fmt.Errorf("the account '%s' is missing token", account.ID)
		}

		for _, zone := range account.ZoneConfigs {
			if !stringSliceContains(zone.Actions, zone.DefaultAction) {
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
	return config, nil
}

func stringSliceContains(slice []string, t string) bool {
	for _, item := range slice {
		if item == t {
			return true
		}
	}
	return false
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
	for _, token := range strings.Split(tokens, ",") {
		api, err := cloudflare.NewWithAPIToken(token)
		if err != nil {
			return "", err
		}
		accounts, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{})
		if err != nil {
			return "", err
		}
		zones, err := api.ListZones(ctx)
		if err != nil {
			return "", err
		}
		for _, account := range accounts {
			accountByID[account.ID] = account
			if _, ok := accountIDXByID[account.ID]; !ok {
				accountConfigs = append(accountConfigs, AccountConfig{
					ID:          account.ID,
					Name:        strings.Replace(account.Name, "'s Account", "", -1),
					ZoneConfigs: make([]ZoneConfig, 0),
					Token:       token,
					BanTemplate: "",
				})
				accountIDXByID[account.ID] = len(accountConfigs) - 1
			}

		}

		for _, zone := range zones {
			zoneByID[zone.ID] = zone
			accountIDX := accountIDXByID[zone.Account.ID]
			accountConfigs[accountIDX].ZoneConfigs = append(accountConfigs[accountIDX].ZoneConfigs, ZoneConfig{
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
	cfConfig := CloudflareConfig{Accounts: accountConfigs}
	baseConfig.CloudflareConfig = cfConfig
	data, err := yaml.Marshal(baseConfig)
	if err != nil {
		return "", err
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
}
