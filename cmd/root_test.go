package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/whuang8/redactrus"
	"golang.org/x/sync/errgroup"

	cf "github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/cloudflare"
)

func PtrTo[T any](v T) *T {
	return &v
}

func apiFromManager(m *cf.CloudflareAccountManager) (*cloudflare.API, error) {
	return cloudflare.NewWithAPIToken(m.AccountCfg.Token)
}

func runInfraTest(t *testing.T, m *cf.CloudflareAccountManager) error {
	api, err := apiFromManager(m)
	if err != nil {
		return err
	}
	_, err = api.GetWorker(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), m.Worker.ScriptName)
	if err != nil {
		return err
	}

	for _, zone := range m.AccountCfg.ZoneConfigs {
		routeResp, err := api.ListWorkerRoutes(m.Ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListWorkerRoutesParams{})
		if err != nil {
			return err
		}
		foundRoute := false
		for _, route := range routeResp.Routes {
			if route.ScriptName == m.Worker.ScriptName {
				foundRoute = true
			}
		}
		if !foundRoute {
			return fmt.Errorf("route not found")
		}
	}

	kvNamespaces, _, err := api.ListWorkersKVNamespaces(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.ListWorkersKVNamespacesParams{})
	if err != nil {
		return err
	}

	foundKVNamespace := false
	for _, kvNamespace := range kvNamespaces {
		if kvNamespace.Title != m.Worker.KVNameSpaceName {
			continue
		}
		foundKVNamespace = true
		widgetTokenCfgByDomain := make(map[string]cf.WidgetTokenCfg)
		oldWidgetTokenCfgByDomain := make(map[string]cf.WidgetTokenCfg)
		turnstileCfg, err := api.GetWorkersKV(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.GetWorkersKVParams{
			NamespaceID: kvNamespace.ID,
			Key:         cf.TurnstileConfigKey,
		})
		if err != nil {
			return err
		}
		if err := json.Unmarshal(turnstileCfg, &oldWidgetTokenCfgByDomain); err != nil {
			return err
		}

		time.Sleep(10 * time.Second)

		turnstileCfg, err = api.GetWorkersKV(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.GetWorkersKVParams{
			NamespaceID: kvNamespace.ID,
			Key:         cf.TurnstileConfigKey,
		})
		if err != nil {
			return err
		}
		if err := json.Unmarshal(turnstileCfg, &widgetTokenCfgByDomain); err != nil {
			return err
		}

		for _, zone := range m.AccountCfg.ZoneConfigs {
			if !zone.Turnstile.Enabled {
				continue
			}
			if _, ok := widgetTokenCfgByDomain[zone.Domain]; !ok {
				return fmt.Errorf("turnstile config not found for domain %s", zone.Domain)
			}
			if !zone.Turnstile.RotateSecretKey {
				continue
			}
			if _, ok := oldWidgetTokenCfgByDomain[zone.Domain]; !ok {
				return fmt.Errorf("turnstile config not found for domain %s", zone.Domain)
			}
			if widgetTokenCfgByDomain[zone.Domain].SiteKey != oldWidgetTokenCfgByDomain[zone.Domain].SiteKey {
				return fmt.Errorf("turnstile sitekey must not change for zone %s", zone.Domain)
			}
			if widgetTokenCfgByDomain[zone.Domain].Secret == oldWidgetTokenCfgByDomain[zone.Domain].Secret {
				return fmt.Errorf("turnstile secret must change for zone %s", zone.Domain)
			}
		}
		break
	}

	if !foundKVNamespace {
		return fmt.Errorf("kv namespace not found")
	}

	return nil
}

func runCleanUpTest(t *testing.T, m *cf.CloudflareAccountManager) error {
	if err := m.CleanUpExistingWorkers(false); err != nil {
		return err
	}
	api, err := apiFromManager(m)
	if err != nil {
		return err
	}
	err = api.DeleteWorker(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.DeleteWorkerParams{
		ScriptName: m.Worker.ScriptName,
	})
	if err == nil || !strings.Contains(err.Error(), "workers.api.error.script_not_found") {
		return fmt.Errorf("worker should not exist")
	}

	widgets, _, err := api.ListTurnstileWidgets(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.ListTurnstileWidgetParams{})
	if err != nil {
		return err
	}
	for _, widget := range widgets {
		if widget.Name == cf.WidgetName {
			return fmt.Errorf("widget should not exist")
		}
	}

	for _, zone := range m.AccountCfg.ZoneConfigs {
		routeResp, err := api.ListWorkerRoutes(m.Ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListWorkerRoutesParams{})
		if err != nil {
			return err
		}
		for _, route := range routeResp.Routes {
			if route.ScriptName == m.Worker.ScriptName {
				return fmt.Errorf("route should not exist")
			}
		}
	}

	kvNamespaces, _, err := api.ListWorkersKVNamespaces(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.ListWorkersKVNamespacesParams{})
	if err != nil {
		return err
	}

	for _, kvNamespace := range kvNamespaces {
		if kvNamespace.Title == m.Worker.KVNameSpaceName {
			return fmt.Errorf("kv namespace should not exist")
		}
	}
	return nil
}

func runDecisionTests(t *testing.T, m *cf.CloudflareAccountManager, newDecisions []*models.Decision, deletedDecisions []*models.Decision) error {
	expectedValues := make(map[string]string)
	notExpectedValues := make(map[string]string)

	expectedIPRanges := make(map[string]string)
	notExpectedIPRanges := make(map[string]string)

	for _, decision := range newDecisions {
		if *decision.Scope != "range" {
			expectedValues[*decision.Value] = *decision.Type
		} else {
			expectedIPRanges[*decision.Value] = *decision.Type
		}
	}

	for _, decision := range deletedDecisions {
		if _, ok := expectedValues[*decision.Value]; !ok {
			if *decision.Scope != "range" {
				notExpectedValues[*decision.Value] = *decision.Type
			} else {
				notExpectedIPRanges[*decision.Value] = *decision.Type
			}
		}
	}

	if err := m.ProcessDeletedDecisions(deletedDecisions); err != nil {
		return err
	}
	if err := m.ProcessNewDecisions(newDecisions); err != nil {
		return err
	}

	api, err := apiFromManager(m)
	if err != nil {
		return err
	}
	resp, err := api.ListWorkersKVKeys(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.ListWorkersKVsParams{
		NamespaceID: m.NamespaceID,
	})

	if err != nil {
		return err
	}

	kvLookup := make(map[string]struct{})
	for _, k := range resp.Result {
		kvLookup[k.Name] = struct{}{}
	}

	for val := range expectedValues {
		if _, ok := kvLookup[val]; !ok {
			return fmt.Errorf("expected value %s not found", val)
		}
	}

	for val := range notExpectedValues {
		if _, ok := kvLookup[val]; ok {
			return fmt.Errorf("unexpected value %s found", val)
		}
	}
	ipRangeValBytes, err := api.GetWorkersKV(m.Ctx, cloudflare.AccountIdentifier(m.AccountCfg.ID), cloudflare.GetWorkersKVParams{
		NamespaceID: m.NamespaceID,
		Key:         cf.IpRangeKeyName,
	})
	if err != nil {
		return err
	}
	actionByIPRange := make(map[string]string)
	if err := json.Unmarshal(ipRangeValBytes, &actionByIPRange); err != nil {
		return err
	}

	for ipRange, action := range expectedIPRanges {
		if val, ok := actionByIPRange[ipRange]; !ok {
			return fmt.Errorf("expected ip range %s not found", ipRange)
		} else if val != action {
			return fmt.Errorf("expected ip range %s to have action %s, got %s", ipRange, action, val)
		}
	}

	for ipRange := range notExpectedIPRanges {
		if _, ok := actionByIPRange[ipRange]; ok {
			return fmt.Errorf("unexpected ip range %s found", ipRange)
		}
	}

	if err != nil {
		return err
	}
	return nil
}

func generateRandomZoneName() string {
	return fmt.Sprintf("test-%d.com", time.Now().Unix())
}

func TestBouncer(t *testing.T) {
	rh := &redactrus.Hook{
		AcceptedLevels: logrus.AllLevels,
		RedactionList:  []string{"password", "email", "zone", "account_name", "owner_name", "account", "id", "secret", "token"},
	}
	logrus.AddHook(rh)
	var cloudflareToken string = os.Getenv("CLOUDFLARE_TOKEN")
	if cloudflareToken == "" {
		t.Fatal("CLOUDFLARE_TOKEN not set")
	}
	api, err := cloudflare.NewWithAPIToken(cloudflareToken)
	if err != nil {
		t.Fatal(err)
	}
	// create test zone per account
	accounts, _, err := api.Accounts(context.Background(), cloudflare.AccountsListParams{})
	if err != nil {
		t.Fatal(err)
	}

	zonesToDelete := make([]string, 0)
	for _, account := range accounts {
		zoneName := generateRandomZoneName()
		zoneObj, err := api.CreateZone(context.Background(), zoneName, false, cloudflare.Account{ID: account.ID}, "full")
		if err != nil {
			t.Fatal(err)
		}
		zonesToDelete = append(zonesToDelete, zoneObj.ID)
	}
	t.Cleanup(func() {
		eg := errgroup.Group{}
		for _, zone := range zonesToDelete {
			zone := zone
			eg.Go(func() error {
				_, err := api.DeleteZone(context.Background(), zone)
				return err
			})
		}
		t.Log(eg.Wait())
	})

	// generate config
	configPath := "/tmp/crowdsec-cloudflare-worker-bouncer.yaml"
	if err := Execute(&cloudflareToken, &configPath, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	cfg, err := getConfigFromPath(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// test setup
	managers, err := CloudflareManagersFromConfig(context.Background(), cfg.CloudflareConfig)
	if err != nil {
		t.Fatal(err)
	}
	g := errgroup.Group{}
	for _, manager := range managers {
		m := manager
		g.Go(func() error {
			return runCleanUpTest(t, m)
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}

	g = errgroup.Group{}
	for _, manager := range managers {
		m := manager
		for idx := range m.AccountCfg.ZoneConfigs {
			m.AccountCfg.ZoneConfigs[idx].Turnstile.Enabled = true
			m.AccountCfg.ZoneConfigs[idx].Turnstile.RotateSecretKey = true
			m.AccountCfg.ZoneConfigs[idx].Turnstile.RotateSecretKeyEvery = time.Second
		}
		turnstileGrp := errgroup.Group{}
		g.Go(func() error {
			if err := m.DeployInfra(); err != nil {
				return err
			}
			turnstileGrp.Go(func() error {
				if err := m.HandleTurnstile(); err != nil {
					return err
				}
				return nil
			})
			time.Sleep(10 * time.Second)
			if err := runInfraTest(t, m); err != nil {
				return err
			}
			decisions := []*models.Decision{
				{
					Scenario: PtrTo("crowdsecurity/http-probing"),
					Type:     PtrTo("captcha"),
					Value:    PtrTo("1.2.3.4"),
					Scope:    PtrTo("ip"),
				},
				{
					Scenario: PtrTo("crowdsecurity/http-probing"),
					Type:     PtrTo("ban"),
					Value:    PtrTo("1.2.3.4"),
					Scope:    PtrTo("ip"),
				},
				{
					Scenario: PtrTo("crowdsecurity/http-probing"),
					Type:     PtrTo("captcha"),
					Value:    PtrTo("1.2.3.0/24"),
					Scope:    PtrTo("range"),
				},
				{
					Scenario: PtrTo("crowdsecurity/http-probing"),
					Type:     PtrTo("captcha"),
					Value:    PtrTo("1234"),
					Scope:    PtrTo("as"),
				},
				{
					Scenario: PtrTo("crowdsecurity/http-probing"),
					Type:     PtrTo("captcha"),
					Value:    PtrTo("CN"),
					Scope:    PtrTo("country"),
				},
			}
			// insert decisions
			if err := runDecisionTests(t, m, decisions, nil); err != nil {
				return err
			}

			// delete decisions
			if err := runDecisionTests(t, m, nil, decisions); err != nil {
				return err
			}

			return runCleanUpTest(t, m)
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
}
