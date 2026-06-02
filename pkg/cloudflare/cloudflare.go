package cf

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	cf "github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/cfg"
	"github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/metrics"
)

//go:embed worker/dist/main.js
var workerScript string

//go:embed decisions-sync-worker/dist/main.js
var decisionsSyncWorkerScript string

const (
	WidgetName            = "crowdsec-cloudflare-worker-bouncer-widget"
	TurnstileConfigKey    = "TURNSTILE_CONFIG"
	VarNameForBanTemplate = "BAN_TEMPLATE"
	IpRangeKeyName        = "IP_RANGES"

	// metricsPollLookback is how far back the AE metrics cursor reaches when
	// the manager is freshly constructed, so the first poll covers any AE
	// data points written between bouncer start and the first push cycle.
	metricsPollLookback = 2 * time.Minute

	// aeIngestionLag is how far in the past windowEnd lands relative to wall
	// clock, so the [start, end) window only covers AE rows that have had time
	// to index. Without this, the cursor advances past unindexed rows that
	// arrive seconds late and the corresponding metrics are dropped forever.
	aeIngestionLag = 10 * time.Second
)

type cloudflareAPI interface {
	Account(ctx context.Context, accountID string) (cf.Account, cf.ResultInfo, error)
	CreateTurnstileWidget(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateTurnstileWidgetParams) (cf.TurnstileWidget, error)
	CreateWorkerRoute(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateWorkerRouteParams) (cf.WorkerRouteResponse, error)
	CreateWorkersKVNamespace(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateWorkersKVNamespaceParams) (cf.WorkersKVNamespaceResponse, error)
	DeleteTurnstileWidget(ctx context.Context, rc *cf.ResourceContainer, siteKey string) error
	DeleteWorker(ctx context.Context, rc *cf.ResourceContainer, params cf.DeleteWorkerParams) error
	DeleteWorkerRoute(ctx context.Context, rc *cf.ResourceContainer, routeID string) (cf.WorkerRouteResponse, error)
	DeleteWorkersKVEntries(ctx context.Context, rc *cf.ResourceContainer, params cf.DeleteWorkersKVEntriesParams) (cf.Response, error)
	DeleteWorkersKVNamespace(ctx context.Context, rc *cf.ResourceContainer, namespaceID string) (cf.Response, error)
	ListTurnstileWidgets(ctx context.Context, rc *cf.ResourceContainer, params cf.ListTurnstileWidgetParams) ([]cf.TurnstileWidget, *cf.ResultInfo, error)
	ListWorkerBindings(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkerBindingsParams) (cf.WorkerBindingListResponse, error)
	ListWorkerRoutes(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkerRoutesParams) (cf.WorkerRoutesResponse, error)
	ListWorkersKVNamespaces(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error)
	ListWorkersSecrets(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkersSecretsParams) (cf.WorkersListSecretsResponse, error)
	ListZones(ctx context.Context, z ...string) ([]cf.Zone, error)
	RotateTurnstileWidget(ctx context.Context, rc *cf.ResourceContainer, param cf.RotateTurnstileWidgetParams) (cf.TurnstileWidget, error)
	SetWorkersSecret(ctx context.Context, rc *cf.ResourceContainer, params cf.SetWorkersSecretParams) (cf.WorkersPutSecretResponse, error)
	UploadWorker(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateWorkerParams) (cf.WorkerScriptResponse, error)
	UpdateWorkerCronTriggers(ctx context.Context, rc *cf.ResourceContainer, params cf.UpdateWorkerCronTriggersParams) ([]cf.WorkerCronTrigger, error)
	WriteWorkersKVEntries(ctx context.Context, rc *cf.ResourceContainer, params cf.WriteWorkersKVEntriesParams) (cf.Response, error)
}

type CloudflareAccountManager struct {
	AccountCfg            cfg.AccountConfig
	api                   cloudflareAPI
	Ctx                   context.Context
	logger                *log.Entry
	hasIPRangeKV          bool
	NamespaceID           string
	KVPairByDecisionValue map[string]cf.WorkersKVPair
	ipRangeKVPair         cf.WorkersKVPair
	ActionByIPRange       map[string]string
	Worker                *cfg.CloudflareWorkerCreateParams
	httpClient            *http.Client
	lastMetricsPoll       time.Time
	metricsMu             sync.Mutex
	cumulativeMetrics     map[string]float64
}

// This function creates a new instance of the CloudflareAccountManager struct,
// which is used to manage Cloudflare resources associated with a specific account.
// It initializes the struct with the account configuration, Cloudflare API client,
// and other necessary fields.
func NewCloudflareManager(ctx context.Context, accountCfg cfg.AccountConfig, worker *cfg.CloudflareWorkerCreateParams) (*CloudflareAccountManager, error) {
	api, err := NewCloudflareAPI(accountCfg)
	if err != nil {
		return nil, err
	}
	zones, err := api.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	for i, zoneCfg := range accountCfg.ZoneConfigs {
		found := false
		for _, zone := range zones {
			if zone.ID == zoneCfg.ID {
				found = true
				accountCfg.ZoneConfigs[i].Domain = zone.Name
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("zone %s not found in account %s", zoneCfg.ID, accountCfg.ID)
		}
	}
	return &CloudflareAccountManager{
		AccountCfg:      accountCfg,
		api:             api,
		Ctx:             ctx,
		logger:          log.WithFields(log.Fields{"account": accountCfg.Name}),
		ipRangeKVPair:   cf.WorkersKVPair{Key: IpRangeKeyName, Value: "{}"},
		ActionByIPRange: make(map[string]string),
		Worker:          worker,
		httpClient: &http.Client{
			Transport: &CloudflareManagerHTTPTransport{accountName: accountCfg.Name},
			Timeout:   30 * time.Second,
		},
		lastMetricsPoll:   time.Now().UTC().Add(-metricsPollLookback).Truncate(time.Second),
		cumulativeMetrics: make(map[string]float64),
	}, nil
}

// The CloudflareManagerHTTPTransport struct implements the http.RoundTripper interface
// and overrides the RoundTrip method to increment a Prometheus counter for each API call made by the account owner.
type CloudflareManagerHTTPTransport struct {
	http.Transport
	accountName string
}

func (cfT *CloudflareManagerHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	metrics.CloudflareAPICallsByAccount.WithLabelValues(cfT.accountName).Inc()
	return http.DefaultTransport.RoundTrip(req)
}

// The NewCloudflareAPI function creates a new instance of the cloudflareAPI interface, which is used to interact with the Cloudflare API.
// It initializes the API client with the provided account configuration and HTTP client, and returns the client instance.
// The function also uses a custom HTTP transport to track the number of Cloudflare API calls made by the account owner.
func NewCloudflareAPI(accountCfg cfg.AccountConfig) (cloudflareAPI, error) {
	transport := CloudflareManagerHTTPTransport{accountName: accountCfg.Name}
	httpClient := http.Client{}
	httpClient.Transport = &transport
	api, err := cf.NewWithAPIToken(accountCfg.Token, cf.HTTPClient(&httpClient))
	if err != nil {
		return nil, err
	}
	return api, nil
}

// This is pushed to KV. It is used by workers to determine the action to take for a given IP address and zone.
type ActionsForZone struct {
	SupportedActions []string `json:"supported_actions"`
	DefaultAction    string   `json:"default_action"`
}

// enableWorkerObservability PATCHes the script-settings API to enable Workers
// Observability (logs + traces). This is a direct HTTP call because cloudflare-go
// v0.116.0 does not expose the observability field.
func (m *CloudflareAccountManager) enableWorkerObservability(scriptName string) error {
	obsCfg := m.Worker.Observability
	if obsCfg == nil {
		return nil
	}

	enabled := true
	if obsCfg.Enabled != nil {
		enabled = *obsCfg.Enabled
	}

	samplingRate := 1.0
	if obsCfg.HeadSamplingRate != nil {
		samplingRate = *obsCfg.HeadSamplingRate
	}

	type tracesPayload struct {
		Enabled          bool    `json:"enabled"`
		HeadSamplingRate float64 `json:"head_sampling_rate"`
	}
	type obsPayload struct {
		Enabled          bool          `json:"enabled"`
		HeadSamplingRate float64       `json:"head_sampling_rate"`
		Traces           tracesPayload `json:"traces"`
	}

	// Default traces to match top-level settings; override if explicitly configured
	traces := tracesPayload{Enabled: enabled, HeadSamplingRate: samplingRate}
	if obsCfg.Traces != nil {
		if obsCfg.Traces.Enabled != nil {
			traces.Enabled = *obsCfg.Traces.Enabled
		}
		if obsCfg.Traces.HeadSamplingRate != nil {
			traces.HeadSamplingRate = *obsCfg.Traces.HeadSamplingRate
		}
	}

	payload, err := json.Marshal(struct {
		Observability obsPayload `json:"observability"`
	}{Observability: obsPayload{
		Enabled:          enabled,
		HeadSamplingRate: samplingRate,
		Traces:           traces,
	}})
	if err != nil {
		return fmt.Errorf("failed to marshal observability payload: %w", err)
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s/script-settings",
		m.AccountCfg.ID, scriptName)

	req, err := http.NewRequestWithContext(m.Ctx, http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create observability request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.AccountCfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("observability settings request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("observability settings HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	m.logger.Infof("Configured observability for %s (logs=%t/%.2f, traces=%t/%.2f)",
		scriptName, enabled, samplingRate, traces.Enabled, traces.HeadSamplingRate)
	return nil
}

// Creates a new Cloudflare Workers KV namespace, uploads a new worker script, and binds the worker to one or more routes for
// each zone configuration in the account. The method also creates a JSON-encoded string of supported actions for each zone
// and binds it to the worker.
func (m *CloudflareAccountManager) DeployInfra() error {
	// Create the worker
	m.logger.Infof("Creating KVNS %s", m.Worker.KVNameSpaceName)
	kvNSResp, err := m.api.CreateWorkersKVNamespace(
		m.Ctx,
		cf.AccountIdentifier(m.AccountCfg.ID),
		cf.CreateWorkersKVNamespaceParams{Title: m.Worker.KVNameSpaceName},
	)
	if err != nil {
		return err
	}
	m.logger.Tracef("KVNS: %+v", kvNSResp)
	m.NamespaceID = kvNSResp.Result.ID

	var banTemplate []byte
	if m.AccountCfg.BanTemplate != "" {
		banTemplate, err = os.ReadFile(m.AccountCfg.BanTemplate)
		if err != nil {
			return fmt.Errorf("error while reading ban template at path %s", m.AccountCfg.BanTemplate)
		}
	} else {
		banTemplate = []byte("Access Denied")
	}

	_, err = m.api.WriteWorkersKVEntries(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.WriteWorkersKVEntriesParams{
		NamespaceID: m.NamespaceID,
		KVs: []*cf.WorkersKVPair{{
			Key:   VarNameForBanTemplate,
			Value: string(banTemplate),
		}},
	})
	if err != nil {
		return fmt.Errorf("error while writing ban template to KV: %w", err)
	}
	actionsForZoneByDomain := make(map[string]ActionsForZone)
	for _, z := range m.AccountCfg.ZoneConfigs {
		actionsForZoneByDomain[z.Domain] = ActionsForZone{
			SupportedActions: z.Actions,
			DefaultAction:    z.DefaultAction,
		}
	}
	varActionsForZoneByDomain, err := json.Marshal(actionsForZoneByDomain)
	if err != nil {
		return err
	}

	m.logger.Infof("Creating worker %s", m.Worker.ScriptName)

	worker, err := m.api.UploadWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), m.Worker.CreateWorkerParams(workerScript, kvNSResp.Result.ID, varActionsForZoneByDomain, m.AccountCfg.Name))
	m.logger.Tracef("Worker: %+v", worker)

	if err != nil {
		return err
	}

	if err := m.enableWorkerObservability(m.Worker.ScriptName); err != nil {
		// Observability is a developer-experience feature; a misconfiguration
		// (rate-limit, wrong scope on the token) shouldn't fail the whole deploy
		// after the worker is already live. Log and continue.
		m.logger.Warnf("Could not enable observability for %s: %s — deploy will continue without it", m.Worker.ScriptName, err)
	}

	zg := errgroup.Group{}
	for _, z := range m.AccountCfg.ZoneConfigs {
		for _, r := range z.RoutesToProtect {
			zone := z
			route := r
			zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
			zoneLogger.Infof("Binding worker to route %s", route)
			zg.Go(func() error {
				workerRouteResp, err := m.api.CreateWorkerRoute(m.Ctx, cf.ZoneIdentifier(zone.ID), cf.CreateWorkerRouteParams{
					Pattern: route,
					Script:  worker.ID,
				})
				if err != nil {
					return err
				}
				zoneLogger.Tracef("WorkerRouteResp: %+v", workerRouteResp)
				zoneLogger.Infof("Bound worker to route %s", route)
				return nil
			})
		}
	}
	return zg.Wait()
}

// DeployDecisionsSyncWorker deploys the autonomous decisions sync worker.
// This worker runs on a cron schedule and syncs decisions from CrowdSec LAPI to Cloudflare KV.
func (m *CloudflareAccountManager) DeployDecisionsSyncWorker(crowdSecConfig cfg.CrowdSecConfig, cronSchedule string) error {
	m.logger.Infof("Deploying decisions sync worker %s with cron schedule: %s", m.Worker.DecisionsSyncScriptName, cronSchedule)

	// Build scenario filters
	includeScenarios := strings.Join(crowdSecConfig.IncludeScenariosContaining, ",")
	excludeScenarios := strings.Join(crowdSecConfig.ExcludeScenariosContaining, ",")
	origins := strings.Join(crowdSecConfig.OnlyIncludeDecisionsFrom, ",")

	// Create bindings for the sync worker
	bindings := map[string]cf.WorkerBinding{
		cfg.KVWorkerBindingName: cf.WorkerKvNamespaceBinding{NamespaceID: m.NamespaceID},
		"LAPI_URL": cf.WorkerPlainTextBinding{
			Text: crowdSecConfig.CrowdSecLAPIUrl,
		},
		"LAPI_KEY": cf.WorkerSecretTextBinding{
			Text: crowdSecConfig.CrowdSecLAPIKey,
		},
		// Cloudflare API credentials for bulk KV operations
		"CF_ACCOUNT_ID": cf.WorkerPlainTextBinding{
			Text: m.AccountCfg.ID,
		},
		"CF_KV_NAMESPACE_ID": cf.WorkerPlainTextBinding{
			Text: m.NamespaceID,
		},
		"CF_API_TOKEN": cf.WorkerSecretTextBinding{
			Text: m.AccountCfg.Token,
		},
	}

	// Only add filter bindings if they have values (Cloudflare doesn't allow empty text bindings)
	if includeScenarios != "" {
		bindings["INCLUDE_SCENARIOS"] = cf.WorkerPlainTextBinding{
			Text: includeScenarios,
		}
	}
	if excludeScenarios != "" {
		bindings["EXCLUDE_SCENARIOS"] = cf.WorkerPlainTextBinding{
			Text: excludeScenarios,
		}
	}
	if origins != "" {
		bindings["ONLY_INCLUDE_ORIGINS"] = cf.WorkerPlainTextBinding{
			Text: origins,
		}
	}

	// Upload the decisions sync worker
	workerParams := cf.CreateWorkerParams{
		Script:             decisionsSyncWorkerScript,
		ScriptName:         m.Worker.DecisionsSyncScriptName,
		Bindings:           bindings,
		Module:             true,
		Logpush:            m.Worker.Logpush,
		Tags:               m.Worker.Tags,
		CompatibilityDate:  m.Worker.CompatibilityDate,
		CompatibilityFlags: m.Worker.CompatibilityFlags,
	}

	worker, err := m.api.UploadWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), workerParams)
	if err != nil {
		return fmt.Errorf("failed to upload decisions sync worker: %w", err)
	}
	m.logger.Tracef("Decisions sync worker: %+v", worker)

	if err := m.enableWorkerObservability(m.Worker.DecisionsSyncScriptName); err != nil {
		// See note above the bouncer-worker observability call: this is a
		// non-fatal DX feature; log and continue.
		m.logger.Warnf("Could not enable observability for %s: %s — deploy will continue without it", m.Worker.DecisionsSyncScriptName, err)
	}

	// Deploy cron trigger for the decisions sync worker
	m.logger.Infof("Deploying cron trigger for decisions sync worker: %s", cronSchedule)
	cronTriggers, err := m.api.UpdateWorkerCronTriggers(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.UpdateWorkerCronTriggersParams{
		ScriptName: m.Worker.DecisionsSyncScriptName,
		Crons:      []cf.WorkerCronTrigger{{Cron: cronSchedule}},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy cron trigger for decisions sync worker: %w", err)
	}
	m.logger.Tracef("Cron triggers: %+v", cronTriggers)
	m.logger.Infof("Successfully deployed decisions sync worker %s with cron: %s", m.Worker.DecisionsSyncScriptName, cronSchedule)

	return nil
}

func (m *CloudflareAccountManager) updateMetrics() {
	totalKVPairs := 1 // one for ActionsByDomain KV pair
	for _, zone := range m.AccountCfg.ZoneConfigs {
		// We only create the turnstile KV pair if the account has at least one zone with turnstile enabled.
		// This is the widgetTokenCfgByDomain KV pair found in HandleTurnstile function.
		if zone.Turnstile.Enabled {
			totalKVPairs += 1
			break
		}
	}
	// We only create the IP range KV pair if the account has at least one IP range decision.
	if m.hasIPRangeKV {
		totalKVPairs += 1
	}
	totalKVPairs += len(m.KVPairByDecisionValue)
	metrics.TotalKeysByAccount.WithLabelValues(m.AccountCfg.Name).Set(float64(totalKVPairs))
}

func (m *CloudflareAccountManager) cleanupTurnstileWidgets() error {
	m.logger.Debug("Listing existing turnstile widgets")
	widgets, _, err := m.api.ListTurnstileWidgets(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.ListTurnstileWidgetParams{})
	if err != nil {
		return err
	}
	m.logger.Tracef("widgets: %+v", widgets)
	m.logger.Debug("Done listing existing turnstile widgets")

	for _, widget := range widgets {
		if widget.Name == WidgetName {
			m.logger.Debugf("Deleting turnstile widget with site key %s", widget.SiteKey)
			if err := m.api.DeleteTurnstileWidget(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), widget.SiteKey); err != nil {
				return err
			}
			m.logger.Debugf("Done deleting turnstile widget with site key %s", widget.SiteKey)
		}
	}
	m.logger.Debug("Done cleaning up existing turnstile widgets")
	return nil
}

func (m *CloudflareAccountManager) cleanupWorkerRoutes() error {
	for _, zone := range m.AccountCfg.ZoneConfigs {
		zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
		zoneLogger.Debugf("Listing worker routes")
		routeResp, err := m.api.ListWorkerRoutes(m.Ctx, cf.ZoneIdentifier(zone.ID), cf.ListWorkerRoutesParams{})
		if err != nil {
			return err
		}
		zoneLogger.Tracef("routeResp: %+v", routeResp)
		zoneLogger.Debugf("Done listing worker routes")

		for _, route := range routeResp.Routes {
			if route.ScriptName == m.Worker.ScriptName {
				zoneLogger.Debugf("Deleting worker route with ID %s", route.ID)
				_, err := m.api.DeleteWorkerRoute(m.Ctx, cf.ZoneIdentifier(zone.ID), route.ID)
				if err != nil {
					return err
				}
				zoneLogger.Debugf("Done deleting worker route with ID %s", route.ID)
			}
		}
	}
	return nil
}

func (m *CloudflareAccountManager) cleanupWorkerScripts() error {
	m.logger.Debugf("Attempting to delete worker script %s", m.Worker.ScriptName)
	err := m.api.DeleteWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.DeleteWorkerParams{
		ScriptName: m.Worker.ScriptName,
	})
	if err != nil {
		m.logger.Debugf("Received error while deleting worker script %s: %s (type: %s)", m.Worker.ScriptName, err, fmt.Sprintf("%T", err))
		var notFoundErr *cf.NotFoundError
		if !errors.As(err, &notFoundErr) {
			return err
		}
		m.logger.Debugf("Didn't find worker script %s", m.Worker.ScriptName)
	} else {
		m.logger.Debugf("Deleted worker script %s", m.Worker.ScriptName)
	}

	// Clean up decisions sync worker if it exists
	m.logger.Debugf("Attempting to delete decisions sync worker script %s", m.Worker.DecisionsSyncScriptName)
	err = m.api.DeleteWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.DeleteWorkerParams{
		ScriptName: m.Worker.DecisionsSyncScriptName,
	})
	if err != nil {
		m.logger.Debugf("Received error while deleting decisions sync worker script %s: %s (type: %s)", m.Worker.DecisionsSyncScriptName, err, fmt.Sprintf("%T", err))
		var notFoundErr *cf.NotFoundError
		if !errors.As(err, &notFoundErr) {
			return err
		}
		m.logger.Debugf("Didn't find decisions sync worker script %s", m.Worker.DecisionsSyncScriptName)
	} else {
		m.logger.Debugf("Deleted decisions sync worker script %s", m.Worker.DecisionsSyncScriptName)
	}
	return nil
}

// findBoundKVNamespaceIDs inspects this instance's worker scripts and returns
// the set of KV namespace IDs bound under cfg.KVWorkerBindingName. Used to
// positively identify which namespaces belong to this instance before
// teardown — without it, two instances sharing a Cloudflare account with the
// same kv_namespace_name would each delete the other's live KV on teardown.
// Must be called BEFORE cleanupWorkerScripts; once the script is gone, the
// binding lookup returns a NotFoundError.
func (m *CloudflareAccountManager) findBoundKVNamespaceIDs() map[string]struct{} {
	ids := map[string]struct{}{}
	scriptNames := []string{m.Worker.ScriptName, m.Worker.DecisionsSyncScriptName}
	for _, scriptName := range scriptNames {
		if scriptName == "" {
			continue
		}
		resp, err := m.api.ListWorkerBindings(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.ListWorkerBindingsParams{
			ScriptName: scriptName,
		})
		if err != nil {
			var notFoundErr *cf.NotFoundError
			if errors.As(err, &notFoundErr) {
				m.logger.Debugf("Worker script %q not deployed; no bindings to inspect", scriptName)
				continue
			}
			m.logger.Warnf("Could not list bindings for worker %q: %s — KV cleanup will fall back to title match for this script", scriptName, err)
			continue
		}
		for _, b := range resp.BindingList {
			if b.Name != cfg.KVWorkerBindingName {
				continue
			}
			kvBinding, ok := b.Binding.(cf.WorkerKvNamespaceBinding)
			if !ok || kvBinding.NamespaceID == "" {
				continue
			}
			ids[kvBinding.NamespaceID] = struct{}{}
		}
	}
	return ids
}

// cleanupKVNamespaces deletes the KV namespaces belonging to this instance.
// boundIDs (from findBoundKVNamespaceIDs) is the authoritative source: when
// non-empty, ONLY those exact namespace IDs are deleted, so two instances
// sharing the same kv_namespace_name can safely tear down independently.
// When empty (worker script never deployed, or binding lookup failed), this
// falls back to title-match — and logs a warning enumerating exactly which
// namespaces are about to be deleted, so an operator notices a collision.
func (m *CloudflareAccountManager) cleanupKVNamespaces(boundIDs map[string]struct{}) error {
	m.logger.Debugf("Listing worker KV Namespaces")
	kvNamespaces, _, err := m.api.ListWorkersKVNamespaces(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.ListWorkersKVNamespacesParams{})
	if err != nil {
		return err
	}
	m.logger.Tracef("kvNamespaces: %+v", kvNamespaces)

	if len(boundIDs) > 0 {
		for _, kv := range kvNamespaces {
			if _, attributed := boundIDs[kv.ID]; !attributed {
				continue
			}
			m.logger.Infof("Deleting KV namespace %q (id: %s, attributed via worker binding)", kv.Title, kv.ID)
			if _, err := m.api.DeleteWorkersKVNamespace(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), kv.ID); err != nil {
				return err
			}
		}
		return nil
	}

	// Title-match fallback: collisions with another instance sharing the same
	// kv_namespace_name are catastrophic (cross-instance KV wipe), so log
	// loudly before deleting.
	var titleMatches []cf.WorkersKVNamespace
	for _, kv := range kvNamespaces {
		if kv.Title == m.Worker.KVNameSpaceName {
			titleMatches = append(titleMatches, kv)
		}
	}
	if len(titleMatches) == 0 {
		return nil
	}
	matchIDs := make([]string, 0, len(titleMatches))
	for _, kv := range titleMatches {
		matchIDs = append(matchIDs, kv.ID)
	}
	m.logger.Warnf(
		"No worker bindings available to attribute KV namespace ownership; falling back to title match. "+
			"About to delete %d namespace(s) titled %q: %v. "+
			"If another bouncer instance shares this account, ensure its kv_namespace_name is unique.",
		len(titleMatches), m.Worker.KVNameSpaceName, matchIDs)
	for _, kv := range titleMatches {
		m.logger.Infof("Deleting KV namespace %q (id: %s, attributed via title match)", kv.Title, kv.ID)
		if _, err := m.api.DeleteWorkersKVNamespace(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), kv.ID); err != nil {
			return err
		}
	}
	return nil
}

// This function checks and destroys the cloudflare infrastructure which could have been deployed by the worker in past.
// It checks this, by matching the names of the KV namespaces, worker scripts, worker routes and turnstile widgets with the names used by the worker.
func (m *CloudflareAccountManager) CleanUpExistingWorkers() error {
	m.logger.Infof("Cleaning up existing workers")

	// Capture KV namespace IDs from the live worker bindings BEFORE deleting
	// the worker scripts — once the script is gone, the binding lookup 404s
	// and cleanupKVNamespaces falls back to title-match (cross-instance risk).
	boundKVIDs := m.findBoundKVNamespaceIDs()

	if err := m.cleanupTurnstileWidgets(); err != nil {
		return err
	}

	if err := m.cleanupWorkerRoutes(); err != nil {
		return err
	}

	if err := m.cleanupWorkerScripts(); err != nil {
		return err
	}

	if err := m.cleanupKVNamespaces(boundKVIDs); err != nil {
		return err
	}

	m.logger.Info("Done cleaning up existing workers")
	return nil
}

func (m *CloudflareAccountManager) ProcessDeletedDecisions(decisions []*models.Decision) error {
	keysToDelete := make([]string, 0)
	newKVPairByValue := make(map[string]cf.WorkersKVPair)
	for _, kvPair := range m.KVPairByDecisionValue {
		newKVPairByValue[kvPair.Key] = kvPair
	}

	for _, decision := range decisions {
		origin := *decision.Origin
		if origin == "lists" {
			origin = fmt.Sprintf("%s:%s", *decision.Origin, *decision.Scenario)
		}
		if *decision.Scope == "range" {
			if _, ok := m.ActionByIPRange[*decision.Value]; ok {
				ipType := "ipv4"
				if strings.Contains(*decision.Value, ":") {
					ipType = "ipv6"
				}
				metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": *decision.Scope, "account": m.AccountCfg.Name}).Dec()
				delete(m.ActionByIPRange, *decision.Value)
			}
			continue
		}
		if val, ok := m.KVPairByDecisionValue[*decision.Value]; ok {
			if *decision.Type == val.Value {
				ipType := "ipv4"
				if *decision.Scope == "ip" {
					if strings.Contains(*decision.Value, ":") {
						ipType = "ipv6"
					}
				} else {
					ipType = "N/A"
				}
				metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": *decision.Scope, "account": m.AccountCfg.Name}).Dec()
				keysToDelete = append(keysToDelete, val.Key)
				delete(newKVPairByValue, val.Key)
			}
		}
	}
	if len(keysToDelete) == 0 {
		m.logger.Debug("No keys to delete")
		return nil
	}
	m.logger.Infof("Deleting %d decisions", len(keysToDelete))
	deleterGrp := errgroup.Group{}
	// Cloudflare API only allows deleting 10k keys at a time. So we need to batch the deletes.
	for batch, i := 0, 0; i < len(keysToDelete); i += 10000 {
		batch++
		begin := i
		end := min(i+10000, len(keysToDelete))
		deleterGrp.Go(func() error {
			resp, err := m.api.DeleteWorkersKVEntries(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.DeleteWorkersKVEntriesParams{
				Keys:        keysToDelete[begin:end],
				NamespaceID: m.NamespaceID,
			})
			if err != nil {
				return err
			}
			m.logger.Tracef("batch %d delete key resp: %+v", batch, resp)
			return nil
		})
	}
	if err := deleterGrp.Wait(); err != nil {
		return err
	}
	m.logger.Infof("Deleted %d decisions", len(keysToDelete))
	m.KVPairByDecisionValue = newKVPairByValue
	m.updateMetrics()
	return m.CommitIPRangesIfChanged()
}

type WidgetTokenCfg struct {
	SiteKey string `json:"site_key"`
	Secret  string `json:"secret"`
}

func (m *CloudflareAccountManager) writeWidgetCfgToKV(ctx context.Context, widgetTokenCfgByDomain map[string]WidgetTokenCfg) error {
	turnstileConfig, err := json.Marshal(widgetTokenCfgByDomain)
	if err != nil {
		return err
	}
	kv := cf.WorkersKVPair{
		Key:   TurnstileConfigKey,
		Value: string(turnstileConfig),
	}
	m.logger.Infof("Writing turnstile cfg")
	resp, err := m.api.WriteWorkersKVEntries(ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.WriteWorkersKVEntriesParams{
		NamespaceID: m.NamespaceID,
		KVs:         []*cf.WorkersKVPair{&kv},
	})
	if err != nil {
		return err
	}
	m.logger.Tracef("resp after writing turnstile cfg %+v", resp)
	return nil
}

func (m *CloudflareAccountManager) ProcessNewDecisions(decisions []*models.Decision) error {
	keysToWrite := make([]*cf.WorkersKVPair, 0)
	newKVPairByValue := make(map[string]cf.WorkersKVPair)

	//copy existing kv pairs
	for _, kvPair := range m.KVPairByDecisionValue {
		newKVPairByValue[kvPair.Key] = kvPair
	}

	for _, decision := range decisions {
		origin := *decision.Origin
		if origin == "lists" {
			origin = fmt.Sprintf("%s:%s", *decision.Origin, *decision.Scenario)
		}
		switch *decision.Scope {
		case "range":
			_, ok := m.ActionByIPRange[*decision.Value]
			if !ok {
				ipType := "ipv4"
				if strings.Contains(*decision.Value, ":") {
					ipType = "ipv6"
				}
				metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": *decision.Scope, "account": m.AccountCfg.Name}).Inc()
			}
			m.ActionByIPRange[*decision.Value] = *decision.Type
			continue
		default:
			if val, ok := newKVPairByValue[*decision.Value]; ok {
				if *decision.Type != val.Value {
					found := false
					for idx, kvPair := range keysToWrite {
						if kvPair.Key == *decision.Value {
							found = true
							keysToWrite[idx].Value = *decision.Type
							break
						}
					}
					if !found {
						keysToWrite = append(keysToWrite, &cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type})
						newKVPairByValue[*decision.Value] = cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type}
					}
				}
			} else {
				keysToWrite = append(keysToWrite, &cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type})
				newKVPairByValue[*decision.Value] = cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type}

				ipType := "ipv4"
				if *decision.Scope == "ip" {
					if strings.Contains(*decision.Value, ":") {
						ipType = "ipv6"
					}
				} else {
					ipType = "N/A"
				}
				metrics.TotalActiveDecisions.With(prometheus.Labels{"origin": origin, "ip_type": ipType, "scope": *decision.Scope, "account": m.AccountCfg.Name}).Inc()
			}
		}
	}
	if len(keysToWrite) == 0 {
		m.logger.Debug("No keys to write")
	} else {
		writerErrGroup := errgroup.Group{}
		m.logger.Infof("Adding %d decisions", len(keysToWrite))
		// Cloudflare API only allows writing 10k keys at a time. So we need to batch the writes.
		for batch, i := 0, 0; i < len(keysToWrite); i += 10000 {
			batch++
			begin := i
			end := min(i+10000, len(keysToWrite))
			writerErrGroup.Go(func() error {
				resp, err := m.api.WriteWorkersKVEntries(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.WriteWorkersKVEntriesParams{
					NamespaceID: m.NamespaceID,
					KVs:         keysToWrite[begin:end],
				})
				if err != nil {
					return err
				}
				m.logger.Tracef("batch %d write key resp: %+v", batch, resp)
				return nil
			})
		}
		if err := writerErrGroup.Wait(); err != nil {
			return err
		}
		m.KVPairByDecisionValue = newKVPairByValue
		m.logger.Infof("Added %d decisions", len(keysToWrite))
	}
	m.updateMetrics()
	return m.CommitIPRangesIfChanged()
}

// check if the ip ranges have changed and updates the KV pair if they have.
func (m *CloudflareAccountManager) CommitIPRangesIfChanged() error {
	m.hasIPRangeKV = true
	c, err := json.Marshal(m.ActionByIPRange)
	if err != nil {
		return err
	}
	ipRangeContent := string(c)
	if ipRangeContent != m.ipRangeKVPair.Value {
		changeCount := strings.Count(ipRangeContent, ",") - strings.Count(m.ipRangeKVPair.Value, ",")
		if changeCount > 0 {
			m.logger.Infof("Adding %d IP ranges", changeCount)
		} else {
			m.logger.Infof("Removing %d IP ranges", -changeCount)
		}
		m.logger.Debugf("IP ranges changed, writing new value: %s", ipRangeContent)
		m.ipRangeKVPair.Value = ipRangeContent
		_, err := m.api.WriteWorkersKVEntries(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.WriteWorkersKVEntriesParams{
			NamespaceID: m.NamespaceID,
			KVs:         []*cf.WorkersKVPair{&m.ipRangeKVPair},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *CloudflareAccountManager) CreateTurnstileWidgets() (map[string]WidgetTokenCfg, error) {
	widgetCreatorGrp := errgroup.Group{}
	widgetTokenCfgByDomain := make(map[string]WidgetTokenCfg)
	widgetTokenCfgByDomainLock := sync.Mutex{}
	for _, z := range m.AccountCfg.ZoneConfigs {
		zone := z
		if !zone.Turnstile.Enabled {
			continue
		}
		zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
		zoneLogger.Info(("Creating turnstile widget"))
		widgetCreatorGrp.Go(func() error {
			resp, err := m.api.CreateTurnstileWidget(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.CreateTurnstileWidgetParams{
				Name:    WidgetName,
				Domains: []string{zone.Domain},
				Mode:    zone.Turnstile.Mode,
			})
			if err != nil {
				return err
			}
			zoneLogger.Tracef("resp: %+v", resp)
			zoneLogger.Info(("Done creating turnstile widget"))
			widgetTokenCfgByDomainLock.Lock()
			defer widgetTokenCfgByDomainLock.Unlock()
			widgetTokenCfgByDomain[zone.Domain] = WidgetTokenCfg{SiteKey: resp.SiteKey, Secret: resp.Secret}
			return nil
		})
	}
	if err := widgetCreatorGrp.Wait(); err != nil {
		return nil, err
	}
	return widgetTokenCfgByDomain, nil
}

// SetupTurnstile creates Turnstile widgets and writes the config to KV.
// This is used during setup (including autonomous mode) and returns immediately.
func (m *CloudflareAccountManager) SetupTurnstile() (map[string]WidgetTokenCfg, error) {
	widgetTokenCfgByDomain, err := m.CreateTurnstileWidgets()
	if err != nil {
		return nil, err
	}

	if err := m.writeWidgetCfgToKV(m.Ctx, widgetTokenCfgByDomain); err != nil {
		return nil, err
	}

	return widgetTokenCfgByDomain, nil
}

// HandleTurnstile creates Turnstile widgets and starts the secret key rotation loop.
// This requires a long-running process and blocks until the context is canceled.
func (m *CloudflareAccountManager) HandleTurnstile() error {
	widgetTokenCfgByDomainLock := sync.Mutex{}
	widgetTokenCfgByDomain, err := m.SetupTurnstile()
	if err != nil {
		return err
	}

	// Start the rotators
	g, ctx := errgroup.WithContext(m.Ctx)
	for _, z := range m.AccountCfg.ZoneConfigs {
		if !z.Turnstile.RotateSecretKey || !z.Turnstile.Enabled {
			continue
		}
		zone := z
		g.Go(func() error {
			zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
			zoneLogger.Info(("Starting turnstile rotator"))
			ticker := time.NewTicker(zone.Turnstile.RotateSecretKeyEvery)
			for {
				select {
				case <-m.Ctx.Done():
					zoneLogger.Warn("Stopping turnstile rotator")
					return m.Ctx.Err()
				case <-ticker.C:
					zoneLogger.Info(("Rotating turnstile secret key"))
					widgetTokenCfgByDomainLock.Lock()
					widgetTokenCfg := widgetTokenCfgByDomain[zone.Domain]
					widgetTokenCfgByDomainLock.Unlock()
					resp, err := m.api.RotateTurnstileWidget(ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.RotateTurnstileWidgetParams{
						SiteKey:               widgetTokenCfg.SiteKey,
						InvalidateImmediately: true,
					})
					zoneLogger.Tracef("resp: %+v", resp)
					if err != nil {
						return err
					}
					widgetTokenCfg.Secret = resp.Secret
					widgetTokenCfgByDomainLock.Lock()
					widgetTokenCfgByDomain[zone.Domain] = widgetTokenCfg
					if err := m.writeWidgetCfgToKV(ctx, widgetTokenCfgByDomain); err != nil {
						return err
					}
					widgetTokenCfgByDomainLock.Unlock()
				}
			}
		})
	}
	return g.Wait()
}

// aeQueryMeta describes a column returned by the Analytics Engine SQL API.
type aeQueryMeta struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// aeQueryResult represents the JSON response from the Analytics Engine SQL API.
type aeQueryResult struct {
	Meta []aeQueryMeta    `json:"meta"`
	Data []map[string]any `json:"data"`
	Rows int              `json:"rows"`
}

func (m *CloudflareAccountManager) queryAnalyticsEngine(query string) (*aeQueryResult, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/analytics_engine/sql", m.AccountCfg.ID)

	req, err := http.NewRequestWithContext(m.Ctx, http.MethodPost, url, strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create AE request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.AccountCfg.Token)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AE query failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read AE response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AE query returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result aeQueryResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse AE response: %w", err)
	}
	return &result, nil
}

func (m *CloudflareAccountManager) UpdateMetrics() error {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	m.logger.Debug("Getting metrics from Analytics Engine")

	// AE only supports second-precision toDateTime. Query the half-open window
	// [lastMetricsPoll, windowEnd) and advance the cursor to windowEnd so every
	// second is counted exactly once. windowEnd lags wall-clock by
	// aeIngestionLag so we don't read across the AE indexing boundary — rows
	// arriving late within that window land in the next poll instead of being
	// stepped over and lost forever.
	windowEnd := time.Now().UTC().Add(-aeIngestionLag).Truncate(time.Second)

	// AE field mapping (must match writeMetricEvent in worker.js):
	//   blob1 = metric_name, blob2 = ip_type, blob3 = origin, blob4 = remediation_type
	//   double1 = count (1), double2 = latency_ms
	// AnalyticsDataset and AccountCfg.Name are allowlist-validated at config load.
	query := fmt.Sprintf(`SELECT
		blob1 AS metric_name,
		blob2 AS ip_type,
		blob3 AS origin,
		blob4 AS remediation_type,
		SUM(_sample_interval * double1) AS val,
		AVG(double2) AS avg_latency_ms
	FROM %s
	WHERE timestamp >= toDateTime('%s')
		AND timestamp < toDateTime('%s')
		AND index1 = '%s'
	GROUP BY metric_name, ip_type, origin, remediation_type
	FORMAT JSON`,
		m.Worker.AnalyticsDataset,
		m.lastMetricsPoll.Format("2006-01-02 15:04:05"),
		windowEnd.Format("2006-01-02 15:04:05"),
		m.AccountCfg.Name,
	)

	result, err := m.queryAnalyticsEngine(query)
	if err != nil {
		return fmt.Errorf("unable to query Analytics Engine: %w", err)
	}
	m.lastMetricsPoll = windowEnd
	m.logger.Tracef("AE result: %+v", result)

	for _, row := range result.Data {
		metricName, ok := row["metric_name"].(string)
		if !ok {
			m.logger.Warnf("Invalid metric_name type in AE response: %T", row["metric_name"])
			continue
		}
		val, ok := row["val"].(float64)
		if !ok {
			m.logger.Warnf("Invalid val type in AE response for metric %s: %T", metricName, row["val"])
			continue
		}
		var ipType, origin, remediation string
		if v, ok := row["ip_type"].(string); ok {
			ipType = v
		}
		if v, ok := row["origin"].(string); ok {
			origin = v
		}
		if v, ok := row["remediation_type"].(string); ok {
			remediation = v
		}

		switch metricName {
		case "processed":
			key := "processed:" + ipType + ":" + m.AccountCfg.Name
			m.cumulativeMetrics[key] += val
			metrics.TotalProcessedRequests.With(prometheus.Labels{
				"ip_type": ipType, "account": m.AccountCfg.Name,
			}).Set(m.cumulativeMetrics[key])
		case "dropped":
			key := "dropped:" + origin + ":" + remediation + ":" + ipType + ":" + m.AccountCfg.Name
			m.cumulativeMetrics[key] += val
			metrics.TotalBlockedRequests.With(prometheus.Labels{
				"origin": origin, "remediation": remediation,
				"ip_type": ipType, "account": m.AccountCfg.Name,
			}).Set(m.cumulativeMetrics[key])
		case "error":
			key := "error:" + ipType + ":" + m.AccountCfg.Name
			m.cumulativeMetrics[key] += val
			metrics.TotalErrors.With(prometheus.Labels{
				"ip_type": ipType, "account": m.AccountCfg.Name,
			}).Set(m.cumulativeMetrics[key])
		default:
			m.logger.Warnf("Unknown metric from AE: %s", metricName)
		}

		if latency, ok := row["avg_latency_ms"].(float64); ok {
			metrics.AverageLatencyMs.With(prometheus.Labels{
				"account":     m.AccountCfg.Name,
				"metric_name": metricName,
				"ip_type":     ipType,
				"remediation": remediation,
			}).Set(latency)
		}
	}

	return nil
}
