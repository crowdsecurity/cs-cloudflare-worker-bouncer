package cf

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
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

//go:embed metrics.sql
var sqlCreateTableStatement string

const (
	WidgetName            = "crowdsec-cloudflare-worker-bouncer-widget"
	TurnstileConfigKey    = "TURNSTILE_CONFIG"
	VarNameForBanTemplate = "BAN_TEMPLATE"
	IpRangeKeyName        = "IP_RANGES"
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
	ListWorkerRoutes(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkerRoutesParams) (cf.WorkerRoutesResponse, error)
	ListWorkersKVNamespaces(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error)
	ListWorkersSecrets(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkersSecretsParams) (cf.WorkersListSecretsResponse, error)
	ListZones(ctx context.Context, z ...string) ([]cf.Zone, error)
	RotateTurnstileWidget(ctx context.Context, rc *cf.ResourceContainer, param cf.RotateTurnstileWidgetParams) (cf.TurnstileWidget, error)
	SetWorkersSecret(ctx context.Context, rc *cf.ResourceContainer, params cf.SetWorkersSecretParams) (cf.WorkersPutSecretResponse, error)
	UploadWorker(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateWorkerParams) (cf.WorkerScriptResponse, error)
	WriteWorkersKVEntries(ctx context.Context, rc *cf.ResourceContainer, params cf.WriteWorkersKVEntriesParams) (cf.Response, error)
	CreateD1Database(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateD1DatabaseParams) (cf.D1Database, error)
	DeleteD1Database(ctx context.Context, rc *cf.ResourceContainer, databaseID string) error
	ListD1Databases(ctx context.Context, rc *cf.ResourceContainer, params cf.ListD1DatabasesParams) ([]cf.D1Database, *cf.ResultInfo, error)
	QueryD1Database(ctx context.Context, rc *cf.ResourceContainer, params cf.QueryD1DatabaseParams) ([]cf.D1Result, error)
}

type CloudflareAccountManager struct {
	AccountCfg            cfg.AccountConfig
	api                   cloudflareAPI
	Ctx                   context.Context
	logger                *log.Entry
	hasIPRangeKV          bool
	NamespaceID           string
	DatabaseID            string
	KVPairByDecisionValue map[string]cf.WorkersKVPair
	ipRangeKVPair         cf.WorkersKVPair
	ActionByIPRange       map[string]string
	Worker                *cfg.CloudflareWorkerCreateParams
	hasD1Access           bool
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

	//Create the database
	m.logger.Info("Creating D1 Database for metrics")

	databaseResp, err := m.api.CreateD1Database(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.CreateD1DatabaseParams{
		Name: m.Worker.D1DBName,
	})

	//This could probably be a check on a more specific error, but because metrics are not critical, we just log the error and continue
	if err != nil {
		m.logger.Warnf("Error while creating D1 DB: %s. Remediation component won't be able to send metrics to crowdsec. Make sure your token has the proper permissions.", err)
		m.hasD1Access = false
	} else {
		m.hasD1Access = true
	}

	if m.hasD1Access {
		m.DatabaseID = databaseResp.UUID

		_, err = m.api.QueryD1Database(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.QueryD1DatabaseParams{
			DatabaseID: m.DatabaseID,
			SQL:        sqlCreateTableStatement,
			Parameters: []string{},
		})

		if err != nil {
			return fmt.Errorf("error while creating D1 DB table, make sure your token has the proper permissions: %w", err)
		}
	}

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

	worker, err := m.api.UploadWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), m.Worker.CreateWorkerParams(workerScript, kvNSResp.Result.ID, varActionsForZoneByDomain, m.DatabaseID))
	m.logger.Tracef("Worker: %+v", worker)

	if err != nil {
		return err
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

// This function checks and destroys the cloudflare infrastructure which could have been deployed by the worker in past.
// It checks this, by matching the names of the KV namespaces, worker scripts, worker routes and turnstile widgets with the names used by the worker.
func (m *CloudflareAccountManager) CleanUpExistingWorkers(start bool) error {
	m.logger.Infof("Cleaning up existing workers")

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

	m.logger.Debugf("Attempting to delete worker script %s", m.Worker.ScriptName)
	err = m.api.DeleteWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.DeleteWorkerParams{
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

	m.logger.Debugf("Listing worker KV Namespaces")
	kvNamespaces, _, err := m.api.ListWorkersKVNamespaces(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.ListWorkersKVNamespacesParams{})
	if err != nil {
		return err
	}
	m.logger.Tracef("kvNamespaces: %+v", kvNamespaces)
	m.logger.Debugf("Done listing worker KV Namespaces")

	for _, kvNamespace := range kvNamespaces {
		if kvNamespace.Title == m.Worker.KVNameSpaceName {
			m.logger.Debugf("Deleting worker KV Namespace with ID %s", kvNamespace.ID)
			_, err := m.api.DeleteWorkersKVNamespace(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), kvNamespace.ID)
			if err != nil {
				return err
			}
			m.logger.Debugf("Done deleting worker KV Namespace with ID %s", kvNamespace.ID)
		}
	}

	if m.hasD1Access || start {
		m.logger.Debugf("Listing D1 DBs")
		dbs, _, err := m.api.ListD1Databases(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.ListD1DatabasesParams{})

		if err != nil {
			if !start {
				return fmt.Errorf("error while listing D1 DBs, make sure your token has the proper permissions: %w", err)
			}
			dbs = []cf.D1Database{}
		}

		m.logger.Tracef("dbs: %+v", dbs)

		for _, db := range dbs {
			m.logger.Debugf("Checking D1 DB %s vs %s", db.Name, m.Worker.D1DBName)
			if db.Name == m.Worker.D1DBName {
				m.logger.Debugf("Deleting D1 DB %s", db.UUID)
				err = m.api.DeleteD1Database(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), db.UUID)
				if err != nil {
					return fmt.Errorf("error while deleting D1 DB %s, make sure your token has the proper permissions: %w", db.UUID, err)
				}
				m.logger.Debugf("Deleted D1 DB %s", db.UUID)
			}
		}
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
		batch := batch
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
			batch := batch
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

// Creates the turnstile widgets and writes the widget tokens to KV.
// It runs infinitely, rotating the secret keys every configured interval.
func (m *CloudflareAccountManager) HandleTurnstile() error {
	widgetTokenCfgByDomainLock := sync.Mutex{}
	// Create the tokens
	widgetTokenCfgByDomain, err := m.CreateTurnstileWidgets()
	if err != nil {
		return err
	}

	if err := m.writeWidgetCfgToKV(m.Ctx, widgetTokenCfgByDomain); err != nil {
		return nil
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

func (m *CloudflareAccountManager) UpdateMetrics() error {
	m.logger.Debug("Getting metrics")
	if !m.hasD1Access {
		m.logger.Debug("No D1 access, skipping metrics update")
		return nil
	}
	resp, err := m.api.QueryD1Database(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.QueryD1DatabaseParams{
		DatabaseID: m.DatabaseID,
		SQL:        "SELECT * FROM metrics",
		Parameters: []string{},
	})
	if err != nil {
		return err
	}
	m.logger.Tracef("resp: %+v", resp)

	for _, r := range resp {
		if r.Success == nil || !*r.Success {
			m.logger.Warnf("Query failed: %+v", r)
			continue
		}
		for _, data := range r.Results {
			switch data["metric_name"] {
			case "processed":
				val, ok := data["val"].(float64)
				if !ok {
					m.logger.Warnf("Invalid value for processed metric: %+v", data)
					continue
				}
				ipType, ok := data["ip_type"].(string)
				if !ok {
					m.logger.Warnf("Invalid value for ip_type: %+v", data)
					continue
				}
				metrics.TotalProcessedRequests.With(prometheus.Labels{"ip_type": ipType, "account": m.AccountCfg.Name}).Set(val)
			case "dropped":
				val, ok := data["val"].(float64)
				if !ok {
					m.logger.Warnf("Invalid value for dropped metric: %+v", data)
					continue
				}
				origin, ok := data["origin"].(string)
				if !ok {
					m.logger.Warnf("Invalid value for origin: %+v", data)
					continue
				}
				ipType, ok := data["ip_type"].(string)
				if !ok {
					m.logger.Warnf("Invalid value for ip_type: %+v", data)
					continue
				}
				remediation, ok := data["remediation_type"].(string)
				if !ok {
					m.logger.Warnf("Invalid value for remediation: %+v", data)
					continue
				}
				metrics.TotalBlockedRequests.With(prometheus.Labels{"origin": origin, "remediation": remediation, "ip_type": ipType, "account": m.AccountCfg.Name}).Set(val)
			default:
				m.logger.Warnf("Unknown metric: %+v", data)
			}
		}
	}

	return nil
}

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
