package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/cfg"
	cf "github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/cloudflare"
)

const (
	DEFAULT_CONFIG_PATH = "/etc/crowdsec/bouncers/crowdsec-cloudflare-worker-bouncer.yaml"
	name                = "crowdsec-cloudflare-worker-bouncer"
)

func cleanUp(managers []*cf.CloudflareAccountManager, c context.CancelFunc, ctx context.Context) {
	var g errgroup.Group
	c()
	<-ctx.Done()
	for _, m := range managers {
		manager := m
		manager.Ctx = context.Background()
		g.Go(func() error {
			return manager.CleanUpExistingWorkers()
		})
	}
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return fmt.Errorf("received SIGTERM")
		case syscall.SIGINT:
			return fmt.Errorf("received SIGINT")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func normalizeDecisions(decisions []*models.Decision) []*models.Decision {
	for i := range decisions {
		*decisions[i].Value = strings.ToLower(*decisions[i].Value)
		*decisions[i].Scope = strings.ToLower(*decisions[i].Scope)
		*decisions[i].Type = strings.ToLower(*decisions[i].Type)
	}
	return decisions
}

func getConfigFromPath(configPath string) (*cfg.BouncerConfig, error) {
	configBytes, err := cfg.MergedConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %w", err)
	}

	conf, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	return conf, nil
}

func CloudflareManagersFromConfig(ctx context.Context, config cfg.CloudflareConfig) ([]*cf.CloudflareAccountManager, error) {
	cfManagers := make([]*cf.CloudflareAccountManager, 0, len(config.Accounts))
	for _, accountCfg := range config.Accounts {
		cfg := accountCfg
		manager, err := cf.NewCloudflareManager(ctx, cfg, &config.Worker)
		if err != nil {
			return nil, fmt.Errorf("unable to create cloudflare manager: %w", err)
		}
		cfManagers = append(cfManagers, manager)
	}
	return cfManagers, nil
}

func Execute(configTokens *string, configOutputPath *string, configPath *string, ver *bool, testConfig *bool, showConfig *bool, deleteOnly *bool, setupOnly *bool) error {
	if ver != nil && *ver {
		fmt.Print(version.FullString())
		return nil
	}

	if configPath == nil || *configPath == "" {
		configPath = new(string)
		*configPath = DEFAULT_CONFIG_PATH
	}

	if configTokens != nil && *configTokens != "" {
		cfgTokenString, err := cfg.ConfigTokens(*configTokens, *configPath)
		if err != nil {
			return err
		}
		if configOutputPath != nil && *configOutputPath != "" {
			err := os.WriteFile(*configOutputPath, []byte(cfgTokenString), 0664)
			if err != nil {
				return err
			}
			log.Printf("Config successfully generated in %s", *configOutputPath)
		} else {
			fmt.Print(cfgTokenString)
		}
		return nil
	}

	conf, err := getConfigFromPath(*configPath)
	if err != nil {
		return err
	}
	if showConfig != nil && *showConfig {
		fmt.Printf("%+v", conf)
		return nil
	}

	csLAPI := &csbouncer.StreamBouncer{
		APIKey:         conf.CrowdSecConfig.CrowdSecLAPIKey,
		APIUrl:         conf.CrowdSecConfig.CrowdSecLAPIUrl,
		TickerInterval: conf.CrowdSecConfig.CrowdsecUpdateFrequencyYAML,
		UserAgent:      fmt.Sprintf("%s/%s", name, version.String()),
		Opts: apiclient.DecisionsStreamOpts{
			Scopes:                 "ip,range,as,country",
			ScenariosNotContaining: strings.Join(conf.CrowdSecConfig.ExcludeScenariosContaining, ","),
			ScenariosContaining:    strings.Join(conf.CrowdSecConfig.IncludeScenariosContaining, ","),
			Origins:                strings.Join(conf.CrowdSecConfig.OnlyIncludeDecisionsFrom, ","),
		},
		CertPath: conf.CrowdSecConfig.CertPath,
		KeyPath:  conf.CrowdSecConfig.KeyPath,
		CAPath:   conf.CrowdSecConfig.CAPath,
	}

	if (testConfig != nil && *testConfig) || (setupOnly == nil || (setupOnly != nil && !*setupOnly)) || (deleteOnly == nil || (deleteOnly != nil && !*deleteOnly)) {
		if err := csLAPI.Init(); err != nil {
			return fmt.Errorf("unable to initialize crowdsec bouncer: %w", err)
		}
	}

	if testConfig != nil && *testConfig {
		log.Info("config is valid")
		return nil
	}

	rootCtx := context.Background()
	g, ctx := errgroup.WithContext(rootCtx)
	cfManagers, err := CloudflareManagersFromConfig(ctx, conf.CloudflareConfig)
	if err != nil {
		return err
	}
	for _, cfManager := range cfManagers {
		manager := cfManager
		g.Go(func() error {
			err := manager.CleanUpExistingWorkers()
			if err != nil {
				return fmt.Errorf("unable to cleanup existing workers: %w for account %s", err, manager.AccountCfg.Name)
			}
			if deleteOnly != nil && *deleteOnly {
				return nil
			}
			if err := manager.DeployInfra(); err != nil {
				return fmt.Errorf("unable to deploy infra: %w for account %s", err, manager.AccountCfg.Name)
			}
			log.Infof("Successfully deployed infra for account %s", manager.AccountCfg.Name)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	if deleteOnly != nil && *deleteOnly {
		return nil
	}
	log.Info("Successfully deployed infra for all accounts")
	if setupOnly != nil && *setupOnly {
		return nil
	}

	g, ctx = errgroup.WithContext(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	for i, manager := range cfManagers {
		cfManagers[i].Ctx = ctx
		m := manager
		g.Go(func() error {
			if err := m.HandleTurnstile(); err != nil {
				return fmt.Errorf("unable to handle turnstile: %w", err)
			}
			return nil
		})
	}

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	g.Go(func() error {
		csLAPI.Run(ctx)
		return fmt.Errorf("crowdsec bouncer stopped")
	})

	if conf.PrometheusConfig.Enabled {
		prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError, cf.CloudflareAPICallsByAccount, cf.TotalKeysByAccount)
		g.Go(func() error {
			http.Handle("/metrics", promhttp.Handler())
			return http.ListenAndServe(net.JoinHostPort(conf.PrometheusConfig.ListenAddress, conf.PrometheusConfig.ListenPort), nil)
		})
	}
	defer cleanUp(cfManagers, cancel, ctx)
	for {
		select {
		case <-ctx.Done():
			log.Warnf("context done: %s", ctx.Err())
			return ctx.Err()
		case streamDecision := <-csLAPI.Stream:
			if streamDecision == nil {
				return fmt.Errorf("stream decision is nil")
			}
			streamDecision.Deleted = normalizeDecisions(streamDecision.Deleted)
			streamDecision.New = normalizeDecisions(streamDecision.New)
			if len(streamDecision.Deleted) > 0 {
				log.Infof("Received %d deleted decisions", len(streamDecision.Deleted))
			}
			if len(streamDecision.New) > 0 {
				log.Infof("Received %d new decisions", len(streamDecision.New))
			}
			mg := errgroup.Group{}
			for _, m := range cfManagers {
				manager := m
				mg.Go(func() error {
					if err := manager.ProcessDeletedDecisions(streamDecision.Deleted); err != nil {
						return fmt.Errorf("account %s, unable to process deleted decisions: %w", manager.AccountCfg.Name, err)
					}
					if err := manager.ProcessNewDecisions(streamDecision.New); err != nil {
						return fmt.Errorf("account %s, unable to process new decisions: %w", manager.AccountCfg.Name, err)
					}
					return nil
				})
			}
			if err := mg.Wait(); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
		}
	}
}
