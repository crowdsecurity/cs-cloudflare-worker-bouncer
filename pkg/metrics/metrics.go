package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	BlockedRequestMetricName   = "crowdsec_cloudflare_worker_bouncer_blocked_requests"
	ProcessedRequestMetricName = "crowdsec_cloudflare_worker_bouncer_processed_requests"
	ActiveDecisionsMetricName  = "crowdsec_cloudflare_worker_bouncer_active_decisions"
)

var CloudflareAPICallsByAccount = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cloudflare_api_calls_total",
		Help: "Number of api calls made to cloudflare by each account",
	},
	[]string{"account"},
)

var TotalKeysByAccount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cloudflare_keys_total",
		Help: "Total Worker KV keys by account",
	},
	[]string{"account"},
)

var TotalBlockedRequests = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: BlockedRequestMetricName,
	Help: "Total number of blocked requests",
}, []string{"origin", "ip_type", "remediation", "account"})
var LastBlockedRequestValue = make(map[string]float64)

var TotalProcessedRequests = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ProcessedRequestMetricName,
	Help: "Total number of processed requests",
}, []string{"ip_type", "account"})
var LastProcessedRequestValue = make(map[string]float64)

var TotalActiveDecisions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ActiveDecisionsMetricName,
	Help: "Total number of active decisions",
}, []string{"origin", "ip_type", "scope", "account"})
