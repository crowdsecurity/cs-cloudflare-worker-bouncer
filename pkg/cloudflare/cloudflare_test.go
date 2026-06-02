package cf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	cf "github.com/cloudflare/cloudflare-go"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/cfg"
	"github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/pkg/metrics"
)

// --- Test Infrastructure ---

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func gaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	if err := g.Write(m); err != nil {
		panic("failed to read gauge: " + err.Error())
	}
	return m.GetGauge().GetValue()
}

func makeAEResponseClient(data []map[string]any) *http.Client {
	result := aeQueryResult{Data: data, Rows: len(data)}
	respBody, err := json.Marshal(&result)
	if err != nil {
		panic("makeAEResponseClient: " + err.Error())
	}
	body := string(respBody)
	return &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			_, _ = io.ReadAll(r.Body)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
}

func makeAEErrorClient(statusCode int, body string) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			_, _ = io.ReadAll(r.Body)
			return &http.Response{
				StatusCode: statusCode,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
}

type capturedRequest struct {
	Request *http.Request
	Body    string
}

func captureRequestClient(responseBody string) (*http.Client, *capturedRequest) {
	captured := &capturedRequest{}
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			captured.Request = r
			body, _ := io.ReadAll(r.Body)
			captured.Body = string(body)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(responseBody)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	return client, captured
}

func newTestManager() *CloudflareAccountManager {
	return &CloudflareAccountManager{
		AccountCfg: cfg.AccountConfig{
			ID:    "test-account-id",
			Token: "test-token",
			Name:  "test-account",
		},
		Ctx:    context.Background(),
		logger: log.WithFields(log.Fields{"account": "test-account"}),
		Worker: &cfg.CloudflareWorkerCreateParams{
			AnalyticsDataset: "test_dataset",
		},
		httpClient:        &http.Client{},
		lastMetricsPoll:   time.Now().UTC().Add(-metricsPollLookback),
		cumulativeMetrics: make(map[string]float64),
	}
}

func resetMetrics() {
	metrics.TotalProcessedRequests.Reset()
	metrics.TotalBlockedRequests.Reset()
	metrics.AverageLatencyMs.Reset()
	metrics.TotalErrors.Reset()
}

// --- Mock cloudflareAPI ---

type mockCFAPI struct {
	// KV cleanup hooks (A-2 multi-instance teardown safety)
	listWorkerBindingsFn       func(context.Context, *cf.ResourceContainer, cf.ListWorkerBindingsParams) (cf.WorkerBindingListResponse, error)
	listWorkersKVNamespacesFn  func(context.Context, *cf.ResourceContainer, cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error)
	deleteWorkersKVNamespaceFn func(context.Context, *cf.ResourceContainer, string) (cf.Response, error)
	deleteKVCalls              []string
}

func (*mockCFAPI) Account(_ context.Context, _ string) (cf.Account, cf.ResultInfo, error) {
	return cf.Account{}, cf.ResultInfo{}, nil
}
func (*mockCFAPI) CreateTurnstileWidget(_ context.Context, _ *cf.ResourceContainer, _ cf.CreateTurnstileWidgetParams) (cf.TurnstileWidget, error) {
	return cf.TurnstileWidget{}, nil
}
func (*mockCFAPI) CreateWorkerRoute(_ context.Context, _ *cf.ResourceContainer, _ cf.CreateWorkerRouteParams) (cf.WorkerRouteResponse, error) {
	return cf.WorkerRouteResponse{}, nil
}
func (*mockCFAPI) CreateWorkersKVNamespace(_ context.Context, _ *cf.ResourceContainer, _ cf.CreateWorkersKVNamespaceParams) (cf.WorkersKVNamespaceResponse, error) {
	return cf.WorkersKVNamespaceResponse{}, nil
}
func (*mockCFAPI) DeleteTurnstileWidget(_ context.Context, _ *cf.ResourceContainer, _ string) error {
	return nil
}
func (*mockCFAPI) DeleteWorker(_ context.Context, _ *cf.ResourceContainer, _ cf.DeleteWorkerParams) error {
	return nil
}
func (*mockCFAPI) DeleteWorkerRoute(_ context.Context, _ *cf.ResourceContainer, _ string) (cf.WorkerRouteResponse, error) {
	return cf.WorkerRouteResponse{}, nil
}
func (*mockCFAPI) DeleteWorkersKVEntries(_ context.Context, _ *cf.ResourceContainer, _ cf.DeleteWorkersKVEntriesParams) (cf.Response, error) {
	return cf.Response{}, nil
}
func (m *mockCFAPI) DeleteWorkersKVNamespace(ctx context.Context, rc *cf.ResourceContainer, namespaceID string) (cf.Response, error) {
	m.deleteKVCalls = append(m.deleteKVCalls, namespaceID)
	if m.deleteWorkersKVNamespaceFn != nil {
		return m.deleteWorkersKVNamespaceFn(ctx, rc, namespaceID)
	}
	return cf.Response{}, nil
}
func (*mockCFAPI) ListTurnstileWidgets(_ context.Context, _ *cf.ResourceContainer, _ cf.ListTurnstileWidgetParams) ([]cf.TurnstileWidget, *cf.ResultInfo, error) {
	return nil, nil, nil
}
func (*mockCFAPI) ListWorkerRoutes(_ context.Context, _ *cf.ResourceContainer, _ cf.ListWorkerRoutesParams) (cf.WorkerRoutesResponse, error) {
	return cf.WorkerRoutesResponse{}, nil
}
func (m *mockCFAPI) ListWorkerBindings(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkerBindingsParams) (cf.WorkerBindingListResponse, error) {
	if m.listWorkerBindingsFn != nil {
		return m.listWorkerBindingsFn(ctx, rc, params)
	}
	return cf.WorkerBindingListResponse{}, nil
}
func (m *mockCFAPI) ListWorkersKVNamespaces(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error) {
	if m.listWorkersKVNamespacesFn != nil {
		return m.listWorkersKVNamespacesFn(ctx, rc, params)
	}
	return nil, nil, nil
}
func (*mockCFAPI) ListWorkersSecrets(_ context.Context, _ *cf.ResourceContainer, _ cf.ListWorkersSecretsParams) (cf.WorkersListSecretsResponse, error) {
	return cf.WorkersListSecretsResponse{}, nil
}
func (*mockCFAPI) ListZones(_ context.Context, _ ...string) ([]cf.Zone, error) {
	return nil, nil
}
func (*mockCFAPI) RotateTurnstileWidget(_ context.Context, _ *cf.ResourceContainer, _ cf.RotateTurnstileWidgetParams) (cf.TurnstileWidget, error) {
	return cf.TurnstileWidget{}, nil
}
func (*mockCFAPI) SetWorkersSecret(_ context.Context, _ *cf.ResourceContainer, _ cf.SetWorkersSecretParams) (cf.WorkersPutSecretResponse, error) {
	return cf.WorkersPutSecretResponse{}, nil
}
func (*mockCFAPI) UploadWorker(_ context.Context, _ *cf.ResourceContainer, _ cf.CreateWorkerParams) (cf.WorkerScriptResponse, error) {
	return cf.WorkerScriptResponse{}, nil
}
func (*mockCFAPI) UpdateWorkerCronTriggers(_ context.Context, _ *cf.ResourceContainer, _ cf.UpdateWorkerCronTriggersParams) ([]cf.WorkerCronTrigger, error) {
	return nil, nil
}
func (*mockCFAPI) WriteWorkersKVEntries(_ context.Context, _ *cf.ResourceContainer, _ cf.WriteWorkersKVEntriesParams) (cf.Response, error) {
	return cf.Response{}, nil
}
// ============================================================
// Group 1: queryAnalyticsEngine
// ============================================================

func TestQueryAnalyticsEngine_SendsRawSQL(t *testing.T) {
	emptyResponse := `{"meta":[],"data":[],"rows":0}`
	client, captured := captureRequestClient(emptyResponse)

	m := newTestManager()
	m.httpClient = client

	query := "SELECT blob1 FROM test_dataset FORMAT JSON"
	_, err := m.queryAnalyticsEngine(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if captured.Request.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", captured.Request.Header.Get("Content-Type"))
	}
	if captured.Request.Header.Get("Authorization") != "Bearer test-token" {
		t.Errorf("Authorization = %q, want Bearer test-token", captured.Request.Header.Get("Authorization"))
	}
	if captured.Body != query {
		t.Errorf("body = %q, want raw SQL %q", captured.Body, query)
	}
	wantURL := "https://api.cloudflare.com/client/v4/accounts/test-account-id/analytics_engine/sql"
	if captured.Request.URL.String() != wantURL {
		t.Errorf("URL = %q, want %q", captured.Request.URL.String(), wantURL)
	}
}

func TestQueryAnalyticsEngine_HTTPError(t *testing.T) {
	m := newTestManager()
	m.httpClient = makeAEErrorClient(403, "Forbidden: invalid token")

	_, err := m.queryAnalyticsEngine("SELECT 1")
	if err == nil {
		t.Fatal("expected error for HTTP 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should contain status code 403, got: %v", err)
	}
}

func TestQueryAnalyticsEngine_InvalidJSON(t *testing.T) {
	m := newTestManager()
	m.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			_, _ = io.ReadAll(r.Body)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("not json")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	_, err := m.queryAnalyticsEngine("SELECT 1")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

func TestQueryAnalyticsEngine_Success(t *testing.T) {
	m := newTestManager()
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "processed", "ip_type": "ipv4", "val": 42.0},
	})

	result, err := m.queryAnalyticsEngine("SELECT 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Rows != 1 {
		t.Errorf("Rows = %d, want 1", result.Rows)
	}
	if len(result.Data) != 1 {
		t.Fatalf("Data length = %d, want 1", len(result.Data))
	}
	if result.Data[0]["metric_name"] != "processed" {
		t.Errorf("metric_name = %v, want processed", result.Data[0]["metric_name"])
	}
}

// ============================================================
// Group 2: UpdateMetrics
// ============================================================

func TestUpdateMetrics_HappyPath(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "processed", "ip_type": "ipv4", "origin": "", "remediation_type": "", "val": 100.0, "avg_latency_ms": 12.5},
		{"metric_name": "dropped", "ip_type": "ipv6", "origin": "crowdsec", "remediation_type": "ban", "val": 7.0, "avg_latency_ms": 45.0},
	})

	if err := m.UpdateMetrics(); err != nil {
		t.Fatalf("UpdateMetrics failed: %v", err)
	}

	processed := gaugeValue(metrics.TotalProcessedRequests.With(prometheus.Labels{
		"ip_type": "ipv4", "account": "test-account",
	}))
	if processed != 100.0 {
		t.Errorf("processed = %f, want 100", processed)
	}

	dropped := gaugeValue(metrics.TotalBlockedRequests.With(prometheus.Labels{
		"origin": "crowdsec", "remediation": "ban", "ip_type": "ipv6", "account": "test-account",
	}))
	if dropped != 7.0 {
		t.Errorf("dropped = %f, want 7", dropped)
	}

	// Each grouped row gets its own label series — no last-row-wins.
	processedLatency := gaugeValue(metrics.AverageLatencyMs.With(prometheus.Labels{
		"account": "test-account", "metric_name": "processed", "ip_type": "ipv4", "remediation": "",
	}))
	if processedLatency != 12.5 {
		t.Errorf("processed avg_latency_ms = %f, want 12.5", processedLatency)
	}
	droppedLatency := gaugeValue(metrics.AverageLatencyMs.With(prometheus.Labels{
		"account": "test-account", "metric_name": "dropped", "ip_type": "ipv6", "remediation": "ban",
	}))
	if droppedLatency != 45.0 {
		t.Errorf("dropped avg_latency_ms = %f, want 45", droppedLatency)
	}
}

func TestUpdateMetrics_CumulativeTracking(t *testing.T) {
	resetMetrics()
	m := newTestManager()

	// First call: 10 processed
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "processed", "ip_type": "ipv4", "origin": "", "remediation_type": "", "val": 10.0},
		{"metric_name": "dropped", "ip_type": "ipv4", "origin": "crowdsec", "remediation_type": "ban", "val": 3.0},
	})
	if err := m.UpdateMetrics(); err != nil {
		t.Fatalf("first UpdateMetrics failed: %v", err)
	}

	// Second call: 5 more processed
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "processed", "ip_type": "ipv4", "origin": "", "remediation_type": "", "val": 5.0},
		{"metric_name": "dropped", "ip_type": "ipv4", "origin": "crowdsec", "remediation_type": "ban", "val": 2.0},
	})
	if err := m.UpdateMetrics(); err != nil {
		t.Fatalf("second UpdateMetrics failed: %v", err)
	}

	processed := gaugeValue(metrics.TotalProcessedRequests.With(prometheus.Labels{
		"ip_type": "ipv4", "account": "test-account",
	}))
	if processed != 15.0 {
		t.Errorf("processed = %f, want 15 (10+5)", processed)
	}

	dropped := gaugeValue(metrics.TotalBlockedRequests.With(prometheus.Labels{
		"origin": "crowdsec", "remediation": "ban", "ip_type": "ipv4", "account": "test-account",
	}))
	if dropped != 5.0 {
		t.Errorf("dropped = %f, want 5 (3+2)", dropped)
	}
}

func TestUpdateMetrics_ConcurrentSafety(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "processed", "ip_type": "ipv4", "origin": "", "remediation_type": "", "val": 1.0},
	})

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_ = m.UpdateMetrics()
		}()
	}
	wg.Wait()

	// Mutex serializes calls: each adds 1.0, total = 20.
	// The -race flag validates no data races.
	val := m.cumulativeMetrics["processed:ipv4:test-account"]
	if val != float64(goroutines) {
		t.Errorf("cumulative = %f, want %d", val, goroutines)
	}
}

func TestUpdateMetrics_InvalidMetricName(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": 12345, "val": 1.0}, // metric_name is not a string
	})

	err := m.UpdateMetrics()
	if err != nil {
		t.Fatalf("should not return error for bad metric_name type: %v", err)
	}
}

func TestUpdateMetrics_InvalidVal(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "processed", "ip_type": "ipv4", "val": "not-a-number"},
	})

	err := m.UpdateMetrics()
	if err != nil {
		t.Fatalf("should not return error for bad val type: %v", err)
	}
}

func TestUpdateMetrics_UnknownMetric(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "unknown_metric", "ip_type": "ipv4", "origin": "", "remediation_type": "", "val": 1.0},
	})

	err := m.UpdateMetrics()
	if err != nil {
		t.Fatalf("unknown metric should not cause error: %v", err)
	}
}

func TestUpdateMetrics_ErrorMetric(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "error", "ip_type": "ipv4", "origin": "", "remediation_type": "", "val": 3.0},
	})

	if err := m.UpdateMetrics(); err != nil {
		t.Fatalf("UpdateMetrics failed: %v", err)
	}

	errs := gaugeValue(metrics.TotalErrors.With(prometheus.Labels{
		"ip_type": "ipv4", "account": "test-account",
	}))
	if errs != 3.0 {
		t.Errorf("errors = %f, want 3", errs)
	}
}

func TestUpdateMetrics_EmptyResult(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	m.httpClient = makeAEResponseClient(nil)

	err := m.UpdateMetrics()
	if err != nil {
		t.Fatalf("empty result should not cause error: %v", err)
	}
	if len(m.cumulativeMetrics) != 0 {
		t.Errorf("cumulative should be empty, got %v", m.cumulativeMetrics)
	}
}

func TestUpdateMetrics_QueryError(t *testing.T) {
	m := newTestManager()
	originalPoll := m.lastMetricsPoll
	m.httpClient = makeAEErrorClient(500, "internal server error")

	err := m.UpdateMetrics()
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !m.lastMetricsPoll.Equal(originalPoll) {
		t.Error("lastMetricsPoll should not advance on error")
	}
}

func TestUpdateMetrics_AdvancesTimestamp(t *testing.T) {
	m := newTestManager()
	before := time.Now().UTC()
	m.lastMetricsPoll = before.Add(-5 * time.Minute)
	m.httpClient = makeAEResponseClient(nil)

	if err := m.UpdateMetrics(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// windowEnd intentionally lags wall-clock by aeIngestionLag (10s) so the
	// cursor doesn't read across the AE indexing boundary. Tolerate that lag
	// plus a small fudge for second-precision truncation.
	if !m.lastMetricsPoll.After(before.Add(-aeIngestionLag - 2*time.Second)) {
		t.Errorf("lastMetricsPoll should be ~(now - aeIngestionLag), got %v", m.lastMetricsPoll)
	}
}

func TestUpdateMetrics_QueryContainsTimestamp(t *testing.T) {
	emptyResp := `{"meta":[],"data":[],"rows":0}`
	client, captured := captureRequestClient(emptyResp)

	// AE supports only second-precision toDateTime; the sub-second component
	// of lastMetricsPoll is truncated in the lower bound.
	pollTime := time.Date(2025, 6, 15, 14, 30, 0, 123000000, time.UTC)
	m := newTestManager()
	m.lastMetricsPoll = pollTime
	m.httpClient = client

	_ = m.UpdateMetrics()

	if !strings.Contains(captured.Body, "timestamp >= toDateTime('2025-06-15 14:30:00')") {
		t.Errorf("query should contain second-precision lower bound, got:\n%s", captured.Body)
	}
	if !strings.Contains(captured.Body, "timestamp < toDateTime(") {
		t.Errorf("query should contain an upper window bound, got:\n%s", captured.Body)
	}
	if !strings.Contains(captured.Body, "FROM test_dataset") {
		t.Errorf("query should contain dataset name, got:\n%s", captured.Body)
	}
	if !strings.Contains(captured.Body, "FORMAT JSON") {
		t.Errorf("query should contain FORMAT JSON, got:\n%s", captured.Body)
	}
	if !strings.Contains(captured.Body, "AVG(double2) AS avg_latency_ms") {
		t.Errorf("query should contain latency aggregation, got:\n%s", captured.Body)
	}
}

func TestUpdateMetrics_QueryInterpolation_NoEscaping(t *testing.T) {
	// Account name is allowlist-validated at config load (see pkg/cfg). The
	// runtime query interpolates it directly without escaping; if a name
	// containing a single quote ever reached this code path it would terminate
	// the string literal and break the query, which is the failure we want.
	emptyResp := `{"meta":[],"data":[],"rows":0}`
	client, captured := captureRequestClient(emptyResp)

	m := newTestManager()
	m.AccountCfg.Name = "acme-prod"
	m.httpClient = client

	_ = m.UpdateMetrics()

	if !strings.Contains(captured.Body, "index1 = 'acme-prod'") {
		t.Errorf("expected literal account name in WHERE clause, got:\n%s", captured.Body)
	}
	if strings.Contains(captured.Body, `\'`) {
		t.Errorf("query should not contain backslash escapes (validation guarantees safe names), got:\n%s", captured.Body)
	}
}

func TestUpdateMetrics_MissingLatency_NoError(t *testing.T) {
	resetMetrics()
	m := newTestManager()
	// AE row missing the avg_latency_ms field — defensive against partial responses.
	m.httpClient = makeAEResponseClient([]map[string]any{
		{"metric_name": "processed", "ip_type": "ipv4", "origin": "", "remediation_type": "", "val": 5.0},
	})

	if err := m.UpdateMetrics(); err != nil {
		t.Fatalf("UpdateMetrics failed: %v", err)
	}

	processed := gaugeValue(metrics.TotalProcessedRequests.With(prometheus.Labels{
		"ip_type": "ipv4", "account": "test-account",
	}))
	if processed != 5.0 {
		t.Errorf("processed = %f, want 5", processed)
	}
}

// ============================================================
// Group 3: cleanupKVNamespaces — multi-instance teardown safety
// ============================================================

// When two bouncer instances share a Cloudflare account with the same
// kv_namespace_name, the worker-binding lookup is the authoritative way to
// tell which namespace belongs to THIS instance — a naive title-match
// would delete both, wiping the other instance's live decisions.
func TestCleanupKVNamespaces_AttributedByBinding_DeletesOnlyBoundID(t *testing.T) {
	mock := &mockCFAPI{
		listWorkersKVNamespacesFn: func(_ context.Context, _ *cf.ResourceContainer, _ cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error) {
			return []cf.WorkersKVNamespace{
				{ID: "ours-id", Title: "CROWDSECCFBOUNCERNS"},
				{ID: "other-instance-id", Title: "CROWDSECCFBOUNCERNS"},
				{ID: "unrelated-id", Title: "some-other-namespace"},
			}, nil, nil
		},
	}

	m := newTestManager()
	m.api = mock
	m.Worker.KVNameSpaceName = "CROWDSECCFBOUNCERNS"

	boundIDs := map[string]struct{}{"ours-id": {}}
	if err := m.cleanupKVNamespaces(boundIDs); err != nil {
		t.Fatalf("cleanupKVNamespaces returned error: %v", err)
	}

	if len(mock.deleteKVCalls) != 1 {
		t.Fatalf("expected exactly 1 KV delete, got %d: %v", len(mock.deleteKVCalls), mock.deleteKVCalls)
	}
	if mock.deleteKVCalls[0] != "ours-id" {
		t.Errorf("deleted %q, want ours-id (would have wiped sibling instance)", mock.deleteKVCalls[0])
	}
}

func TestCleanupKVNamespaces_NoBindings_FallsBackToTitleMatch(t *testing.T) {
	mock := &mockCFAPI{
		listWorkersKVNamespacesFn: func(_ context.Context, _ *cf.ResourceContainer, _ cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error) {
			return []cf.WorkersKVNamespace{
				{ID: "id-a", Title: "CROWDSECCFBOUNCERNS"},
				{ID: "id-b", Title: "CROWDSECCFBOUNCERNS"},
				{ID: "id-c", Title: "unrelated"},
			}, nil, nil
		},
	}

	m := newTestManager()
	m.api = mock
	m.Worker.KVNameSpaceName = "CROWDSECCFBOUNCERNS"

	if err := m.cleanupKVNamespaces(map[string]struct{}{}); err != nil {
		t.Fatalf("cleanupKVNamespaces returned error: %v", err)
	}

	// Fallback path: both title-matches get deleted (the WARN log makes the
	// operator aware of the collision risk; positive attribution is preferred).
	if len(mock.deleteKVCalls) != 2 {
		t.Fatalf("expected 2 deletes in fallback, got %d: %v", len(mock.deleteKVCalls), mock.deleteKVCalls)
	}
}

func TestCleanupKVNamespaces_NoMatches_NoOp(t *testing.T) {
	mock := &mockCFAPI{
		listWorkersKVNamespacesFn: func(_ context.Context, _ *cf.ResourceContainer, _ cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error) {
			return []cf.WorkersKVNamespace{
				{ID: "id-a", Title: "unrelated"},
			}, nil, nil
		},
	}

	m := newTestManager()
	m.api = mock
	m.Worker.KVNameSpaceName = "CROWDSECCFBOUNCERNS"

	if err := m.cleanupKVNamespaces(map[string]struct{}{}); err != nil {
		t.Fatalf("cleanupKVNamespaces returned error: %v", err)
	}
	if len(mock.deleteKVCalls) != 0 {
		t.Errorf("expected no deletes, got %d", len(mock.deleteKVCalls))
	}
}

func TestFindBoundKVNamespaceIDs_QueriesBothWorkerScripts(t *testing.T) {
	queried := []string{}
	mock := &mockCFAPI{
		listWorkerBindingsFn: func(_ context.Context, _ *cf.ResourceContainer, params cf.ListWorkerBindingsParams) (cf.WorkerBindingListResponse, error) {
			queried = append(queried, params.ScriptName)
			switch params.ScriptName {
			case "main-worker":
				return cf.WorkerBindingListResponse{
					BindingList: []cf.WorkerBindingListItem{
						{Name: cfg.KVWorkerBindingName, Binding: cf.WorkerKvNamespaceBinding{NamespaceID: "ns-main"}},
						{Name: "SOME_OTHER", Binding: cf.WorkerPlainTextBinding{Text: "x"}},
					},
				}, nil
			case "sync-worker":
				return cf.WorkerBindingListResponse{
					BindingList: []cf.WorkerBindingListItem{
						{Name: cfg.KVWorkerBindingName, Binding: cf.WorkerKvNamespaceBinding{NamespaceID: "ns-sync"}},
					},
				}, nil
			}
			return cf.WorkerBindingListResponse{}, nil
		},
	}

	m := newTestManager()
	m.api = mock
	m.Worker.ScriptName = "main-worker"
	m.Worker.DecisionsSyncScriptName = "sync-worker"

	ids := m.findBoundKVNamespaceIDs()

	if len(queried) != 2 {
		t.Errorf("expected to query 2 worker scripts, queried %d: %v", len(queried), queried)
	}
	if _, ok := ids["ns-main"]; !ok {
		t.Errorf("missing main worker's KV id; got %v", ids)
	}
	if _, ok := ids["ns-sync"]; !ok {
		t.Errorf("missing sync worker's KV id; got %v", ids)
	}
}

func TestFindBoundKVNamespaceIDs_HandlesNotFoundError(t *testing.T) {
	mock := &mockCFAPI{
		listWorkerBindingsFn: func(_ context.Context, _ *cf.ResourceContainer, _ cf.ListWorkerBindingsParams) (cf.WorkerBindingListResponse, error) {
			return cf.WorkerBindingListResponse{}, &cf.NotFoundError{}
		},
	}

	m := newTestManager()
	m.api = mock
	m.Worker.ScriptName = "missing-worker"
	m.Worker.DecisionsSyncScriptName = "missing-sync"

	ids := m.findBoundKVNamespaceIDs()

	if len(ids) != 0 {
		t.Errorf("expected empty result on 404, got %v", ids)
	}
}

// ============================================================
// Group 5: Manager Initialization
// ============================================================

func TestManagerInit_LastMetricsPollSet(t *testing.T) {
	m := newTestManager()
	if m.lastMetricsPoll.IsZero() {
		t.Error("lastMetricsPoll should not be zero")
	}
	elapsed := time.Since(m.lastMetricsPoll)
	if elapsed > 3*time.Minute || elapsed < 1*time.Minute {
		t.Errorf("lastMetricsPoll should be ~2min ago, got %v ago", elapsed)
	}
}

func TestManagerInit_CumulativeMetricsMap(t *testing.T) {
	m := newTestManager()
	if m.cumulativeMetrics == nil {
		t.Error("cumulativeMetrics should not be nil")
	}
	if len(m.cumulativeMetrics) != 0 {
		t.Errorf("cumulativeMetrics should be empty, got %v", m.cumulativeMetrics)
	}
}

func TestManagerInit_HttpClientSet(t *testing.T) {
	m := newTestManager()
	if m.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
}

// obsFromBody extracts the observability section from a JSON request body.
func obsFromBody(t *testing.T, rawBody string) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(rawBody), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	obs, ok := body["observability"].(map[string]any)
	if !ok {
		t.Fatal("body missing observability key")
	}
	return obs
}

func tracesFromObs(t *testing.T, obs map[string]any) map[string]any {
	t.Helper()
	traces, ok := obs["traces"].(map[string]any)
	if !ok {
		t.Fatal("body missing observability.traces key")
	}
	return traces
}

// --- Group 5: enableWorkerObservability ---

func TestEnableObservability_NilConfig_Skipped(t *testing.T) {
	m := newTestManager()
	// Transport that fails if any request is made
	m.httpClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("no HTTP request should be made when observability is nil")
			return nil, errors.New("unreachable")
		}),
	}
	m.Worker.Observability = nil

	if err := m.enableWorkerObservability("test-worker"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnableObservability_SendsCorrectRequest(t *testing.T) {
	m := newTestManager()
	client, captured := captureRequestClient(`{"success":true}`)
	m.httpClient = client

	enabled := true
	rate := 1.0
	m.Worker.Observability = &cfg.WorkerObservabilityConfig{
		Enabled:          &enabled,
		HeadSamplingRate: &rate,
	}

	if err := m.enableWorkerObservability("my-worker"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if captured.Request.Method != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", captured.Request.Method)
	}
	wantURL := "https://api.cloudflare.com/client/v4/accounts/test-account-id/workers/scripts/my-worker/script-settings"
	if captured.Request.URL.String() != wantURL {
		t.Errorf("URL = %s, want %s", captured.Request.URL.String(), wantURL)
	}
	if captured.Request.Header.Get("Authorization") != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", captured.Request.Header.Get("Authorization"), "Bearer test-token")
	}
	if captured.Request.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", captured.Request.Header.Get("Content-Type"))
	}

	obs := obsFromBody(t, captured.Body)
	if enabled, ok := obs["enabled"].(bool); !ok || !enabled {
		t.Errorf("enabled = %v, want true", obs["enabled"])
	}
	if obs["head_sampling_rate"] != 1.0 {
		t.Errorf("head_sampling_rate = %v, want 1", obs["head_sampling_rate"])
	}

	traces := tracesFromObs(t, obs)
	if enabled, ok := traces["enabled"].(bool); !ok || !enabled {
		t.Errorf("traces.enabled = %v, want true", traces["enabled"])
	}
	if traces["head_sampling_rate"] != 1.0 {
		t.Errorf("traces.head_sampling_rate = %v, want 1", traces["head_sampling_rate"])
	}
}

func TestEnableObservability_CustomSamplingRate(t *testing.T) {
	m := newTestManager()
	client, captured := captureRequestClient(`{"success":true}`)
	m.httpClient = client

	enabled := true
	rate := 0.05
	m.Worker.Observability = &cfg.WorkerObservabilityConfig{
		Enabled:          &enabled,
		HeadSamplingRate: &rate,
	}

	if err := m.enableWorkerObservability("my-worker"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	obs := obsFromBody(t, captured.Body)
	if obs["head_sampling_rate"] != 0.05 {
		t.Errorf("head_sampling_rate = %v, want 0.05", obs["head_sampling_rate"])
	}
}

func TestEnableObservability_HTTPError(t *testing.T) {
	m := newTestManager()
	m.httpClient = makeAEErrorClient(500, "internal server error")

	enabled := true
	m.Worker.Observability = &cfg.WorkerObservabilityConfig{Enabled: &enabled}

	err := m.enableWorkerObservability("my-worker")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should contain status code: %v", err)
	}
}

func TestEnableObservability_DefaultValues(t *testing.T) {
	m := newTestManager()
	client, captured := captureRequestClient(`{"success":true}`)
	m.httpClient = client

	// Non-nil config but both fields nil — should default to enabled=true, rate=1.0
	m.Worker.Observability = &cfg.WorkerObservabilityConfig{}

	if err := m.enableWorkerObservability("my-worker"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	obs := obsFromBody(t, captured.Body)
	if enabled, ok := obs["enabled"].(bool); !ok || !enabled {
		t.Errorf("enabled = %v, want true (default)", obs["enabled"])
	}
	if obs["head_sampling_rate"] != 1.0 {
		t.Errorf("head_sampling_rate = %v, want 1.0 (default)", obs["head_sampling_rate"])
	}

	// Traces should inherit top-level defaults
	traces := tracesFromObs(t, obs)
	if enabled, ok := traces["enabled"].(bool); !ok || !enabled {
		t.Errorf("traces.enabled = %v, want true (default)", traces["enabled"])
	}
	if traces["head_sampling_rate"] != 1.0 {
		t.Errorf("traces.head_sampling_rate = %v, want 1.0 (default)", traces["head_sampling_rate"])
	}
}

func TestEnableObservability_NetworkError(t *testing.T) {
	m := newTestManager()
	m.httpClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}),
	}
	enabled := true
	m.Worker.Observability = &cfg.WorkerObservabilityConfig{Enabled: &enabled}

	err := m.enableWorkerObservability("my-worker")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "observability settings request failed") {
		t.Errorf("error should mention request failure: %v", err)
	}
}

func TestEnableObservability_CustomTracesConfig(t *testing.T) {
	m := newTestManager()
	client, captured := captureRequestClient(`{"success":true}`)
	m.httpClient = client

	enabled := true
	logRate := 1.0
	traceRate := 0.1
	m.Worker.Observability = &cfg.WorkerObservabilityConfig{
		Enabled:          &enabled,
		HeadSamplingRate: &logRate,
		Traces: &cfg.WorkerTracesConfig{
			Enabled:          &enabled,
			HeadSamplingRate: &traceRate,
		},
	}

	if err := m.enableWorkerObservability("my-worker"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	obs := obsFromBody(t, captured.Body)
	if obs["head_sampling_rate"] != 1.0 {
		t.Errorf("log sampling rate = %v, want 1.0", obs["head_sampling_rate"])
	}
	traces := tracesFromObs(t, obs)
	if traces["head_sampling_rate"] != 0.1 {
		t.Errorf("trace sampling rate = %v, want 0.1", traces["head_sampling_rate"])
	}
}

func TestEnableObservability_ExplicitlyDisabled(t *testing.T) {
	m := newTestManager()
	client, captured := captureRequestClient(`{"success":true}`)
	m.httpClient = client

	enabled := false
	m.Worker.Observability = &cfg.WorkerObservabilityConfig{Enabled: &enabled}

	if err := m.enableWorkerObservability("my-worker"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	obs := obsFromBody(t, captured.Body)
	if enabled, ok := obs["enabled"].(bool); !ok || enabled {
		t.Errorf("enabled = %v, want false", obs["enabled"])
	}
}
