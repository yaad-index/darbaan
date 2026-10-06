package telemetry_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	colmetric "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaad-index/darbaan/internal/telemetry"
)

// clearEnv unsets every variable Setup reads, so the host's own cannot
// change a test.
func clearEnv(t *testing.T) {
	for _, k := range []string{
		"OTEL_SDK_DISABLED", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
	} {
		t.Setenv(k, "")
	}
}

func TestExportIsOffWithoutAMetricsEndpoint(t *testing.T) {
	clearEnv(t)
	e, err := telemetry.Setup(context.Background(), "v1")
	require.NoError(t, err)
	assert.Nil(t, e)

	// A traces endpoint alone exports nothing: Darbaan has no traces.
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:1")
	e, err = telemetry.Setup(context.Background(), "v1")
	require.NoError(t, err)
	assert.Nil(t, e)
}

func TestExportIsOffWhenTheSDKIsDisabled(t *testing.T) {
	clearEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	e, err := telemetry.Setup(context.Background(), "v1")
	require.NoError(t, err)
	assert.Nil(t, e)
}

func TestAnUnsupportedProtocolIsRefused(t *testing.T) {
	clearEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/json")
	_, err := telemetry.Setup(context.Background(), "v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"http/json"`)
}

// A metric reaches the endpoint over OTLP/HTTP under service darbaan at its
// version, by the time Shutdown returns.
func TestAMetricReachesTheEndpoint(t *testing.T) {
	var mu sync.Mutex
	var res map[string]string
	var names []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/metrics" {
			body, _ := io.ReadAll(r.Body)
			var req colmetric.ExportMetricsServiceRequest
			if proto.Unmarshal(body, &req) == nil {
				mu.Lock()
				for _, rm := range req.ResourceMetrics {
					res = map[string]string{}
					for _, kv := range rm.Resource.Attributes {
						res[kv.Key] = kv.Value.GetStringValue()
					}
					for _, sm := range rm.ScopeMetrics {
						for _, m := range sm.Metrics {
							names = append(names, m.Name)
						}
					}
				}
				mu.Unlock()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clearEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	e, err := telemetry.Setup(context.Background(), "v1.2.3")
	require.NoError(t, err)
	require.NotNil(t, e)
	m, err := telemetry.New(e.MeterProvider)
	require.NoError(t, err)
	m.Outbound(context.Background(), telemetry.Queued)
	require.NoError(t, e.Shutdown(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "darbaan", res["service.name"])
	assert.Equal(t, "v1.2.3", res["service.version"])
	assert.Contains(t, names, "darbaan.outbound.messages")
}
