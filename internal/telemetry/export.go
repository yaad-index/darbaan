// Package telemetry is Darbaan's OpenTelemetry metrics (ADR 0040): their
// export over OTLP, the instruments, and the closed sets their attribute
// values come from. It exports metrics only, never traces, and no attribute
// carries mail, configuration text or anything a remote party sent.
package telemetry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

// Exporter sends the metrics made with its meter provider to the collector.
type Exporter struct {
	MeterProvider *sdkmetric.MeterProvider
}

// Setup returns the exporter the environment configures, for Darbaan at
// version, or nil when metrics are not exported: no OTLP endpoint is set for
// them, or OTEL_SDK_DISABLED is true (ADR 0040 point 1).
//
// The exporter reads its endpoint, headers, timeout, compression and
// certificate from the OTEL_EXPORTER_OTLP_* variables itself; Setup reads only
// whether an endpoint is set and the protocol. OTEL_RESOURCE_ATTRIBUTES adds
// resource attributes, for example to tell two deployments apart.
func Setup(ctx context.Context, version string) (*Exporter, error) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true") {
		return nil, nil
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") == "" {
		return nil, nil
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("darbaan"), semconv.ServiceVersion(version)),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry resource: %w", err)
	}
	exp, err := metricExporter(ctx)
	if err != nil {
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)), sdkmetric.WithResource(res))
	return &Exporter{MeterProvider: mp}, nil
}

// Shutdown sends what is still buffered and stops the meter provider.
func (e *Exporter) Shutdown(ctx context.Context) error {
	return e.MeterProvider.Shutdown(ctx)
}

// The OTLP protocols Darbaan exports with. http/protobuf is the standard's
// default; http/json has no Go exporter.
const (
	protocolGRPC = "grpc"
	protocolHTTP = "http/protobuf"
)

// protocol is the metrics protocol: its own variable, else the shared one,
// else the standard's default.
func protocol() (string, error) {
	p := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")
	if p == "" {
		p = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	switch p = strings.TrimSpace(p); p {
	case "":
		return protocolHTTP, nil
	case protocolGRPC, protocolHTTP:
		return p, nil
	}
	return "", fmt.Errorf("OTLP protocol %q is not supported for metrics: use %q or %q", p, protocolHTTP, protocolGRPC)
}

func metricExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	p, err := protocol()
	if err != nil {
		return nil, err
	}
	if p == protocolGRPC {
		return otlpmetricgrpc.New(ctx)
	}
	return otlpmetrichttp.New(ctx)
}
