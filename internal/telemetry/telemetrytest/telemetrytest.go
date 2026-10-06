// Package telemetrytest reads back what a telemetry.Metrics recorded, for tests.
package telemetrytest

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/yaad-index/darbaan/internal/telemetry"
)

// Point is one data point: its attributes and its value. A histogram's value
// is its count and Sum its sum; a counter's or gauge's value is the value.
type Point struct {
	Attrs map[string]string
	Value int64
	Sum   float64
}

// Instrument is what one instrument recorded. Bounds are a histogram's bucket
// boundaries, from its first point.
type Instrument struct {
	Unit   string
	Points []Point
	Bounds []float64
}

// New returns Metrics and a function that collects what they recorded, by
// instrument name.
func New(t *testing.T) (*telemetry.Metrics, func() map[string]Instrument) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	m, err := telemetry.New(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	return m, func() map[string]Instrument {
		t.Helper()
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		out := map[string]Instrument{}
		for _, sm := range rm.ScopeMetrics {
			for _, md := range sm.Metrics {
				out[md.Name] = Instrument{Unit: md.Unit, Points: points(t, md.Data), Bounds: bounds(md.Data)}
			}
		}
		return out
	}
}

func points(t *testing.T, data metricdata.Aggregation) []Point {
	var out []Point
	switch d := data.(type) {
	case metricdata.Sum[int64]:
		for _, p := range d.DataPoints {
			out = append(out, Point{Attrs: attrs(p.Attributes.ToSlice()), Value: p.Value})
		}
	case metricdata.Gauge[int64]:
		for _, p := range d.DataPoints {
			out = append(out, Point{Attrs: attrs(p.Attributes.ToSlice()), Value: p.Value})
		}
	case metricdata.Histogram[int64]:
		for _, p := range d.DataPoints {
			out = append(out, Point{Attrs: attrs(p.Attributes.ToSlice()), Value: int64(p.Count), Sum: float64(p.Sum)})
		}
	case metricdata.Histogram[float64]:
		for _, p := range d.DataPoints {
			out = append(out, Point{Attrs: attrs(p.Attributes.ToSlice()), Value: int64(p.Count), Sum: p.Sum})
		}
	default:
		t.Fatalf("metric data %T is not read", data)
	}
	return out
}

func bounds(data metricdata.Aggregation) []float64 {
	switch d := data.(type) {
	case metricdata.Histogram[int64]:
		if len(d.DataPoints) > 0 {
			return d.DataPoints[0].Bounds
		}
	case metricdata.Histogram[float64]:
		if len(d.DataPoints) > 0 {
			return d.DataPoints[0].Bounds
		}
	}
	return nil
}

func attrs(kvs []attribute.KeyValue) map[string]string {
	out := map[string]string{}
	for _, kv := range kvs {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}
