package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/semconv/v1.41.0/httpconv"
)

// scope is the instrumentation scope Darbaan's metrics are under.
const scope = "github.com/yaad-index/darbaan"

// Darbaan's own names (ADR 0040 point 7).
const (
	metricOutbound       = "darbaan.outbound.messages"
	metricPending        = "darbaan.outbound.pending"
	metricSendDuration   = "darbaan.send.duration"
	metricHoldDecisions  = "darbaan.inbound.hold_decisions"
	metricSyncRuns       = "darbaan.sync.runs"
	metricSyncDuration   = "darbaan.sync.duration"
	keyOutboundEvent     = attribute.Key("darbaan.outbound.event")
	keyHoldDecision      = attribute.Key("darbaan.hold.decision")
	keyOutcome           = attribute.Key("darbaan.outcome")
	outcomeOK, outcomeKO = "ok", "failed"
)

// Event is what happened to an outbound message: darbaan.outbound.event.
type Event string

// The outbound events.
const (
	// Queued is a submission trapped as pending.
	Queued Event = "queued"
	// Approved and Rejected are the approval chain's decisions.
	Approved Event = "approved"
	Rejected Event = "rejected"
	// Sent and SendFailed are attempts to release an approved message upstream.
	Sent       Event = "sent"
	SendFailed Event = "send_failed"
)

// Decision is an operator's verdict on a held inbound message:
// darbaan.hold.decision.
type Decision string

// The hold decisions.
const (
	Exposed Decision = "exposed"
	Dropped Decision = "dropped"
)

// DurationBuckets are the bucket boundaries of every duration histogram, in
// seconds: the semantic conventions' advised set, 10ms to about 82s. The SDK's
// defaults (0, 5, 10, 25 ...) are sized for milliseconds.
var DurationBuckets = []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92}

// Metrics records Darbaan's metrics. A nil *Metrics records nothing.
type Metrics struct {
	meter         metric.Meter
	outbound      metric.Int64Counter
	sendDuration  metric.Float64Histogram
	holdDecisions metric.Int64Counter
	syncRuns      metric.Int64Counter
	syncDuration  metric.Float64Histogram
	httpServer    httpconv.ServerRequestDuration
	httpClient    httpconv.ClientRequestDuration
}

// New returns Metrics recording through mp.
func New(mp metric.MeterProvider) (*Metrics, error) {
	m := mp.Meter(scope)
	buckets := metric.WithExplicitBucketBoundaries(DurationBuckets...)
	out := &Metrics{meter: m}
	var err error
	if out.outbound, err = m.Int64Counter(metricOutbound, metric.WithUnit("{message}"),
		metric.WithDescription("Outbound messages by what happened to them: queued, approved, rejected, sent, send_failed.")); err != nil {
		return nil, err
	}
	if out.sendDuration, err = m.Float64Histogram(metricSendDuration, metric.WithUnit("s"),
		metric.WithDescription("How long releasing an approved message to the upstream SMTP server took."), buckets); err != nil {
		return nil, err
	}
	if out.holdDecisions, err = m.Int64Counter(metricHoldDecisions, metric.WithUnit("{message}"),
		metric.WithDescription("Held inbound messages an operator exposed or dropped.")); err != nil {
		return nil, err
	}
	if out.syncRuns, err = m.Int64Counter(metricSyncRuns, metric.WithUnit("{run}"),
		metric.WithDescription("Upstream IMAP sync runs, by outcome.")); err != nil {
		return nil, err
	}
	if out.syncDuration, err = m.Float64Histogram(metricSyncDuration, metric.WithUnit("s"),
		metric.WithDescription("How long an upstream IMAP sync run took."), buckets); err != nil {
		return nil, err
	}
	if out.httpServer, err = httpconv.NewServerRequestDuration(m, buckets); err != nil {
		return nil, err
	}
	if out.httpClient, err = httpconv.NewClientRequestDuration(m, buckets); err != nil {
		return nil, err
	}
	return out, nil
}

// Outbound counts an approval-chain event: Queued, Approved or Rejected.
func (m *Metrics) Outbound(ctx context.Context, e Event) {
	if m == nil {
		return
	}
	m.outbound.Add(ctx, 1, metric.WithAttributes(keyOutboundEvent.String(string(e))))
}

// Send records an attempt to release a message upstream: how long it took,
// and Sent or SendFailed with the failure's kind.
func (m *Metrics) Send(ctx context.Context, took time.Duration, err error) {
	if m == nil {
		return
	}
	if err != nil {
		kind := semconv.ErrorTypeKey.String(ErrorKind(err))
		m.sendDuration.Record(ctx, took.Seconds(), metric.WithAttributes(keyOutcome.String(outcomeKO), kind))
		m.outbound.Add(ctx, 1, metric.WithAttributes(keyOutboundEvent.String(string(SendFailed)), kind))
		return
	}
	m.sendDuration.Record(ctx, took.Seconds(), metric.WithAttributes(keyOutcome.String(outcomeOK)))
	m.outbound.Add(ctx, 1, metric.WithAttributes(keyOutboundEvent.String(string(Sent))))
}

// HoldDecision counts an operator's verdict on a held inbound message.
func (m *Metrics) HoldDecision(ctx context.Context, d Decision) {
	if m == nil {
		return
	}
	m.holdDecisions.Add(ctx, 1, metric.WithAttributes(keyHoldDecision.String(string(d))))
}

// SyncRun records one upstream sync run: how long it took and its outcome,
// with the failure's kind.
func (m *Metrics) SyncRun(ctx context.Context, took time.Duration, err error) {
	if m == nil {
		return
	}
	attrs := []attribute.KeyValue{keyOutcome.String(outcomeOK)}
	if err != nil {
		attrs = []attribute.KeyValue{keyOutcome.String(outcomeKO), semconv.ErrorTypeKey.String(ErrorKind(err))}
	}
	m.syncRuns.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.syncDuration.Record(ctx, took.Seconds(), metric.WithAttributes(attrs...))
}

// ObservePending reports the outbound messages waiting for a decision, read
// from pending at each collection. A failed read reports nothing that time.
func (m *Metrics) ObservePending(pending func() (int64, error)) error {
	if m == nil {
		return nil
	}
	g, err := m.meter.Int64ObservableGauge(metricPending, metric.WithUnit("{message}"),
		metric.WithDescription("Outbound messages waiting for a decision."))
	if err != nil {
		return err
	}
	_, err = m.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		n, err := pending()
		if err != nil {
			return nil
		}
		o.ObserveInt64(g, n)
		return nil
	}, g)
	return err
}
