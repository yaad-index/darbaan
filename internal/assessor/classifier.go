package assessor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// ClassifierTokenEnv names the environment variable holding the classifier's
// bearer token. It is read only when the classifier detector is built and is
// sent only to the classifier endpoint (ADR 0038 section 3).
const ClassifierTokenEnv = "DARBAAN_CLASSIFIER_TOKEN"

// BackendHTTP is the one classifier backend: an HTTP endpoint taking
// {"text": "..."} and answering {"labels": [{"label", "confidence"}], "truncated"}.
const BackendHTTP = "http"

// ErrClassifierUnavailable wraps every classifier failure: an unreachable or
// refused endpoint, a timeout, a bad reply, or a message too long to cover. The
// assessment fails with it and the message is held (ADR 0038 section 4).
var ErrClassifierUnavailable = errors.New("classifier unavailable")

// Classifier defaults. The thresholds are a starting point from a small smoke test
// of one model, not a tuned value: the operator is expected to set their own.
const (
	defaultClassifierTimeout = 3 * time.Second
	defaultWindowRunes       = 1000
	defaultOverlapRunes      = 200
	defaultMaxWindows        = 32
	minSplitRunes            = 64
	maxReplyBytes            = 64 << 10
)

// ClassifierConfig is `assessment.detector.classifier:` (ADR 0038). It is off
// unless enabled.
type ClassifierConfig struct {
	Enabled bool   `yaml:"enabled"`
	Backend string `yaml:"backend"`
	// Endpoint is the full URL of the classify call.
	Endpoint string        `yaml:"endpoint"`
	Timeout  time.Duration `yaml:"timeout"`
	// AllowRemote permits an endpoint that is neither loopback nor in PrivateHosts.
	// It is decided by the address actually connected to, whatever the backend.
	AllowRemote bool `yaml:"allow_remote"`
	// PrivateHosts are IP addresses or CIDR prefixes treated as this operator's own
	// machines, so sending text to them needs no allow_remote.
	PrivateHosts []string `yaml:"private_hosts"`
	// WindowRunes, OverlapRunes and MaxWindows shape how a long body is covered:
	// overlapping windows over the whole text, the highest confidence per label
	// taken across them. A body needing more than MaxWindows fails the detector,
	// so the message is held rather than classified in part.
	WindowRunes  int `yaml:"window_runes"`
	OverlapRunes int `yaml:"overlap_runes"`
	MaxWindows   int `yaml:"max_windows"`
	// Labels maps each classifier label to the factor it flags and the confidence
	// at or above which it does. A label the classifier returns that is not listed
	// here flags nothing. Empty selects DefaultClassifierLabels.
	Labels map[string]LabelConfig `yaml:"labels"`
}

// LabelConfig maps one classifier label to a factor.
type LabelConfig struct {
	Factor    riskscore.Factor `yaml:"factor"`
	Threshold float64          `yaml:"threshold"`
}

// DefaultClassifierLabels is the map used when the operator gives none. It leaves
// hidden_directives unmapped: in the 2026-09-28 smoke test of the first model it
// separated nothing, so mapping it would only add noise to scores.
func DefaultClassifierLabels() map[string]LabelConfig {
	return map[string]LabelConfig{
		"instruction_to_reader": {Factor: riskscore.FactorInstruction, Threshold: 0.9},
		"secrets_request":       {Factor: riskscore.FactorSecretsRequest, Threshold: 0.8},
	}
}

// ClassifierDetector sends a message's body text to a classification endpoint
// and flags factors from the labels it returns (ADR 0038 sections 2 and 3).
type ClassifierDetector struct {
	endpoint     *url.URL
	token        string
	timeout      time.Duration
	window       int
	overlap      int
	maxWindows   int
	labels       map[string]LabelConfig
	client       *http.Client
	policy       addrPolicy
	allowRemote  bool
	resolvedHost []netip.Addr
}

// NewClassifierDetector validates cfg and builds the detector. It resolves the
// endpoint's host and refuses an address that is neither loopback nor a private
// host unless allow_remote is set, so a misdirected endpoint stops startup. The
// same rule is enforced again on every connection (see addrPolicy.control).
func NewClassifierDetector(ctx context.Context, cfg ClassifierConfig, token string) (*ClassifierDetector, error) {
	cfg, err := normalizeClassifier(cfg)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(cfg.Endpoint) // validated by normalizeClassifier
	policy, _ := newAddrPolicy(cfg.PrivateHosts, cfg.AllowRemote)
	addrs, err := lookupHost(ctx, u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("assessor: classifier endpoint %q: %w", cfg.Endpoint, err)
	}
	for _, a := range addrs {
		if !policy.allows(a) {
			return nil, fmt.Errorf("assessor: classifier endpoint %q resolves to %s, which is not loopback and not in private_hosts; "+
				"sending mail text there needs allow_remote: true", cfg.Endpoint, a)
		}
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout, Control: policy.control}
	transport := &http.Transport{
		// No proxy, whatever the environment says: through a proxy the address
		// connected to would be the proxy's, and the remote check would pass on it.
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    cfg.Timeout,
		ResponseHeaderTimeout:  cfg.Timeout,
		MaxResponseHeaderBytes: 16 << 10,
		MaxIdleConns:           4,
		IdleConnTimeout:        90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		// A redirect would send the text to a second address the startup check
		// never saw, so none is followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &ClassifierDetector{
		endpoint: u, token: token, timeout: cfg.Timeout,
		window: cfg.WindowRunes, overlap: cfg.OverlapRunes, maxWindows: cfg.MaxWindows,
		labels: cfg.Labels, client: client, policy: policy, allowRemote: cfg.AllowRemote, resolvedHost: addrs,
	}, nil
}

// ValidateClassifierConfig checks cfg without resolving or contacting the
// endpoint, so a bad section fails startup even while the classifier is off.
func ValidateClassifierConfig(cfg ClassifierConfig) error {
	_, err := normalizeClassifier(cfg)
	return err
}

func normalizeClassifier(cfg ClassifierConfig) (ClassifierConfig, error) {
	if cfg.Backend == "" {
		cfg.Backend = BackendHTTP
	}
	if cfg.Backend != BackendHTTP {
		return cfg, fmt.Errorf("assessor: classifier.backend %q: the only backend is %q", cfg.Backend, BackendHTTP)
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return cfg, fmt.Errorf("assessor: classifier.endpoint %q must be an http or https URL with a host", cfg.Endpoint)
	}
	if u.User != nil {
		return cfg, fmt.Errorf("assessor: classifier.endpoint must not carry credentials; the token comes from %s", ClassifierTokenEnv)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultClassifierTimeout
	}
	if cfg.Timeout < 0 {
		return cfg, fmt.Errorf("assessor: classifier.timeout must be positive")
	}
	if _, err := newAddrPolicy(cfg.PrivateHosts, cfg.AllowRemote); err != nil {
		return cfg, err
	}
	if cfg.WindowRunes == 0 {
		cfg.WindowRunes = defaultWindowRunes
	}
	if cfg.OverlapRunes == 0 {
		cfg.OverlapRunes = defaultOverlapRunes
	}
	if cfg.MaxWindows == 0 {
		cfg.MaxWindows = defaultMaxWindows
	}
	if cfg.WindowRunes < 2*minSplitRunes {
		return cfg, fmt.Errorf("assessor: classifier.window_runes must be at least %d", 2*minSplitRunes)
	}
	if cfg.OverlapRunes < 0 || cfg.OverlapRunes*2 > cfg.WindowRunes {
		return cfg, fmt.Errorf("assessor: classifier.overlap_runes must be between 0 and half of window_runes")
	}
	if cfg.MaxWindows < 1 {
		return cfg, fmt.Errorf("assessor: classifier.max_windows must be at least 1")
	}
	if len(cfg.Labels) == 0 {
		cfg.Labels = DefaultClassifierLabels()
	}
	for name, lc := range cfg.Labels {
		if strings.TrimSpace(name) == "" {
			return cfg, fmt.Errorf("assessor: classifier.labels: an empty label name")
		}
		if lc.Factor == "" {
			return cfg, fmt.Errorf("assessor: classifier.labels.%s: factor is required", name)
		}
		if !(lc.Threshold > 0 && lc.Threshold <= 1) {
			return cfg, fmt.Errorf("assessor: classifier.labels.%s: threshold must be above 0 and at most 1", name)
		}
	}
	return cfg, nil
}

// Factors returns the factors the configured labels can flag, sorted.
func (d *ClassifierDetector) Factors() []riskscore.Factor {
	seen := make(map[riskscore.Factor]struct{}, len(d.labels))
	for _, lc := range d.labels {
		seen[lc.Factor] = struct{}{}
	}
	out := make([]riskscore.Factor, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Timeout is the classifier's own bound on one message, inside the assessor's.
func (d *ClassifierDetector) Timeout() time.Duration { return d.timeout }

// Describe names the backend and where the text goes, for the startup warning.
func (d *ClassifierDetector) Describe() (backend, endpoint string, hosts []string, remote bool) {
	for _, a := range d.resolvedHost {
		hosts = append(hosts, a.String())
		if !a.IsLoopback() {
			remote = true
		}
	}
	return BackendHTTP, d.endpoint.Redacted(), hosts, remote
}

// Detect returns the factors DetectFindings flags.
func (d *ClassifierDetector) Detect(ctx context.Context, c mailtext.Content) ([]riskscore.Factor, error) {
	fs, err := d.DetectFindings(ctx, c)
	if err != nil {
		return nil, err
	}
	out := make([]riskscore.Factor, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Factor)
	}
	return out, nil
}

// DetectFindings classifies the whole body, window by window, and flags each
// configured label whose highest confidence across the windows reaches its
// threshold. Any failure, including a body too long for max_windows, is returned
// wrapped in ErrClassifierUnavailable. The body only: attachment text stays with
// the pattern detector.
func (d *ClassifierDetector) DetectFindings(ctx context.Context, c mailtext.Content) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	text := []rune(c.Body)
	if strings.TrimSpace(c.Body) == "" {
		return nil, nil
	}
	windows := splitWindows(len(text), d.window, d.overlap)
	if len(windows) > d.maxWindows {
		return nil, fmt.Errorf("%w: the body needs %d windows, more than max_windows %d", ErrClassifierUnavailable, len(windows), d.maxWindows)
	}
	best := make(map[string]float64, len(d.labels))
	calls := 0
	for len(windows) > 0 {
		w := windows[0]
		windows = windows[1:]
		calls++
		if calls > d.maxWindows {
			return nil, fmt.Errorf("%w: covering the body took more than max_windows %d calls", ErrClassifierUnavailable, d.maxWindows)
		}
		got, truncated, err := d.classify(ctx, string(text[w.start:w.end]))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrClassifierUnavailable, err)
		}
		if truncated {
			// The classifier read only part of this window, so its scores do not
			// cover it. Split it and classify both halves instead; the halves
			// overlap so nothing straddling the cut is lost.
			if w.end-w.start < 2*minSplitRunes {
				return nil, fmt.Errorf("%w: the classifier cannot read even a %d-rune window whole", ErrClassifierUnavailable, w.end-w.start)
			}
			n := w.end - w.start
			windows = append(splitWindows(n, (n+1)/2+d.overlap/2, d.overlap/2).offset(w.start), windows...)
			continue
		}
		for label, p := range got {
			if p > best[label] {
				best[label] = p
			}
		}
	}
	var out []Finding
	for label, lc := range d.labels {
		if p := best[label]; p >= lc.Threshold {
			out = append(out, Finding{Factor: lc.Factor, Detector: DetectorClassifier, Label: label, Confidence: p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

// classifyReply is the part of the endpoint's reply the detector reads.
type classifyReply struct {
	Labels []struct {
		Label      string   `json:"label"`
		Confidence *float64 `json:"confidence"`
	} `json:"labels"`
	Truncated bool `json:"truncated"`
}

// classify sends one window and returns the confidence of every configured label.
// A reply missing a configured label, or carrying a confidence that is not a
// number in [0, 1], is a failure, never a zero.
func (d *ClassifierDetector) classify(ctx context.Context, text string) (map[string]float64, bool, error) {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("endpoint answered %d", resp.StatusCode)
	}
	if len(raw) > maxReplyBytes {
		return nil, false, fmt.Errorf("reply larger than %d bytes", maxReplyBytes)
	}
	var rep classifyReply
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, false, fmt.Errorf("reply is not the classify contract: %w", err)
	}
	got := make(map[string]float64, len(d.labels))
	for _, l := range rep.Labels {
		if _, want := d.labels[l.Label]; !want {
			continue // a label nobody mapped flags nothing
		}
		if l.Confidence == nil || math.IsNaN(*l.Confidence) || *l.Confidence < 0 || *l.Confidence > 1 {
			return nil, false, fmt.Errorf("label %q has no confidence in [0, 1]", l.Label)
		}
		got[l.Label] = *l.Confidence
	}
	for label := range d.labels {
		if _, ok := got[label]; !ok {
			return nil, false, fmt.Errorf("reply has no confidence for configured label %q", label)
		}
	}
	return got, rep.Truncated, nil
}

type window struct{ start, end int }

type windowList []window

func (ws windowList) offset(by int) windowList {
	for i := range ws {
		ws[i].start += by
		ws[i].end += by
	}
	return ws
}

// splitWindows covers [0, n) with windows of size runes that overlap by overlap,
// so a phrase shorter than the overlap is whole in at least one window. The last
// window ends at n.
func splitWindows(n, size, overlap int) windowList {
	if n <= size {
		return windowList{{0, n}}
	}
	step := size - overlap
	var out windowList
	for start := 0; ; start += step {
		end := start + size
		if end >= n {
			out = append(out, window{start, n})
			return out
		}
		out = append(out, window{start, end})
	}
}

// addrPolicy decides whether text may be sent to an address (ADR 0038 section 3):
// loopback always, a configured private host always, anything else only with
// allow_remote.
type addrPolicy struct {
	allowRemote bool
	private     []netip.Prefix
}

func newAddrPolicy(hosts []string, allowRemote bool) (addrPolicy, error) {
	p := addrPolicy{allowRemote: allowRemote}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if pr, err := netip.ParsePrefix(h); err == nil {
			p.private = append(p.private, pr.Masked())
			continue
		}
		a, err := netip.ParseAddr(h)
		if err != nil {
			return p, fmt.Errorf("assessor: classifier.private_hosts: %q is not an IP address or CIDR prefix "+
				"(a name is not accepted, since what is checked is the address connected to)", h)
		}
		a = a.Unmap()
		p.private = append(p.private, netip.PrefixFrom(a, a.BitLen()))
	}
	return p, nil
}

func (p addrPolicy) allows(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	for _, pr := range p.private {
		if pr.Contains(a) {
			return true
		}
	}
	return p.allowRemote
}

// control runs on every connection, after the name is resolved and before the
// connection is made, so the check applies to the address actually used: a name
// that resolved to loopback at startup and elsewhere later is refused here.
func (p addrPolicy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("classifier connection to %q: cannot check the address: %w", address, err)
	}
	if !p.allows(ap.Addr()) {
		return fmt.Errorf("classifier connection to %s refused: not loopback, not in private_hosts, and allow_remote is off", ap.Addr())
	}
	return nil
}

// lookupHost resolves the endpoint's host at startup. A variable so a test can
// make startup see one address while the connection goes to another.
var lookupHost = resolveHost

func resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = a.Unmap()
	}
	return out, nil
}
