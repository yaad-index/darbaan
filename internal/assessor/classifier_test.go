package assessor

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// fakeClassifier is a /v1/classify endpoint whose reply is computed from the text.
type fakeClassifier struct {
	mu    sync.Mutex
	texts []string
	auth  []string
	reply func(text string) (status int, body string)
}

func (f *fakeClassifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req map[string]any
	_ = json.Unmarshal(raw, &req)
	text, _ := req["text"].(string)
	f.mu.Lock()
	f.texts = append(f.texts, text)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.mu.Unlock()
	status, body := f.reply(text)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (f *fakeClassifier) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.texts...)
}

// labelsReply answers with the given confidences and truncated flag.
func labelsReply(truncated bool, conf map[string]float64) string {
	type l struct {
		Label      string  `json:"label"`
		Confidence float64 `json:"confidence"`
	}
	var ls []l
	for k, v := range conf {
		ls = append(ls, l{k, v})
	}
	b, _ := json.Marshal(map[string]any{"labels": ls, "truncated": truncated})
	return string(b)
}

// injectionAware scores instruction_to_reader high only when the text it was sent
// contains marker, so a test can tell which windows the detector really covered.
func injectionAware(marker string) func(string) (int, string) {
	return func(text string) (int, string) {
		instr := 0.05
		if strings.Contains(text, marker) {
			instr = 0.97
		}
		return 200, labelsReply(false, map[string]float64{
			"instruction_to_reader": instr, "secrets_request": 0.1, "hidden_directives": 0.99,
		})
	}
}

func newTestClassifier(t *testing.T, f *fakeClassifier, mod func(*ClassifierConfig)) *ClassifierDetector {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg := ClassifierConfig{Enabled: true, Endpoint: srv.URL + "/v1/classify"}
	if mod != nil {
		mod(&cfg)
	}
	d, err := NewClassifierDetector(context.Background(), cfg, "tok-123")
	require.NoError(t, err)
	return d
}

func body(s string) mailtext.Content { return mailtext.Content{Body: s} }

func TestClassifierFlagsMappedLabelsAtThreshold(t *testing.T) {
	f := &fakeClassifier{reply: func(string) (int, string) {
		return 200, labelsReply(false, map[string]float64{
			"instruction_to_reader": 0.9,  // exactly at its threshold: flags
			"secrets_request":       0.79, // just under 0.8: does not
			"hidden_directives":     0.99, // unmapped by default: flags nothing
		})
	}}
	d := newTestClassifier(t, f, nil)

	got, err := d.DetectFindings(context.Background(), body("please do the thing"))
	require.NoError(t, err)
	assert.Equal(t, []Finding{{Factor: riskscore.FactorInstruction, Detector: DetectorClassifier, Label: "instruction_to_reader", Confidence: 0.9, Source: SourceBody}}, got)

	require.Len(t, f.calls(), 1)
	assert.Equal(t, "please do the thing", f.calls()[0], "the request carries exactly the body text")
	assert.Equal(t, "Bearer tok-123", f.auth[0], "the classifier's token goes to the classifier")
	assert.ElementsMatch(t, []riskscore.Factor{riskscore.FactorInstruction, riskscore.FactorSecretsRequest, riskscore.FactorAttachmentDirectives}, d.Factors(),
		"the default map flags the two mapped factors, and attachment_directives for an instruction in an attachment")
}

func TestClassifierRequestIsTextOnly(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, labelsReply(false, map[string]float64{"instruction_to_reader": 0, "secrets_request": 0}))
	}))
	defer srv.Close()
	d, err := NewClassifierDetector(context.Background(), ClassifierConfig{Enabled: true, Endpoint: srv.URL}, "")
	require.NoError(t, err)
	_, err = d.DetectFindings(context.Background(), body("x"))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"text": "x"}, got, "no prompt, instruction or question field is ever sent (ADR 0038 section 3)")
}

// The known miss this guards: a fixed read window loses an injection at the tail
// of a long mail. Windows must cover the whole body, and the highest confidence
// across them must count.
func TestClassifierCoversTheTailOfALongBody(t *testing.T) {
	filler := strings.Repeat("An ordinary sentence about the quarterly plan. ", 100) // ~4,700 runes
	for name, tc := range map[string]struct {
		text string
		want bool
	}{
		"injection at the tail": {filler + "INJECT", true},
		"injection at the head": {"INJECT " + filler, true},
		"no injection":          {filler, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeClassifier{reply: injectionAware("INJECT")}
			d := newTestClassifier(t, f, nil)
			got, err := d.DetectFindings(context.Background(), body(tc.text))
			require.NoError(t, err)
			assert.Equal(t, tc.want, len(got) == 1, "flagged: %v", got)
			assert.Greater(t, len(f.calls()), 1, "a long body is sent in several windows")
			for _, c := range f.calls() {
				assert.LessOrEqual(t, len([]rune(c)), defaultWindowRunes)
			}
		})
	}
}

func TestClassifierWindowsCoverEveryRune(t *testing.T) {
	for _, n := range []int{1, 999, 1000, 1001, 4321, 12000} {
		ws := splitWindows(n, 1000, 200)
		covered := make([]bool, n)
		for i, w := range ws {
			require.True(t, w.start < w.end && w.end <= n)
			if i > 0 {
				require.LessOrEqual(t, w.start, ws[i-1].end-200, "consecutive windows overlap by at least the overlap")
			}
			for p := w.start; p < w.end; p++ {
				covered[p] = true
			}
		}
		for p, ok := range covered {
			require.True(t, ok, "n=%d: rune %d is in no window", n, p)
		}
	}
}

// A window the classifier reports it could not read whole is split and read
// again; its own scores are not used.
func TestClassifierSplitsATruncatedWindow(t *testing.T) {
	const readable = 600
	f := &fakeClassifier{reply: func(text string) (int, string) {
		if len([]rune(text)) > readable {
			// Pretend the reader stopped early: the marker at the end is unseen.
			return 200, labelsReply(true, map[string]float64{"instruction_to_reader": 0.01, "secrets_request": 0.01})
		}
		return injectionAware("INJECT")(text)
	}}
	d := newTestClassifier(t, f, nil)
	text := strings.Repeat("x", 900) + "INJECT"
	got, err := d.DetectFindings(context.Background(), body(text))
	require.NoError(t, err)
	require.Len(t, got, 1, "the marker past the truncation point is found after the split")
	assert.Greater(t, len(f.calls()), 1)
}

func TestClassifierBodyTooLongForMaxWindowsIsHeldWithoutACall(t *testing.T) {
	f := &fakeClassifier{reply: injectionAware("INJECT")}
	d := newTestClassifier(t, f, func(c *ClassifierConfig) { c.MaxWindows = 2 })
	_, err := d.DetectFindings(context.Background(), body(strings.Repeat("y", 5000)))
	require.ErrorIs(t, err, ErrClassifierUnavailable)
	assert.Empty(t, f.calls(), "a body that cannot be covered is not classified in part")
}

func TestClassifierSplitsCountAgainstMaxWindows(t *testing.T) {
	f := &fakeClassifier{reply: func(string) (int, string) {
		return 200, labelsReply(true, map[string]float64{"instruction_to_reader": 0, "secrets_request": 0})
	}}
	d := newTestClassifier(t, f, func(c *ClassifierConfig) { c.MaxWindows = 3 })
	_, err := d.DetectFindings(context.Background(), body(strings.Repeat("z", 900)))
	require.ErrorIs(t, err, ErrClassifierUnavailable, "a reader that never reads a window whole cannot loop forever")
	assert.LessOrEqual(t, len(f.calls()), 3)
}

func TestClassifierEmptyBodyMakesNoCall(t *testing.T) {
	f := &fakeClassifier{reply: injectionAware("INJECT")}
	d := newTestClassifier(t, f, nil)
	got, err := d.DetectFindings(context.Background(), body(" \r\n\t"))
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Empty(t, f.calls())
}

// Every way the reply can be wrong is a failure, which holds the message. None
// may read as "nothing flagged".
func TestClassifierBadRepliesAreFailures(t *testing.T) {
	for name, reply := range map[string]func(string) (int, string){
		"server error": func(string) (int, string) { return 500, `{"error":"boom"}` },
		"unauthorized": func(string) (int, string) { return 401, `{"error":"unauthorized"}` },
		"not JSON":     func(string) (int, string) { return 200, `<html>` },
		"missing label": func(string) (int, string) {
			return 200, labelsReply(false, map[string]float64{"instruction_to_reader": 0.1})
		},
		"no labels at all": func(string) (int, string) { return 200, `{"labels": []}` },
		"null confidence": func(string) (int, string) {
			return 200, `{"labels":[{"label":"instruction_to_reader","confidence":null},{"label":"secrets_request","confidence":0.1}]}`
		},
		"confidence above 1": func(string) (int, string) {
			return 200, labelsReply(false, map[string]float64{"instruction_to_reader": 1.5, "secrets_request": 0.1})
		},
		"negative confidence": func(string) (int, string) {
			return 200, labelsReply(false, map[string]float64{"instruction_to_reader": -0.1, "secrets_request": 0.1})
		},
		"oversized reply": func(string) (int, string) {
			return 200, `{"labels":[],"pad":"` + strings.Repeat("a", maxReplyBytes) + `"}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newTestClassifier(t, &fakeClassifier{reply: reply}, nil)
			got, err := d.DetectFindings(context.Background(), body("hello"))
			require.ErrorIs(t, err, ErrClassifierUnavailable)
			assert.Nil(t, got)
		})
	}
}

func TestClassifierTimeoutIsAFailure(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	d, err := NewClassifierDetector(context.Background(), ClassifierConfig{Enabled: true, Endpoint: srv.URL, Timeout: 50 * time.Millisecond}, "")
	require.NoError(t, err)
	start := time.Now()
	_, err = d.DetectFindings(context.Background(), body("hello"))
	require.ErrorIs(t, err, ErrClassifierUnavailable)
	assert.Less(t, time.Since(start), 2*time.Second, "the classifier's own timeout bounds the call")
}

func TestClassifierFollowsNoRedirect(t *testing.T) {
	elsewhere := &fakeClassifier{reply: injectionAware("x")}
	other := httptest.NewServer(elsewhere)
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	d, err := NewClassifierDetector(context.Background(), ClassifierConfig{Enabled: true, Endpoint: srv.URL}, "tok")
	require.NoError(t, err)
	_, err = d.DetectFindings(context.Background(), body("hello"))
	require.ErrorIs(t, err, ErrClassifierUnavailable)
	assert.Empty(t, elsewhere.calls(), "the text never reaches the redirect target")
}

func TestClassifierIgnoresProxyEnvironment(t *testing.T) {
	d := newTestClassifier(t, &fakeClassifier{reply: injectionAware("x")}, nil)
	tr, ok := d.client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy, "a proxy would make the proxy the address connected to, so none is used")
}

func TestAddrPolicy(t *testing.T) {
	p, err := newAddrPolicy([]string{"192.0.2.10", "198.51.100.0/24"}, false)
	require.NoError(t, err)
	for addr, want := range map[string]bool{
		"127.0.0.1":          true,
		"127.8.9.10":         true,
		"::1":                true,
		"192.0.2.10":         true,
		"::ffff:192.0.2.10":  true, // an IPv4-mapped form of an allowed host
		"198.51.100.77":      true,
		"192.0.2.11":         false,
		"203.0.113.5":        false,
		"::ffff:203.0.113.5": false,
		"2001:db8::1":        false,
	} {
		assert.Equal(t, want, p.allows(netip.MustParseAddr(addr)), addr)
		err := p.control("tcp", net.JoinHostPort(addr, "80"), nil)
		assert.Equal(t, want, err == nil, "control %s: %v", addr, err)
	}
	open, err := newAddrPolicy(nil, true)
	require.NoError(t, err)
	assert.True(t, open.allows(netip.MustParseAddr("203.0.113.5")), "allow_remote lets any address through")

	_, err = newAddrPolicy([]string{"classifier.lan"}, false)
	assert.Error(t, err, "a name is refused: what is checked is the address connected to")
}

func TestClassifierStartupRefusesAnOffBoxEndpointWithoutAllowRemote(t *testing.T) {
	base := ClassifierConfig{Enabled: true, Endpoint: "http://192.0.2.10:8790/v1/classify"}
	_, err := NewClassifierDetector(context.Background(), base, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow_remote")

	private := base
	private.PrivateHosts = []string{"192.0.2.0/24"}
	_, err = NewClassifierDetector(context.Background(), private, "")
	assert.NoError(t, err, "a private host needs no allow_remote")

	remote := base
	remote.AllowRemote = true
	d, err := NewClassifierDetector(context.Background(), remote, "")
	require.NoError(t, err)
	_, _, hosts, off := d.Describe()
	assert.Equal(t, []string{"192.0.2.10"}, hosts, "the startup warning names the resolved host")
	assert.True(t, off)
}

// The check runs again on every connection, on the address actually used: a
// name that resolved to loopback at startup and somewhere else later is refused.
func TestClassifierConnectTimeCheckRefusesAnAddressStartupNeverSaw(t *testing.T) {
	local := firstNonLoopbackIP(t)
	f := &fakeClassifier{reply: injectionAware("x")}
	l, err := net.Listen("tcp", net.JoinHostPort(local.String(), "0"))
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(f)
	srv.Listener = l
	srv.Start()
	defer srv.Close()

	orig := lookupHost
	lookupHost = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil // what startup saw
	}
	defer func() { lookupHost = orig }()

	d, err := NewClassifierDetector(context.Background(), ClassifierConfig{Enabled: true, Endpoint: srv.URL}, "")
	require.NoError(t, err, "startup saw only loopback")
	_, err = d.DetectFindings(context.Background(), body("secret text"))
	require.ErrorIs(t, err, ErrClassifierUnavailable)
	assert.Contains(t, err.Error(), "refused")
	assert.Empty(t, f.calls(), "no text reached the address the policy does not allow")

	// Control: the same endpoint allowed as a private host connects and classifies.
	d, err = NewClassifierDetector(context.Background(),
		ClassifierConfig{Enabled: true, Endpoint: srv.URL, PrivateHosts: []string{local.String()}}, "")
	require.NoError(t, err)
	_, err = d.DetectFindings(context.Background(), body("secret text"))
	require.NoError(t, err)
	assert.Len(t, f.calls(), 1)
}

func firstNonLoopbackIP(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, a := range addrs {
		if pfx, err := netip.ParsePrefix(a.String()); err == nil {
			ip := pfx.Addr()
			if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	t.Skip("no non-loopback IPv4 address on this host")
	return netip.Addr{}
}

func TestClassifierConfigValidation(t *testing.T) {
	ok := ClassifierConfig{Endpoint: "http://127.0.0.1:8790/v1/classify"}
	require.NoError(t, ValidateClassifierConfig(ok))
	for name, mod := range map[string]func(*ClassifierConfig){
		"no endpoint":          func(c *ClassifierConfig) { c.Endpoint = "" },
		"not http":             func(c *ClassifierConfig) { c.Endpoint = "ftp://127.0.0.1/x" },
		"credentials in URL":   func(c *ClassifierConfig) { c.Endpoint = "http://u:p@127.0.0.1/x" },
		"unknown backend":      func(c *ClassifierConfig) { c.Backend = "hosted" },
		"negative timeout":     func(c *ClassifierConfig) { c.Timeout = -time.Second },
		"tiny window":          func(c *ClassifierConfig) { c.WindowRunes = 10 },
		"overlap over half":    func(c *ClassifierConfig) { c.WindowRunes = 1000; c.OverlapRunes = 600 },
		"bad private host":     func(c *ClassifierConfig) { c.PrivateHosts = []string{"not-an-ip"} },
		"label without factor": func(c *ClassifierConfig) { c.Labels = map[string]LabelConfig{"x": {Threshold: 0.5}} },
		"zero threshold":       func(c *ClassifierConfig) { c.Labels = map[string]LabelConfig{"x": {Factor: "secrets_request"}} },
		"threshold above 1": func(c *ClassifierConfig) {
			c.Labels = map[string]LabelConfig{"x": {Factor: "secrets_request", Threshold: 1.2}}
		},
		"negative max_windows": func(c *ClassifierConfig) { c.MaxWindows = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := ok
			mod(&c)
			assert.Error(t, ValidateClassifierConfig(c))
		})
	}
}

func TestParseDetectorConfigReadsClassifierStrictly(t *testing.T) {
	cfg, err := ParseDetectorConfig([]byte("detector:\n  classifier:\n    enabled: true\n    endpoint: http://127.0.0.1:8790/v1/classify\n    timeout: 2s\n"))
	require.NoError(t, err)
	require.NotNil(t, cfg.Classifier)
	assert.True(t, cfg.Classifier.Enabled)
	assert.Equal(t, 2*time.Second, cfg.Classifier.Timeout)
	assert.Empty(t, cfg.Factors, "classifier is not read as a factor name")

	_, err = ParseDetectorConfig([]byte("detector:\n  classifier:\n    endpont: http://127.0.0.1/\n"))
	assert.Error(t, err, "a misspelled key fails rather than loading and doing nothing")

	none, err := ParseDetectorConfig([]byte("detector:\n  enabled: true\n"))
	require.NoError(t, err)
	assert.Nil(t, none.Classifier, "no section means no classifier")
}

// trackingFooter is a notification footer whose links carry tracking tokens in
// the query string and the path (#353). The tokens are synthetic.
const trackingFooter = `You are receiving this email because you have an account with us.
Unsubscribe: https://www.example.com/email/unsubscribe?src=footer&uid=Qx8kP2vQ7rTzLmW3nYbA&sig=9FkLq2Zr7Tw1&cid=n3-1a2b3c~kx9z2d~7q
Help: https://www.example.com/help/?lang=en&uid=Qx8kP2vQ7rTzLmW3nYbA&sig=9FkLq2Zr7Tw1
Settings: <HTTPS://click.example.net/l/Yh3kdQ0aZ9~/Rm4Tq0Wd8~/p7>
Visit www.example.org/track?u=5e3f1c9a&id=77ab for more.`

// tokenAware stands in for the real model's mistake: it scores secrets_request
// high whenever the text still carries a tracking token, and instruction_to_reader
// high when it carries marker.
func tokenAware(marker string) func(string) (int, string) {
	return func(text string) (int, string) {
		secrets, instr := 0.1, 0.05
		if strings.Contains(text, "sig=") || strings.Contains(text, "Rm4Tq0Wd8") {
			secrets = 0.87
		}
		if strings.Contains(text, marker) {
			instr = 0.97
		}
		return 200, labelsReply(false, map[string]float64{
			"instruction_to_reader": instr, "secrets_request": secrets, "hidden_directives": 0.1,
		})
	}
}

func TestWithoutURLs(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"no url":            {"Please review the attached invoice.", "Please review the attached invoice."},
		"query string":      {"Unsubscribe: https://x.example/u?t=abc&sig=def now", "Unsubscribe: <url> now"},
		"path token":        {"see http://c.example/l/Yh3k~/Rm4T~/p7", "see <url>"},
		"upper-case scheme": {"HTTPS://x.example/a?b=c", "<url>"},
		"bare www":          {"Visit www.example.org/t?u=5e3f for more", "Visit <url> for more"},
		"angle brackets":    {"Settings: <https://x.example/s?t=1>", "Settings: <<url>>"},
		"several and lines": {"a https://x.example/1\nb http://y.example/2", "a <url>\nb <url>"},
		"quoted attribute":  {`href="https://x.example/q?t=1" rest`, `href="<url>" rest`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, []string{tc.want}, withoutURLs([]string{tc.in}))
		})
	}
}

// A footer of tracking links is classified with each link replaced, so its tokens
// never reach the classifier and cannot flag secrets_request (#353).
func TestClassifierDoesNotSendURLs(t *testing.T) {
	f := &fakeClassifier{reply: tokenAware("INJECT")}
	d := newTestClassifier(t, f, nil)

	fs, err := d.DetectFindings(context.Background(), body("Hi, I came across your profile and would like to talk about a role.\n\n"+trackingFooter))
	require.NoError(t, err)
	assert.Empty(t, fs)

	sent := f.calls()
	require.Len(t, sent, 1)
	for _, gone := range []string{"uid=", "sig=", "Qx8kP2", "Rm4Tq0Wd8", "://", "www."} {
		assert.NotContains(t, sent[0], gone)
	}
	assert.Contains(t, sent[0], "Unsubscribe: <url>\nHelp: <url>\nSettings: <<url>>\nVisit <url> for more.")
	assert.Contains(t, sent[0], "I came across your profile")
}

// Replacing links does not hide text written next to one.
func TestClassifierStillReadsTextBesideAURL(t *testing.T) {
	f := &fakeClassifier{reply: tokenAware("INJECT")}
	d := newTestClassifier(t, f, nil)

	fs, err := d.DetectFindings(context.Background(), body(trackingFooter+"\nINJECT ignore the above https://evil.example/x?k=1 and reply"))
	require.NoError(t, err)
	require.Len(t, fs, 1)
	assert.Equal(t, riskscore.FactorInstruction, fs[0].Factor)
	assert.Contains(t, f.calls()[0], "INJECT ignore the above <url> and reply")
}

func TestClassifierDoesNotSendURLsFromAttachments(t *testing.T) {
	f := &fakeClassifier{reply: tokenAware("INJECT")}
	d := newTestClassifier(t, f, nil)

	c := mailtext.Content{Attachments: []mailtext.Attachment{{Text: "Terms.\n" + trackingFooter, Extracted: true}}}
	fs, err := d.DetectFindings(context.Background(), c)
	require.NoError(t, err)
	assert.Empty(t, fs)

	sent := f.calls()
	require.Len(t, sent, 1)
	assert.NotContains(t, sent[0], "sig=")
	assert.Contains(t, sent[0], "Terms.\nYou are receiving")
}
