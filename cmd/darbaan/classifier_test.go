package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/riskscore"
	"github.com/yaad-index/darbaan/internal/screener"
)

// classifierConfig writes a config file enabling the classifier at endpoint.
func classifierConfig(t *testing.T, classifier string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("assessment:\n  detector:\n    classifier:\n"+classifier), 0o600))
	return path
}

// stubClassifier answers instruction_to_reader high when the text says "wire the money".
func stubClassifier(t *testing.T, token *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != nil {
			*token = r.Header.Get("Authorization")
		}
		var req struct{ Text string }
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &req)
		instr := 0.02
		if strings.Contains(req.Text, "wire the money") {
			instr = 0.96
		}
		_, _ = fmt.Fprintf(w, `{"labels":[{"label":"instruction_to_reader","confidence":%v},{"label":"secrets_request","confidence":0.01}]}`, instr)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// End to end: a phrasing no pattern catches is flagged by the classifier, stored
// with its label and confidence, and the score goes up.
func TestBuildAssessHookWithClassifierStoresItsFindings(t *testing.T) {
	var gotAuth string
	srv := stubClassifier(t, &gotAuth)
	t.Setenv("DARBAAN_CLASSIFIER_TOKEN", "cls-token")
	cli := &CLI{Config: classifierConfig(t, "      enabled: true\n      endpoint: "+srv.URL+"\n      timeout: 1s\n"),
		AssessmentEnabled: true, AssessmentTimeout: 3 * time.Second}
	hook, _, err := cli.buildAssessHook(nil, nilResolver, riskscore.DefaultConfig())
	require.NoError(t, err)
	require.NotNil(t, hook)

	raw := []byte("Subject: x\r\n\r\nHi, before lunch please wire the money to the new supplier account.")
	a := hook(inbound.DefaultInbox, "x@example.com", raw, &inbound.Envelope{})
	require.NotNil(t, a)
	assert.Contains(t, a.Factors, "instruction_to_reader")
	assert.Contains(t, a.Findings, inbound.Finding{Factor: "instruction_to_reader", Detector: "classifier", Label: "instruction_to_reader", Confidence: 0.96, Source: "body"})
	assert.Equal(t, "Bearer cls-token", gotAuth, "the token comes from DARBAAN_CLASSIFIER_TOKEN")

	// Control: the same message without the phrase is not flagged by either detector.
	clean := hook(inbound.DefaultInbox, "x@example.com", []byte("Subject: x\r\n\r\nHi, lunch at noon?"), &inbound.Envelope{})
	assert.Empty(t, clean.Factors)
}

// ADR 0038 section 4: the classifier down means the message is held, and the card
// can say why.
func TestBuildAssessHookClassifierOutageHoldsTheMessage(t *testing.T) {
	srv := stubClassifier(t, nil)
	url := srv.URL
	srv.Close() // nothing listens any more
	cli := &CLI{Config: classifierConfig(t, "      enabled: true\n      endpoint: "+url+"\n      timeout: 1s\n"),
		AssessmentEnabled: true, AssessmentTimeout: 3 * time.Second}
	hook, _, err := cli.buildAssessHook(nil, nilResolver, riskscore.DefaultConfig())
	require.NoError(t, err)
	a := hook(inbound.DefaultInbox, "x@example.com", []byte("Subject: x\r\n\r\nHi, lunch at noon?"), &inbound.Envelope{})
	require.NotNil(t, a)
	assert.Equal(t, inbound.AssessmentHeld, a.Disposition)
	assert.True(t, a.NotCleared)
	assert.Equal(t, screener.ClassifierUnavailableSummary, a.Summary)
}

func TestBuildAssessHookClassifierStartupChecks(t *testing.T) {
	for name, tc := range map[string]struct {
		section string
		enabled bool
		want    string
	}{
		"off-box endpoint without allow_remote, assessment off": {
			section: "      enabled: true\n      endpoint: http://192.0.2.10:8790/v1/classify\n",
			want:    "allow_remote",
		},
		"timeout not inside the assessment timeout": {
			section: "      enabled: true\n      endpoint: http://127.0.0.1:1/v1/classify\n      timeout: 3s\n",
			enabled: true,
			want:    "must be shorter than --assessment-timeout",
		},
		"bad section while the classifier is off": {
			section: "      enabled: false\n      endpoint: ftp://nowhere\n",
			want:    "classifier.endpoint",
		},
		"misspelled key": {
			section: "      enabled: false\n      endpont: http://127.0.0.1/\n",
			want:    "endpont",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cli := &CLI{Config: classifierConfig(t, tc.section), AssessmentEnabled: tc.enabled, AssessmentTimeout: 3 * time.Second}
			_, _, err := cli.buildAssessHook(nil, nilResolver, riskscore.DefaultConfig())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// Off means off: a disabled classifier section leaves the pattern detector alone,
// and no endpoint is contacted.
func TestBuildAssessHookDisabledClassifierIsNotUsed(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer srv.Close()
	cli := &CLI{Config: classifierConfig(t, "      enabled: false\n      endpoint: "+srv.URL+"\n"),
		AssessmentEnabled: true, AssessmentTimeout: 3 * time.Second}
	hook, _, err := cli.buildAssessHook(nil, nilResolver, riskscore.DefaultConfig())
	require.NoError(t, err)
	a := hook(inbound.DefaultInbox, "x@example.com", []byte("Subject: x\r\n\r\nplease wire the money"), &inbound.Envelope{})
	require.NotNil(t, a)
	assert.Equal(t, 0, calls)
	for _, f := range a.Findings {
		assert.Equal(t, "pattern", f.Detector)
	}
}
