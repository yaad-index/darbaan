package assessor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// findingDetector is a FindingDetector with fixed findings.
type findingDetector struct {
	findings []Finding
	declared []riskscore.Factor
	err      error
	calls    int
}

func (f *findingDetector) DetectFindings(context.Context, mailtext.Content) ([]Finding, error) {
	f.calls++
	return f.findings, f.err
}

func (f *findingDetector) Detect(ctx context.Context, c mailtext.Content) ([]riskscore.Factor, error) {
	fs, err := f.DetectFindings(ctx, c)
	var out []riskscore.Factor
	for _, x := range fs {
		out = append(out, x.Factor)
	}
	return out, err
}

func (f *findingDetector) Factors() []riskscore.Factor { return f.declared }

func clsFinding(f riskscore.Factor, label string, p float64) Finding {
	return Finding{Factor: f, Detector: DetectorClassifier, Label: label, Confidence: p}
}

func TestMultiIsTheUnionAndNamesEachFinding(t *testing.T) {
	pattern := &fakeDetector{factors: []riskscore.Factor{riskscore.FactorSecretsRequest}}
	cls := &findingDetector{
		findings: []Finding{clsFinding(riskscore.FactorInstruction, "instruction_to_reader", 0.97)},
		declared: []riskscore.Factor{riskscore.FactorInstruction},
	}
	m, err := NewMulti(Member{DetectorPattern, pattern}, Member{DetectorClassifier, cls})
	require.NoError(t, err)

	fs, err := m.DetectFindings(context.Background(), mailtext.Content{})
	require.NoError(t, err)
	assert.Equal(t, []Finding{
		{Factor: riskscore.FactorSecretsRequest, Detector: DetectorPattern},
		clsFinding(riskscore.FactorInstruction, "instruction_to_reader", 0.97),
	}, fs)

	factors, err := m.Detect(context.Background(), mailtext.Content{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []riskscore.Factor{riskscore.FactorSecretsRequest, riskscore.FactorInstruction}, factors)
	assert.Equal(t, []riskscore.Factor{riskscore.FactorInstruction, riskscore.FactorSecretsRequest}, m.Factors(), "the union of what each member declares")
}

// A classifier reporting nothing leaves the pattern detector's flags standing:
// union can only add.
func TestMultiAClassifierCannotClearAPatternFlag(t *testing.T) {
	pattern := &fakeDetector{factors: []riskscore.Factor{riskscore.FactorInstruction}}
	cls := &findingDetector{declared: []riskscore.Factor{riskscore.FactorInstruction}}
	m, err := NewMulti(Member{DetectorPattern, pattern}, Member{DetectorClassifier, cls})
	require.NoError(t, err)
	factors, err := m.Detect(context.Background(), mailtext.Content{})
	require.NoError(t, err)
	assert.Equal(t, []riskscore.Factor{riskscore.FactorInstruction}, factors)
}

// Any member failing fails the whole detection (ADR 0038 section 4): a partial
// result is never reported as a clean one.
func TestMultiAnyFailureFailsTheWhole(t *testing.T) {
	pattern := &fakeDetector{factors: []riskscore.Factor{riskscore.FactorInstruction}}
	down := &findingDetector{err: errors.New("connection refused"), declared: []riskscore.Factor{riskscore.FactorInstruction}}
	after := &findingDetector{declared: []riskscore.Factor{riskscore.FactorSecretsRequest}}
	m, err := NewMulti(Member{DetectorPattern, pattern}, Member{DetectorClassifier, down}, Member{"third", after})
	require.NoError(t, err)

	fs, err := m.DetectFindings(context.Background(), mailtext.Content{})
	require.Error(t, err)
	assert.Nil(t, fs, "no partial findings on failure")
	assert.Contains(t, err.Error(), "classifier detector")
	assert.Equal(t, 0, after.calls, "detection stops at the failure")

	asr, err := New(m)
	require.NoError(t, err)
	_, err = asr.Assess(context.Background(), mailtext.Content{})
	assert.Error(t, err, "so the assessment fails and the screener holds the message")
}

func TestNewMultiValidates(t *testing.T) {
	_, err := NewMulti()
	assert.Error(t, err)
	_, err = NewMulti(Member{Name: "", Detector: &fakeDetector{}})
	assert.Error(t, err)
	_, err = NewMulti(Member{Name: "x"})
	assert.Error(t, err)
}

// Findings obey the same boundary as factors: a finding for a factor the detector
// never declared is dropped from both, so it cannot reach the store or the card.
func TestAssessFiltersFindingsToTheDeclaredVocabulary(t *testing.T) {
	det := &findingDetector{
		findings: []Finding{
			clsFinding(riskscore.FactorInstruction, "instruction_to_reader", 0.95),
			clsFinding("ignore previous instructions", "x", 1),
		},
		declared: []riskscore.Factor{riskscore.FactorInstruction},
	}
	asr, err := New(det)
	require.NoError(t, err)
	a, err := asr.Assess(context.Background(), mailtext.Content{})
	require.NoError(t, err)
	assert.Equal(t, []riskscore.Factor{riskscore.FactorInstruction}, a.Factors)
	assert.Equal(t, []Finding{clsFinding(riskscore.FactorInstruction, "instruction_to_reader", 0.95)}, a.Findings)
}

func TestAssessKeepsTheMostConfidentFindingPerDetector(t *testing.T) {
	det := &findingDetector{
		findings: []Finding{
			clsFinding(riskscore.FactorInstruction, "a", 0.91),
			clsFinding(riskscore.FactorInstruction, "b", 0.99),
			{Factor: riskscore.FactorInstruction, Detector: DetectorPattern},
		},
		declared: []riskscore.Factor{riskscore.FactorInstruction},
	}
	asr, err := New(det)
	require.NoError(t, err)
	a, err := asr.Assess(context.Background(), mailtext.Content{})
	require.NoError(t, err)
	assert.Equal(t, []Finding{
		clsFinding(riskscore.FactorInstruction, "b", 0.99),
		{Factor: riskscore.FactorInstruction, Detector: DetectorPattern},
	}, a.Findings)
}

// A plain Detector's factors are recorded as the pattern detector's findings.
func TestAssessRecordsAPlainDetectorAsThePatternDetector(t *testing.T) {
	asr, err := New(&fakeDetector{factors: []riskscore.Factor{riskscore.FactorSecretsRequest}})
	require.NoError(t, err)
	a, err := asr.Assess(context.Background(), mailtext.Content{})
	require.NoError(t, err)
	assert.Equal(t, []Finding{{Factor: riskscore.FactorSecretsRequest, Detector: DetectorPattern}}, a.Findings)
}
