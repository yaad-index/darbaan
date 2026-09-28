package assessor

import (
	"context"
	"fmt"
	"sort"

	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// Detector names recorded on a Finding (ADR 0038 section 4b).
const (
	DetectorPattern    = "pattern"
	DetectorClassifier = "classifier"
)

// Finding is one detector's report of one factor (ADR 0038 section 4b): which
// detector flagged it and, for a classifier, the label and confidence that
// produced the flag. Every field is system-defined or a number: a classifier's
// label is kept only when it is one the operator's configuration names, so no
// text from the message or the classifier's reply crosses the boundary.
type Finding struct {
	Factor     riskscore.Factor
	Detector   string
	Label      string
	Confidence float64
}

// FindingDetector is a Detector that also says, per flagged factor, what flagged
// it. A detector that is only a Detector has its factors recorded as findings
// under the name it was given in the Multi.
type FindingDetector interface {
	Detector
	DetectFindings(ctx context.Context, c mailtext.Content) ([]Finding, error)
}

// Member is one detector in a Multi, with the name its findings are recorded under.
type Member struct {
	Name     string
	Detector Detector
}

// Multi runs several detectors and reports the union of what they flag (ADR 0038
// section 1). Union means a detector can only add a factor: none can clear one
// another flagged, so adding a detector never lowers a score. A failure of ANY
// member fails the whole detection, because a partial result is not a clean one
// (ADR 0038 section 4): the assessor then returns an error and the message is held.
type Multi struct {
	members []Member
}

// NewMulti composes members, in order. At least one is required, and each needs a
// name and a detector.
func NewMulti(members ...Member) (*Multi, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("assessor: multi: no detectors")
	}
	for i, m := range members {
		if m.Name == "" || m.Detector == nil {
			return nil, fmt.Errorf("assessor: multi: member %d needs a name and a detector", i)
		}
	}
	return &Multi{members: append([]Member(nil), members...)}, nil
}

// Detect returns the union of every member's factors.
func (m *Multi) Detect(ctx context.Context, c mailtext.Content) ([]riskscore.Factor, error) {
	fs, err := m.DetectFindings(ctx, c)
	if err != nil {
		return nil, err
	}
	out := make([]riskscore.Factor, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Factor)
	}
	return out, nil
}

// DetectFindings runs every member in order and returns all of their findings. It
// stops at the first member that fails.
func (m *Multi) DetectFindings(ctx context.Context, c mailtext.Content) ([]Finding, error) {
	var out []Finding
	for _, mem := range m.members {
		fs, err := findingsOf(ctx, mem, c)
		if err != nil {
			return nil, fmt.Errorf("%s detector: %w", mem.Name, err)
		}
		out = append(out, fs...)
	}
	return out, nil
}

// Factors returns the union of the members' factors, sorted, so ValidateAlignment
// checks every factor any member can emit.
func (m *Multi) Factors() []riskscore.Factor {
	seen := make(map[riskscore.Factor]struct{})
	for _, mem := range m.members {
		for _, f := range mem.Detector.Factors() {
			seen[f] = struct{}{}
		}
	}
	out := make([]riskscore.Factor, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func findingsOf(ctx context.Context, mem Member, c mailtext.Content) ([]Finding, error) {
	if fd, ok := mem.Detector.(FindingDetector); ok {
		return fd.DetectFindings(ctx, c)
	}
	fs, err := mem.Detector.Detect(ctx, c)
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, Finding{Factor: f, Detector: mem.Name})
	}
	return out, nil
}
