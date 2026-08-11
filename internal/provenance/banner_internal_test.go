package provenance

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var nonASCII = regexp.MustCompile(`[^\x00-\x7f]`)

// #274: neutralization must leave NO live marker in its output — the invariant both
// passes establish, and the exact class C37 exists to close (an edit leaving a live
// marker behind). The prior defanged form ENDED with the delimiter it removed, so two
// SAME-KIND markers sharing a dash run manufactured a live marker a single pass never
// re-scanned; CROSS-kind did not — the asymmetry a future reader would not guess and
// the fixpoint covers without explaining. This asserts the invariant directly over the
// four adjacency arrangements plus a small sweep, so it objects if anyone later
// reshapes the replacement back to a delimiter-bearing form or reorders the passes.
func TestNeutralizeBannersLeavesNoLiveMarker(t *testing.T) {
	b, e := bannerBegin, bannerEnd
	cases := map[string]string{
		"BEGIN+BEGIN (shared dash run, survived pre-fix)": b + "BEGIN DARBAAN TRUST BANNER-----",
		"END+END (shared dash run, survived pre-fix)":     e + "END DARBAAN TRUST BANNER-----",
		"BEGIN+END (cross-kind, did not survive pre-fix)": b + "END DARBAAN TRUST BANNER-----",
		"END+BEGIN (cross-kind)":                          e + "BEGIN DARBAAN TRUST BANNER-----",
		"triple begin":                                    b + b + b,
		"triple end":                                      e + e + e,
		"interleaved begin/end/begin":                     b + e + b,
		"markers amid text":                               "lead " + b + " mid " + e + " tail",
	}
	for name, in := range cases {
		out := neutralizeBanners([]byte(in))
		assert.Falsef(t, bannerBeginMarker.Match(out), "%s: a live BEGIN marker survives: %q", name, out)
		assert.Falsef(t, bannerEndMarker.Match(out), "%s: a live END marker survives: %q", name, out)
		// This insertion path re-encodes 7bit/8bit/us-ascii bodies as identity, so a
		// non-ASCII byte in the replacement would land in a body that declares it has
		// none. Inputs here are ASCII, so any non-ASCII output came from the replacement.
		assert.Falsef(t, nonASCII.Match(out), "%s: non-ASCII byte in neutralized output: %q", name, out)
	}
}

// The defanged constants must keep the three properties the safety argument rests on,
// pinned directly so a later "nicer" phrasing (a curly quote, an em dash, a delimiter-
// shaped run) is caught at the source rather than only through the behavioural test.
func TestBannerDefangedFormsAreSafe(t *testing.T) {
	for _, s := range []string{bannerBeginDefanged, bannerEndDefanged} {
		assert.Falsef(t, nonASCII.MatchString(s), "defanged form must be ASCII-only: %q", s)
		assert.NotContainsf(t, s, "-----", "defanged form must carry no five-hyphen delimiter run: %q", s)
		assert.Truef(t, strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"), "defanged form must be bracket-delimited: %q", s)
	}
}
