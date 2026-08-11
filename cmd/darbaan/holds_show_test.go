package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// `holds show` must render HeldContent's three outcomes distinctly, because they
// call for opposite operator actions. A held message with no stored body (empty 200)
// and a not-currently-held id (404 → ErrNotHeld) are the two the old empty-200
// contract conflated — writing zero bytes and exiting 0 on either would read as "the
// message is empty", the misrepresentation this surface exists to prevent on the
// class of message where the body is the decision. Each is reachable straight from
// the fetch-failure alert: the notification fires, the operator retries a minute
// later, the hold was either never bodied or decided in between.

// TestHoldsShowEmptyBodyIsError: a held message with no stored body (empty 200) is an
// error that names that state and steers the operator to decide from metadata — never
// a silent success.
func TestHoldsShowEmptyBodyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // held, but no stored body: the empty-200 contract
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")

	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}
	err := (&HoldsShowCmd{ID: "bodyless"}).Run(cli)
	require.Error(t, err, "an empty body must be an error, not a silent success")
	assert.Contains(t, err.Error(), "held with no stored body")
	assert.NotContains(t, err.Error(), "no longer held", "must not steer to the take-no-action branch")
}

// TestHoldsShowNotHeldIsError: a not-currently-held id (server 404 → ErrNotHeld) is an
// error that names the decision as already made — the opposite action from the
// no-stored-body case, and never conflated with it.
func TestHoldsShowNotHeldIsError(t *testing.T) {
	// The not-held signal is a 404 carrying the service's not-held CODE — the positive
	// evidence the client maps on. A bare 404 must NOT reach this branch (see the
	// unclassifiable guard, which covers it).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"admin: message is not currently held","code":"not_held"}`))
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")

	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}
	err := (&HoldsShowCmd{ID: "gone"}).Run(cli)
	require.Error(t, err, "a not-held id must be an error naming the already-made decision")
	assert.Contains(t, err.Error(), "no longer held")
	assert.Contains(t, err.Error(), "take no action")
	assert.NotContains(t, err.Error(), "no stored body", "must not steer to the decide-from-metadata branch")
}

// TestQueueShowEmptyBodyIsError: the outbound sibling states an empty body explicitly
// too. A present outbound message with an empty stored body (a legitimate empty
// submission, reachable by ordinary submission — nothing on the write path requires a
// non-empty body) served as an empty 200 must be an error naming it a genuinely empty
// message, not zero bytes and a clean exit the fetch-failure retry would read as a
// glitch. Empty means something different here than on the inbound side: genuinely
// empty (fully materialized), not a body not yet fetched.
func TestQueueShowEmptyBodyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // present, but empty stored body
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")

	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}
	err := (&QueueShowCmd{ID: "empty"}).Run(cli)
	require.Error(t, err, "an empty stored body must be stated, not a silent zero-exit")
	assert.Contains(t, err.Error(), "genuinely empty message")
}

// TestHoldsShowUnclassifiableFailureGoesRed pins the property the whole round turns
// on: the safe-branch default. A failure the retry cannot classify — a server fault, a
// permission denial, or a BARE 404 that carries no not-held code (a route-less daemon
// under version skew, or a mis-pointed peer) — must surface as an error (go red), never
// fall through to the decide-from-metadata ("held with no stored body") branch. 404 is
// deliberately in scope: only a 404 carrying THIS service's code is not-held; a bare
// one is just another unidentified failure. It guards the ordering in HoldsShowCmd.Run:
// the error check precedes the empty-body check, so an errored (nil-body) response is
// never misread as an empty message. Strip that default and this test fails — the
// responses below would reach the "held with no stored body" text instead.
func TestHoldsShowUnclassifiableFailureGoesRed(t *testing.T) {
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")
	for _, status := range []int{http.StatusInternalServerError, http.StatusForbidden, http.StatusNotFound} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status) // unclassifiable: a server fault, a denial, or a bare (codeless) 404
		}))
		cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}
		err := (&HoldsShowCmd{ID: "x"}).Run(cli)
		srv.Close()
		require.Errorf(t, err, "status %d must surface as an error, not a silent success", status)
		// Positive: the surfaced error IS the client's classified tool failure
		// (errorFrom's "admin: <status>") — i.e. the safe branch propagated it — and it
		// names THIS response's status, not some incidental error. This ties the passing
		// case to the ordering, so the test can't pass for an unrelated reason.
		assert.Containsf(t, err.Error(), "admin:",
			"status %d must surface as the propagated tool error, not a state claim", status)
		assert.Containsf(t, err.Error(), strconv.Itoa(status),
			"the propagated error names this response's status")
		// Negative: it did not fall through to a state-claiming branch. Under the strip,
		// both the positive anchors above and these fail — the failure names the ordering.
		assert.NotContainsf(t, err.Error(), "held with no stored body",
			"status %d must not reach the decide-from-metadata branch", status)
		assert.NotContainsf(t, err.Error(), "no longer held",
			"status %d is the tool failing, not a not-held signal", status)
	}
}

// TestHoldsShowEndToEndAgainstRealServer drives the command through the REAL admin
// transport — service → http → client → command — rather than each layer against a
// stub. It proves the three-way split the operator's decision rests on survives the
// round trip: a held message with a stored body, one held with no stored body, and an
// id that is not held reach the command as three distinct outcomes, with the not-held
// signal originating as the service's typed ErrNotHeld (a 404 on the wire), never
// re-derived downstream.
func TestHoldsShowEndToEndAgainstRealServer(t *testing.T) {
	dir := t.TempDir()
	store, err := sluice.New("bbolt", filepath.Join(dir, "q.db"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	inbox, err := inbound.New("bbolt", filepath.Join(dir, "in.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = inbox.Close() })

	svc := admin.NewService(store, inbox, nil, nil, nil, "darbaan.test")
	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	svc.SetInboundHolds(map[string]*filter.Filter{inbound.DefaultInbox: flt}, func(string) string { return "agent" }, nil, false)

	_, withBody, err := inbox.AddSyncedAssessed(
		inbound.Delivery{Owner: "agent", Subject: "has body", Raw: []byte("Subject: x\r\n\r\nbody-bytes"), UpstreamUID: 1, UIDValidity: 1},
		&inbound.Assessment{Disposition: inbound.AssessmentHeld},
	)
	require.NoError(t, err)
	_, noBody, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", Subject: "no body", UpstreamUID: 2, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)

	srv, err := admin.NewServer("", "tok", svc)
	require.NoError(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	t.Setenv("DARBAAN_ADMIN_TOKEN", "tok")
	cli := &CLI{AdminAddr: l.Addr().String()}

	// Held with a stored body: succeeds (the command writes the body, no error).
	require.NoError(t, (&HoldsShowCmd{ID: withBody.ID}).Run(cli), "a held message with a body is served")

	// Held with no stored body: the decide-from-metadata error — never the not-held one.
	err = (&HoldsShowCmd{ID: noBody.ID}).Run(cli)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "held with no stored body")
	assert.NotContains(t, err.Error(), "no longer held")

	// Not held: the take-no-action error, carried the whole way as ErrNotHeld — never
	// conflated with an empty body.
	err = (&HoldsShowCmd{ID: "not-a-held-id"}).Run(cli)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer held")
	assert.Contains(t, err.Error(), "take no action")
	assert.NotContains(t, err.Error(), "no stored body")
}

// #261: --text prints the decoded body rather than the raw source. Both modes are
// kept because they serve different jobs — the raw dump is byte-exact and redirects
// to a .eml, --text is for actually reading the thing before deciding on it.
func TestHoldsShowTextPrintsDecodedBody(t *testing.T) {
	raw := "Delivered-To: agent@x.test\r\n" +
		"ARC-Seal: i=1; a=rsa-sha256; b=" + strings.Repeat("Zq", 200) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"the readable body\r\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(raw))
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")
	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}

	out := captureStdout(t, func() {
		require.NoError(t, (&HoldsShowCmd{ID: "x", Text: true}).Run(cli))
	})
	assert.Contains(t, out, "the readable body")
	assert.NotContains(t, out, "ARC-Seal", "--text does not print transport headers")

	// Default stays the raw dump: removing that would take away the byte-exact
	// output the .eml redirect depends on.
	rawOut := captureStdout(t, func() {
		require.NoError(t, (&HoldsShowCmd{ID: "x"}).Run(cli))
	})
	assert.Contains(t, rawOut, "ARC-Seal", "the default mode is still the raw source")
}

// A body that exists but yields no text fails loudly under --text, for the same
// reason the no-stored-body case does: exiting 0 having printed nothing reads as
// "the message is empty" on the surface where the body is the decision.
func TestHoldsShowTextNoReadableTextIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Content-Type: image/png\r\n\r\n\x89PNG binary"))
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")
	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}

	err := (&HoldsShowCmd{ID: "img", Text: true}).Run(cli)
	require.Error(t, err, "no readable text must not exit 0 having printed nothing")
	assert.Contains(t, err.Error(), "NOT empty")
	assert.Contains(t, err.Error(), "without --text", "points at the raw dump rather than dead-ending")
}

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	require.NoError(t, w.Close())
	os.Stdout = orig
	return <-done
}
