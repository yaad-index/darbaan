package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
)

// #245: the sync-status table's LAST ERROR column carries the upstream IMAP server's
// response text verbatim, so it must go through sanitizeField like every other
// operator-table free-text field (C22) — an ESC or a bidi override in a server's
// error string otherwise rewrites what the operator sees while they judge whether an
// account is healthy.
//
// Asserted at the CALL SITE, through the real command, rather than on sanitizeField:
// a helper test passes whether or not the table ever calls the helper, which is the
// coverage gap that let this column stay raw while sanitizeField itself was tested.
func TestSyncStatusTableSanitizesLastError(t *testing.T) {
	// A hostile upstream error: an OSC title-set sequence and an RTL override.
	// Written as escapes, not raw runes: a literal U+202E would reorder THIS source
	// as displayed to a reviewer, which is the same attack the assertion is about
	// (staticcheck ST1018 enforces it).
	hostile := "NO [ALERT] \x1b]0;owned\x07 \u202egnitcelfeR"
	body, err := json.Marshal([]admin.SyncStatus{{
		Inbox: "work", ConsecutiveErrors: 3, LastError: hostile,
		WatermarkUID: 41, UIDValidity: 4000, LastSuccess: "2026-09-25T06:00:00Z",
	}})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")
	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}

	out := captureStdout(t, func() {
		require.NoError(t, (&SyncStatusCmd{}).Run(cli))
	})

	assert.NotContains(t, out, "\x1b", "an ESC must never reach the operator's terminal")
	assert.NotContains(t, out, "\x07", "nor a BEL")
	assert.NotContains(t, out, "\u202e", "nor a bidi override that reorders the row")
	assert.Contains(t, out, "�", "the neutralised runes are replaced, not dropped silently")
	// Controls: the row is still rendered and its ordinary text survives, so the
	// assertions above cannot be passing merely because nothing was printed.
	assert.Contains(t, out, "work")
	assert.Contains(t, out, "erroring")
}
