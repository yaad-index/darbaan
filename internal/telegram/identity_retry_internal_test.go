package telegram

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
)

// newClientForAdmin builds a bare Client pointed at a test admin server, with the
// bot/handler machinery omitted (these tests exercise only the identity fetch).
func newClientForAdmin(url string) *Client {
	return &Client{
		admin:  admin.NewClient(strings.TrimPrefix(url, "http://"), "tok"),
		logger: slog.Default(),
	}
}

// #160: the Change-sender identity fetch is retried by the poll loop until it
// succeeds. A co-start race where serve's admin endpoint isn't listening yet
// leaves Change-sender off for that cycle but self-recovers on the next, instead
// of staying off until a manual restart.
func TestEnsureIdentitiesRetriesUntilReady(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// First cycle: serve not ready yet (stands in for connection-refused).
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`[{"name":"work","identity":"w@x"},{"name":"personal","identity":"p@x"}]`))
	}))
	defer srv.Close()
	c := newClientForAdmin(srv.URL)

	// Cycle 1: serve not ready → nothing loaded, Change-sender omitted from the
	// decision keyboard (Approve + Reject rows only).
	c.ensureIdentities(context.Background())
	assert.False(t, c.identitiesLoaded)
	assert.Empty(t, c.inboxIdentities())
	assert.Len(t, c.decisionKeyboard("42").InlineKeyboard, 2)

	// Cycle 2: serve ready → identities loaded, Change-sender now offered (Approve +
	// Change + Reject rows).
	c.ensureIdentities(context.Background())
	assert.True(t, c.identitiesLoaded)
	require.Len(t, c.inboxIdentities(), 2)
	assert.Len(t, c.decisionKeyboard("42").InlineKeyboard, 3)

	// Cycle 3: already loaded → no further upstream fetch (call count stays at 2).
	c.ensureIdentities(context.Background())
	assert.Equal(t, int32(2), calls.Load(), "no re-fetch after the first success")
}

// The identities are written by the poll goroutine (ensureIdentities) and read by
// the callback goroutine (decisionKeyboard / identityKeyboard), so the access must
// be race-clean under -race (#160 retires the old "read-only after startup" lock
// exemption).
func TestInboxIdentitiesRaceClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"a","identity":"a@x"},{"name":"b","identity":"b@x"}]`))
	}))
	defer srv.Close()
	c := newClientForAdmin(srv.URL)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // poll-loop side: writes identities
		defer wg.Done()
		for i := 0; i < 50; i++ {
			c.ensureIdentities(context.Background())
		}
	}()
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() { // callback side: reads identities
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = c.inboxIdentities()
				_ = c.decisionKeyboard("1")
				_ = c.identityKeyboard("1")
			}
		}()
	}
	wg.Wait()
	assert.True(t, c.identitiesLoaded)
}
