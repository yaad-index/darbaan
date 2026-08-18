package admin_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/admincfg"
	"github.com/yaad-index/darbaan/internal/audit"
)

// wireAudit gives svc a bbolt audit log and returns it so a test can append.
func wireAudit(t *testing.T, svc *admin.Service) audit.AuditLog {
	t.Helper()
	al, err := audit.New("bbolt", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = al.Close() })
	svc.SetAuditLog(al)
	return al
}

func auditSeqs(entries []audit.Entry) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e.Seq
	}
	return out
}

// The two no-read states stay distinct (ADR 0033 §4): no sink wired is
// ErrAuditDisabled; a wired backend that cannot enumerate is ErrAuditNotListable.
func TestAuditListDisabledVsNotListable(t *testing.T) {
	svc, _, _ := newSvc(t) // no audit wired
	_, _, err := svc.AuditList(admin.AuditFilter{}, 0, 10)
	require.ErrorIs(t, err, admin.ErrAuditDisabled)

	// The null backend appends/verifies but is not a Reader.
	nl, err := audit.New("null", "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = nl.Close() })
	svc.SetAuditLog(nl)
	_, _, err = svc.AuditList(admin.AuditFilter{}, 0, 10)
	require.ErrorIs(t, err, admin.ErrAuditNotListable)
}

func TestAuditListPagingAndFilters(t *testing.T) {
	svc, _, _ := newSvc(t)
	al := wireAudit(t, svc)
	agents := []string{"a", "b", "a", "b", "a"}
	for i, ag := range agents {
		require.NoError(t, al.Append(audit.Record{
			Event: "enqueue", Agent: ag, Inbox: "work", MessageID: string(rune('1' + i)),
		}))
	}

	// Paging by resume cursor: no overlap, no gap, and a short final page ends it.
	p1, next, err := svc.AuditList(admin.AuditFilter{}, 0, 2)
	require.NoError(t, err)
	assert.Equal(t, []uint64{1, 2}, auditSeqs(p1))
	assert.Equal(t, uint64(2), next)

	p2, next, err := svc.AuditList(admin.AuditFilter{}, next, 2)
	require.NoError(t, err)
	assert.Equal(t, []uint64{3, 4}, auditSeqs(p2))
	assert.Equal(t, uint64(4), next)

	p3, next, err := svc.AuditList(admin.AuditFilter{}, next, 2)
	require.NoError(t, err)
	assert.Equal(t, []uint64{5}, auditSeqs(p3))
	assert.Equal(t, uint64(0), next, "exhausted log reports no next")

	// Agent filter selects across the whole chain (seqs 1,3,5 are agent a).
	byAgent, next, err := svc.AuditList(admin.AuditFilter{Agent: "a"}, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, []uint64{1, 3, 5}, auditSeqs(byAgent))
	assert.Equal(t, uint64(0), next)

	// Message-id filter is exact.
	byMsg, _, err := svc.AuditList(admin.AuditFilter{MessageID: "4"}, 0, 10)
	require.NoError(t, err)
	require.Len(t, byMsg, 1)
	assert.Equal(t, uint64(4), byMsg[0].Seq)
}

func TestAuditListTimeBounds(t *testing.T) {
	svc, _, _ := newSvc(t)
	al := wireAudit(t, svc)
	require.NoError(t, al.Append(audit.Record{Event: "enqueue", Agent: "a", MessageID: "1"}))

	// The one entry was written ~now. A window in the past excludes it; the same
	// past instant as an open lower bound includes it; a future lower bound excludes.
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	got, _, err := svc.AuditList(admin.AuditFilter{Since: past}, 0, 10)
	require.NoError(t, err)
	assert.Len(t, got, 1, "since in the past includes a now entry")

	got, _, err = svc.AuditList(admin.AuditFilter{Since: future}, 0, 10)
	require.NoError(t, err)
	assert.Empty(t, got, "since in the future excludes a now entry")

	got, _, err = svc.AuditList(admin.AuditFilter{Until: past}, 0, 10)
	require.NoError(t, err)
	assert.Empty(t, got, "until in the past excludes a now entry (half-open upper bound)")
}

// GET /audit is gated on its own audit:read scope (ADR 0033 §2 / ADR 0029): a
// client with a different read scope is 403, one with audit:read reaches the
// handler, an unknown token is 401.
func TestAuditListRouteScope(t *testing.T) {
	svc, _, _ := newSvc(t)
	al := wireAudit(t, svc)
	require.NoError(t, al.Append(audit.Record{Event: "enqueue", Agent: "a", MessageID: "1"}))

	addr := startScopedServer(t, svc, "root-tok",
		admin.ScopedClient{Name: "q", Token: "q-tok", Scopes: []string{admincfg.ScopeQueueRead}},
		admin.ScopedClient{Name: "au", Token: "au-tok", Scopes: []string{admincfg.ScopeAuditRead}},
	)
	base := "http://" + addr

	assert.Equal(t, http.StatusUnauthorized, doReq(t, "GET", base+"/audit", "nope-tok"))
	assert.Equal(t, http.StatusForbidden, doReq(t, "GET", base+"/audit", "q-tok"), "queue:read must not reach audit")
	assert.Equal(t, http.StatusOK, doReq(t, "GET", base+"/audit", "au-tok"))
	assert.Equal(t, http.StatusOK, doReq(t, "GET", base+"/audit", "root-tok"))
}

func TestAuditListClientRoundtrip(t *testing.T) {
	svc, _, _ := newSvc(t)
	al := wireAudit(t, svc)
	for i := 0; i < 3; i++ {
		require.NoError(t, al.Append(audit.Record{Event: "enqueue", Agent: "a", MessageID: string(rune('1' + i))}))
	}
	addr := startScopedServer(t, svc, "root-tok")
	c := admin.NewClient(addr, "root-tok")

	entries, next, err := c.AuditList(context.Background(), admin.AuditFilter{}, 0, 2)
	require.NoError(t, err)
	assert.Equal(t, []uint64{1, 2}, auditSeqs(entries))
	assert.Equal(t, uint64(2), next)
	assert.Equal(t, "a", entries[0].Record.Agent, "record fields survive the round-trip")
}
