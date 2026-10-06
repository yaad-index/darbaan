package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// The queue table tells a re-send in flight and an unknown outcome apart from
// an ordinary failed send.
func TestQueueStatusShowsTheResendStates(t *testing.T) {
	assert.Equal(t, "approved", queueStatus(sluice.Meta{Status: sluice.StatusApproved, SendErr: "451 later"}))
	assert.Equal(t, "approved (OUTCOME UNKNOWN)", queueStatus(sluice.Meta{Status: sluice.StatusApproved, OutcomeUnknown: true}))
	assert.Equal(t, "approved (re-sending)", queueStatus(sluice.Meta{Status: sluice.StatusApproved, OutcomeUnknown: true, ResendInProgress: true}))
}

// queue resend sends the acknowledgement only with its flag, and without it a
// refused re-send names the flag.
func TestQueueResendAcknowledgesOnlyWithItsFlag(t *testing.T) {
	var acked []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ack bool `json:"acknowledge_outcome_unknown"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		acked = append(acked, req.Ack)
		w.Header().Set("Content-Type", "application/json")
		if !req.Ack {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"outcome unknown","code":"ack_required"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"7","status":"sent","detail":"re-sent upstream"}`))
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "tok")
	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}

	err := (&QueueResendCmd{ID: "7"}).Run(cli)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--acknowledge-outcome-unknown")

	require.NoError(t, (&QueueResendCmd{ID: "7", AcknowledgeOutcomeUnknown: true}).Run(cli))
	assert.Equal(t, []bool{false, true}, acked)
}
