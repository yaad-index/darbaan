package main

import (
	"sort"
	"sync"
	"time"

	"github.com/yaad-index/darbaan/internal/admin"
)

// syncHealth is the per-account inbound-sync health registry (#195): the sync loop
// records each cycle's outcome, and the admin API reads a snapshot. It is the
// server-side complement to the client-side fetch alert (#191) — it catches a
// stall that never even reaches a client. It is safe for concurrent use: one
// writer goroutine per account (the sync loop) and the admin reader.
type syncHealth struct {
	mu        sync.RWMutex
	rec       map[string]*syncHealthRecord
	threshold int              // consecutive errors before an account is "stalled"
	now       func() time.Time // injectable for tests
}

// syncHealthRecord is one account's tracked health.
type syncHealthRecord struct {
	lastSuccess  time.Time // last cycle that completed without error
	firstFailure time.Time // start of the current error streak; zero when not failing
	consecErrors int
	lastError    string
	watermarkUID uint32
	uidValidity  uint32
}

// newSyncHealth builds the registry. A threshold below 1 is clamped to 1 so a
// single failure can never be "not yet a stall".
func newSyncHealth(threshold int) *syncHealth {
	if threshold < 1 {
		threshold = 1
	}
	return &syncHealth{rec: map[string]*syncHealthRecord{}, threshold: threshold, now: time.Now}
}

func (h *syncHealth) at(inbox string) *syncHealthRecord {
	r := h.rec[inbox]
	if r == nil {
		r = &syncHealthRecord{}
		h.rec[inbox] = r
	}
	return r
}

// recordSuccess clears the error streak and records the fresh watermark. A zero
// uidValidity means the watermark could not be read this cycle; the prior one is
// then kept rather than clobbered.
func (h *syncHealth) recordSuccess(inbox string, uidValidity, watermarkUID uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.at(inbox)
	r.lastSuccess = h.now()
	r.consecErrors = 0
	r.firstFailure = time.Time{}
	r.lastError = ""
	if uidValidity != 0 {
		r.uidValidity = uidValidity
		r.watermarkUID = watermarkUID
	}
}

// recordFailure extends the error streak and reports whether the account has now
// crossed the stall threshold, along with the streak length and when it began, so
// the caller can emit a loud stall event.
func (h *syncHealth) recordFailure(inbox string, err error) (stalled bool, consec int, since time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.at(inbox)
	if r.consecErrors == 0 {
		r.firstFailure = h.now()
	}
	r.consecErrors++
	if err != nil {
		r.lastError = err.Error()
	}
	return r.consecErrors >= h.threshold, r.consecErrors, r.firstFailure
}

// snapshot returns every account's health as admin.SyncStatus records, inbox-sorted
// for stable output.
func (h *syncHealth) snapshot() []admin.SyncStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]admin.SyncStatus, 0, len(h.rec))
	for inbox, r := range h.rec {
		st := admin.SyncStatus{
			Inbox:             inbox,
			ConsecutiveErrors: r.consecErrors,
			LastError:         r.lastError,
			WatermarkUID:      r.watermarkUID,
			UIDValidity:       r.uidValidity,
			Stalled:           r.consecErrors >= h.threshold,
		}
		if !r.lastSuccess.IsZero() {
			st.LastSuccess = r.lastSuccess.UTC().Format(time.RFC3339)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Inbox < out[j].Inbox })
	return out
}
