package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/yaad-index/darbaan/internal/admincfg"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// credential is one admin-API bearer credential (ADR 0029): the SHA-256 of its
// full "Bearer <token>" header value (fixed-width, so the constant-time compare
// can never leak token length) and the set of scopes it grants.
type credential struct {
	hash   [32]byte
	scopes map[string]bool
}

// Server is the localhost-only HTTP admin API. It is the operator's approval
// surface; it must be bound to loopback (or kept container-internal) and is
// reachable only with a bearer credential — never by the agent (ADR 0002). Each
// credential carries a scope set (ADR 0029): the single root token grants every
// scope; per-client tokens grant a least-privilege subset.
type Server struct {
	svc   *Service
	creds []credential
	http  *http.Server
}

// ScopedClient is a named admin client's token + granted scopes (ADR 0029),
// supplied by the serve wiring from the configured admin_clients.
type ScopedClient struct {
	Name   string
	Token  string
	Scopes []string
}

// NewServer builds the admin server. It fails closed: an empty token is refused
// rather than expose an unauthenticated admin API. The token is the full-scope
// root credential (ADR 0029) — the back-compat single-token behavior when no
// scoped clients are added; SetScopedClients adds least-privilege clients.
func NewServer(addr, token string, svc *Service) (*Server, error) {
	if token == "" {
		return nil, errors.New("admin: a token is required (no unauthenticated admin API); set DARBAAN_ADMIN_TOKEN")
	}
	s := &Server{svc: svc}
	s.creds = append(s.creds, credential{
		hash:   hashBearer(token),
		scopes: scopeSet(admincfg.AllScopes()),
	})

	mux := http.NewServeMux()
	s.register(mux, "GET /queue", s.handleList)
	s.register(mux, "GET /queue/{id}", s.handleShow)
	s.register(mux, "POST /queue/{id}/approve", s.handleApprove)
	s.register(mux, "POST /queue/{id}/approve-as/{inbox}", s.handleApproveAs)
	s.register(mux, "POST /queue/{id}/reject", s.handleReject)

	// Configured inbox identities for the Change-sender picker (ADR 0023 slice 5).
	s.register(mux, "GET /inboxes", s.handleInboxes)

	// Inbound hold-for-human queue (ADR 0021): expose = show to the agent, drop =
	// keep hidden.
	s.register(mux, "GET /holds", s.handleHeldList)
	s.register(mux, "POST /holds/{id}/expose", s.handleExpose)
	s.register(mux, "POST /holds/{id}/drop", s.handleDrop)

	// Reconcile safety-cap controls (ADR 0026): list held inboxes, release one.
	s.register(mux, "GET /reconcile", s.handleReconcileStatus)
	s.register(mux, "POST /reconcile/{inbox}/release", s.handleReconcileRelease)

	// Per-account inbound-sync health (#195): is every fronted account syncing?
	s.register(mux, "GET /sync-status", s.handleSyncStatus)

	s.http = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s, nil
}

// SetScopedClients registers the configured per-client scoped credentials
// (ADR 0029). It is called once at setup, before serving; the root token stays as
// break-glass. A client whose token is empty (its secret was not supplied) is
// skipped.
func (s *Server) SetScopedClients(clients []ScopedClient) {
	for _, c := range clients {
		if c.Token == "" {
			continue
		}
		s.creds = append(s.creds, credential{
			hash:   hashBearer(c.Token),
			scopes: scopeSet(c.Scopes),
		})
	}
}

// hashBearer is the fixed-width hash of a token's full Authorization header value.
func hashBearer(token string) [32]byte { return sha256.Sum256([]byte("Bearer " + token)) }

// scopeSet builds a lookup set from a scope list.
func scopeSet(scopes []string) map[string]bool {
	m := make(map[string]bool, len(scopes))
	for _, sc := range scopes {
		m[sc] = true
	}
	return m
}

// register wires a route with the required scope from the authoritative
// route→scope map (ADR 0029). It panics if the route has no mapped scope — a
// build-wiring error (a new admin route must ship with its scope in
// admincfg.RouteScopes), which enforces the map↔routes invariant.
func (s *Server) register(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	scope, ok := admincfg.RouteScopes[pattern]
	if !ok {
		panic("admin: route " + pattern + " has no required scope in admincfg.RouteScopes")
	}
	mux.HandleFunc(pattern, s.scoped(scope, h))
}

// ListenAndServe binds Addr and serves until Close.
func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

// Serve serves on an already-open listener (used by tests).
func (s *Server) Serve(l net.Listener) error { return s.http.Serve(l) }

// Close stops the server.
func (s *Server) Close() error { return s.http.Close() }

// scoped gates a handler on a required scope (ADR 0029): it resolves the
// presented bearer to a credential, then authorizes the scope. An unrecognized
// token is 401 Unauthorized; a recognized token lacking the scope is 403
// Forbidden — a distinct, clearer signal than a blanket 401.
func (s *Server) scoped(required string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cred, ok := s.resolve(r.Header.Get("Authorization"))
		if !ok {
			writeErr(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		if !cred.scopes[required] {
			writeErr(w, http.StatusForbidden, errors.New("forbidden: missing scope "+required))
			return
		}
		next(w, r)
	}
}

// resolve matches a presented Authorization header value to a configured
// credential (ADR 0029). It hashes the value to a fixed width and constant-time-
// compares against every credential with NO early exit, so timing reveals neither
// which credential matched nor whether one did — the same no-oracle discipline as
// the ADR 0027 agent Verify.
func (s *Server) resolve(authHeader string) (credential, bool) {
	got := sha256.Sum256([]byte(authHeader))
	var found credential
	matched := 0
	for _, c := range s.creds {
		if subtle.ConstantTimeCompare(got[:], c.hash[:]) == 1 {
			found = c
			matched = 1
		}
	}
	return found, matched == 1
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	metas, err := s.svc.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if metas == nil {
		metas = []sluice.Meta{}
	}
	writeJSON(w, http.StatusOK, metas)
}

func (s *Server) handleShow(w http.ResponseWriter, r *http.Request) {
	m, err := s.svc.Show(r.PathValue("id"))
	if errors.Is(err, sluice.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "message/rfc822")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(m.Raw)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.ApproveID(r.Context(), r.PathValue("id"))
	writeAction(w, out, err)
}

func (s *Server) handleApproveAs(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.ApproveAs(r.Context(), r.PathValue("id"), r.PathValue("inbox"))
	if errors.Is(err, ErrUnknownInbox) {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeAction(w, out, err)
}

func (s *Server) handleInboxes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Inboxes())
}

func (s *Server) handleHeldList(w http.ResponseWriter, _ *http.Request) {
	held, err := s.svc.HeldList()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if held == nil {
		held = []inbound.Message{}
	}
	writeJSON(w, http.StatusOK, held)
}

func (s *Server) handleExpose(w http.ResponseWriter, r *http.Request) {
	m, err := s.svc.ExposeHeld(r.PathValue("id"))
	s.writeHold(w, m, err)
}

func (s *Server) handleDrop(w http.ResponseWriter, r *http.Request) {
	m, err := s.svc.DropHeld(r.PathValue("id"))
	s.writeHold(w, m, err)
}

func (s *Server) writeHold(w http.ResponseWriter, m inbound.Message, err error) {
	if errors.Is(err, inbound.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleReconcileStatus(w http.ResponseWriter, _ *http.Request) {
	st, err := s.svc.ReconcileStatusAll()
	if errors.Is(err, ErrReconcileUnavailable) {
		writeErr(w, http.StatusServiceUnavailable, err)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if st == nil {
		st = []ReconcileStatus{}
	}
	writeJSON(w, http.StatusOK, st)
}

// handleSyncStatus reports the inbound-sync health of every fronted account (#195).
// An empty list (no account syncs) is a normal 200, not an error.
func (s *Server) handleSyncStatus(w http.ResponseWriter, _ *http.Request) {
	st := s.svc.SyncStatusAll()
	if st == nil {
		st = []SyncStatus{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleReconcileRelease(w http.ResponseWriter, r *http.Request) {
	inbox := r.PathValue("inbox")
	n, err := s.svc.ReleaseReconcile(r.Context(), inbox)
	if errors.Is(err, ErrReconcileUnavailable) {
		writeErr(w, http.StatusServiceUnavailable, err)
		return
	}
	if errors.Is(err, ErrReconcileNotHeld) {
		writeErr(w, http.StatusConflict, err) // not held → nothing to release
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, ReconcileReleaseResult{Inbox: inbox, Purged: n})
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason    string `json:"reason"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Reason == "" {
		writeErr(w, http.StatusBadRequest, errors.New("reason is required"))
		return
	}
	out, err := s.svc.RejectID(r.Context(), r.PathValue("id"), req.Reason, req.Retryable)
	writeAction(w, out, err)
}

// writeAction maps a verdict outcome to a response: a committed verdict is 200
// (any send/bounce issue rides in Outcome.Warn); "can't act" is 404/409.
func writeAction(w http.ResponseWriter, out Outcome, err error) {
	switch {
	case errors.Is(err, sluice.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, sluice.ErrNotPending):
		writeErr(w, http.StatusConflict, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
