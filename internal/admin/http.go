package admin

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// Server is the localhost-only HTTP admin API. It is the operator's approval
// surface; it must be bound to loopback (or kept container-internal) and is
// reachable only with the bearer token — never by the agent (ADR 0002).
type Server struct {
	svc   *Service
	token string
	http  *http.Server
}

// NewServer builds the admin server. It fails closed: an empty token is refused
// rather than expose an unauthenticated admin API.
func NewServer(addr, token string, svc *Service) (*Server, error) {
	if token == "" {
		return nil, errors.New("admin: a token is required (no unauthenticated admin API); set DARBAAN_ADMIN_TOKEN")
	}
	s := &Server{svc: svc, token: token}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /queue", s.auth(s.handleList))
	mux.HandleFunc("GET /queue/{id}", s.auth(s.handleShow))
	mux.HandleFunc("POST /queue/{id}/approve", s.auth(s.handleApprove))
	mux.HandleFunc("POST /queue/{id}/reject", s.auth(s.handleReject))

	// Inbound hold-for-human queue (ADR 0021): expose = show to the agent, drop =
	// keep hidden.
	mux.HandleFunc("GET /holds", s.auth(s.handleHeldList))
	mux.HandleFunc("POST /holds/{id}/expose", s.auth(s.handleExpose))
	mux.HandleFunc("POST /holds/{id}/drop", s.auth(s.handleDrop))

	s.http = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s, nil
}

// ListenAndServe binds Addr and serves until Close.
func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

// Serve serves on an already-open listener (used by tests).
func (s *Server) Serve(l net.Listener) error { return s.http.Serve(l) }

// Close stops the server.
func (s *Server) Close() error { return s.http.Close() }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	want := []byte("Bearer " + s.token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			writeErr(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		next(w, r)
	}
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
