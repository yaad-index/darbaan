package listener

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/provenance"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// Enqueuer is the sink an authenticated submission is trapped into. The sluice
// implements it; the SMTP face never sends upstream (ADR 0003).
type Enqueuer interface {
	Enqueue(sluice.Submission) (sluice.Message, error)
}

// Router resolves which inbox an authenticated submission's From routes to (ADR
// 0023): the inbox whose identity matches From, else the catchAll inbox if it
// exists (the catch-all target — the connecting agent's default_inbox in
// multi-agent mode, ADR 0027, or the global default at N=1), else false — the
// submission is then refused at MAIL FROM. nil routes every From to the default
// inbox (single-inbox / back-compat).
type Router func(from, catchAll string) (inbox string, ok bool)

// Backend is the go-smtp backend for the submission face.
type Backend struct {
	auth  *Auth
	queue Enqueuer
	route Router
}

// NewBackend builds a Backend that authenticates against auth, routes each
// submission's From to an inbox via route (nil = always the default inbox), and
// traps every accepted submission into queue.
func NewBackend(auth *Auth, queue Enqueuer, route Router) *Backend {
	return &Backend{auth: auth, queue: queue, route: route}
}

// resolveInbox routes a From to its inbox (ADR 0023); ok=false means refuse.
func (b *Backend) resolveInbox(from, catchAll string) (string, bool) {
	if b.route == nil {
		return "", true // back-compat: any From → default inbox
	}
	return b.route(from, catchAll)
}

// NewSession starts a new SMTP session.
func (b *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &session{backend: b}, nil
}

// session implements smtp.Session and smtp.AuthSession for one connection.
type session struct {
	backend   *Backend
	authed    bool
	principal *Principal // the authenticated agent + its grants (ADR 0027)
	agent     string     // the authenticated agent's name, stamped on the submission
	from      string
	inbox     string // the inbox From routed to (ADR 0023)
	rcpt      []string
}

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnsupported
	}
	return sasl.NewPlainServer(func(_, username, password string) error {
		p, ok := s.backend.auth.Verify(username, password)
		if !ok {
			return smtp.ErrAuthFailed
		}
		s.principal = p
		s.agent = p.Name
		s.authed = true
		return nil
	}), nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	// Route the From to an inbox (ADR 0023): its matching identity, else the
	// catch-all — the connecting agent's default_inbox (per-agent, ADR 0027), or
	// the global default at N=1 (empty DefaultInbox). Refuse a From that matches no
	// inbox and has no catch-all, fail-fast at MAIL FROM.
	catchAll := inbound.DefaultInbox
	if s.principal != nil && s.principal.DefaultInbox != "" {
		catchAll = s.principal.DefaultInbox
	}
	inbox, ok := s.backend.resolveInbox(from, catchAll)
	if !ok {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "sender address is not configured for any inbox",
		}
	}
	// Send-scoping (ADR 0027): the connecting agent must be granted send on the
	// resolved inbox. A read-only grant cannot originate mail — reject at submit,
	// fail-closed (ADR 0003), before the message is ever trapped. An unrestricted
	// principal (single-agent / back-compat) may send as any inbox.
	if !s.principal.CanSend(inbox) {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "not authorized to send as this inbox",
		}
	}
	s.from = from
	s.inbox = inbox
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	s.rcpt = append(s.rcpt, to)
	return nil
}

// Data reads the message and traps it in the sluice. It returns nil (250 OK)
// only once the message is durably queued; nothing is sent upstream
// (ADR 0003, default-deny).
func (s *session) Data(r io.Reader) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	// Routing + ADR 0027 send-scoping key on the envelope MAIL FROM, but recipients
	// see the header From. Reject at submit when the visible header From diverges
	// from the routed/scoped envelope sender (C27), so a send-granted agent cannot
	// present an identity it holds no grant on. An ambiguous From (unparseable
	// header block, more than one From header, or not exactly one address) is
	// rejected fail-closed; an absent From is allowed. The legitimate "send as a
	// different identity" path is the operator's ApproveAs, not a divergent header.
	hdrFrom, err := provenance.SubmitFromAddress(raw)
	if err != nil {
		slog.Warn("submission rejected: ambiguous From header", "agent", s.agent, "inbox", s.inbox, "error", err)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "message From header is malformed or ambiguous"}
	}
	if hdrFrom != "" && hdrFrom != provenance.NormalizeAddress(s.from) {
		slog.Warn("submission rejected: header From differs from envelope sender", "agent", s.agent, "inbox", s.inbox)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "message From header does not match the envelope sender"}
	}
	if _, err := s.backend.queue.Enqueue(sluice.Submission{
		Agent: s.agent,
		Inbox: s.inbox,
		From:  s.from,
		Rcpt:  s.rcpt,
		Raw:   raw,
	}); err != nil {
		// A queue write can fail transiently (locked DB, disk hiccup). Return a
		// 4xx so a correct client retries instead of dropping the mail, and keep
		// the internal error server-side only — never leak it to the agent (C12).
		slog.Error("trap submission failed", "agent", s.agent, "inbox", s.inbox, "error", err)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary queue failure",
		}
	}
	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.inbox = ""
	s.rcpt = nil
}

func (s *session) Logout() error { return nil }

// ServerConfig configures the SMTP submission listener.
type ServerConfig struct {
	Addr            string      // listen address, e.g. ":1465"
	Domain          string      // SMTP greeting domain
	TLSConfig       *tls.Config // enables STARTTLS; required unless AllowInsecure
	AllowInsecure   bool        // permit AUTH over plaintext — local/testing only
	MaxMessageBytes int64       // 0 = library default
	ReadTimeout     time.Duration
}

// Server is the SMTP submission face agents send through.
type Server struct {
	smtp *smtp.Server
}

// NewServer wires the submission face. TLS is required: NewServer refuses to
// start a plaintext listener that would carry credentials in the clear unless
// AllowInsecure is explicitly set (local/testing). route maps each submission's
// From to an inbox (ADR 0023; nil = always the default inbox).
func NewServer(cfg ServerConfig, auth *Auth, queue Enqueuer, route Router) (*Server, error) {
	if cfg.TLSConfig == nil && !cfg.AllowInsecure {
		return nil, errors.New("listener: TLS required (set TLSConfig, or AllowInsecure for local testing)")
	}
	srv := smtp.NewServer(NewBackend(auth, queue, route))
	srv.Addr = cfg.Addr
	srv.Domain = cfg.Domain
	srv.TLSConfig = cfg.TLSConfig
	srv.AllowInsecureAuth = cfg.AllowInsecure
	if cfg.MaxMessageBytes > 0 {
		srv.MaxMessageBytes = cfg.MaxMessageBytes
	}
	if cfg.ReadTimeout > 0 {
		srv.ReadTimeout = cfg.ReadTimeout
	}
	return &Server{smtp: srv}, nil
}

// ListenAndServe binds cfg.Addr and serves until Close is called.
func (s *Server) ListenAndServe() error { return s.smtp.ListenAndServe() }

// Serve serves on an already-open listener (used by tests).
func (s *Server) Serve(l net.Listener) error { return s.smtp.Serve(l) }

// Close stops the server.
func (s *Server) Close() error { return s.smtp.Close() }
