package listener

import (
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// Credential is a single agent's Darbaan SMTP credential. The agent
// authenticates to Darbaan with this and never holds upstream credentials
// (ADR 0002). v1 is single-agent; the mechanism generalizes to many (ADR 0010).
type Credential struct {
	Username string
	Password string
}

// Enqueuer is the sink an authenticated submission is trapped into. The sluice
// implements it; the SMTP face never sends upstream (ADR 0003).
type Enqueuer interface {
	Enqueue(sluice.Submission) (sluice.Message, error)
}

// Router resolves which inbox an authenticated submission's From routes to (ADR
// 0023), reporting false when the From matches no inbox and there is no default —
// the submission is then refused at MAIL FROM. nil routes every From to the
// default inbox (single-inbox / back-compat).
type Router func(from string) (inbox string, ok bool)

// Backend is the go-smtp backend for the submission face.
type Backend struct {
	cred  Credential
	queue Enqueuer
	route Router
}

// NewBackend builds a Backend that authenticates against cred, routes each
// submission's From to an inbox via route (nil = always the default inbox), and
// traps every accepted submission into queue.
func NewBackend(cred Credential, queue Enqueuer, route Router) *Backend {
	return &Backend{cred: cred, queue: queue, route: route}
}

// resolveInbox routes a From to its inbox (ADR 0023); ok=false means refuse.
func (b *Backend) resolveInbox(from string) (string, bool) {
	if b.route == nil {
		return "", true // back-compat: any From → default inbox
	}
	return b.route(from)
}

// NewSession starts a new SMTP session.
func (b *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &session{backend: b}, nil
}

// session implements smtp.Session and smtp.AuthSession for one connection.
type session struct {
	backend *Backend
	authed  bool
	from    string
	inbox   string // the inbox From routed to (ADR 0023)
	rcpt    []string
}

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnsupported
	}
	return sasl.NewPlainServer(func(_, username, password string) error {
		if !constEqual(username, s.backend.cred.Username) ||
			!constEqual(password, s.backend.cred.Password) {
			return smtp.ErrAuthFailed
		}
		s.authed = true
		return nil
	}), nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	// Route the From to an inbox (ADR 0023); refuse a From that matches no inbox
	// and has no default catch-all, fail-fast at MAIL FROM.
	inbox, ok := s.backend.resolveInbox(from)
	if !ok {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "sender address is not configured for any inbox",
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
	if _, err := s.backend.queue.Enqueue(sluice.Submission{
		Agent: s.backend.cred.Username,
		Inbox: s.inbox,
		From:  s.from,
		Rcpt:  s.rcpt,
		Raw:   raw,
	}); err != nil {
		return fmt.Errorf("trap submission: %w", err)
	}
	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.inbox = ""
	s.rcpt = nil
}

func (s *session) Logout() error { return nil }

func constEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

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
func NewServer(cfg ServerConfig, cred Credential, queue Enqueuer, route Router) (*Server, error) {
	if cfg.TLSConfig == nil && !cfg.AllowInsecure {
		return nil, errors.New("listener: TLS required (set TLSConfig, or AllowInsecure for local testing)")
	}
	srv := smtp.NewServer(NewBackend(cred, queue, route))
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
