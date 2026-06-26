// Package backend is the upstream connectivity layer: the Sender that delivers
// a fully-approved message to the real upstream SMTP (ADR 0009). It is the only
// component that can cause mail to leave Darbaan, and it is selected by config
// (sender-type), defaulting to the stub — so enabling real delivery is a
// deliberate operator act, never a merge side-effect (ADR 0003).
package backend

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/emersion/go-smtp"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// Sender releases an approved message to the real upstream. Only fully-approved
// messages ever reach it (ADR 0003); it is invoked downstream of the approval
// commit, in the caller, never inside the decision path.
type Sender interface {
	Send(ctx context.Context, msg sluice.Message) error
}

// ErrSendPending is returned by the stub Sender: approval reaches the send seam,
// but no upstream backend is configured, so nothing is delivered. Default-deny
// stays structural until an operator sets sender-type=smtp.
var ErrSendPending = errors.New("upstream send pending")

// StubSender is the default Sender. It always returns ErrSendPending, so nothing
// is ever actually sent; the approval still records and audits the attempt.
type StubSender struct{}

// Send always fails with ErrSendPending.
func (StubSender) Send(context.Context, sluice.Message) error { return ErrSendPending }

func init() {
	Register("stub", func(Config) (Sender, error) { return StubSender{}, nil })
}

// Config configures a Sender backend. Password is the SMTP secret (a Gmail app
// password for v1): supplied via the environment, never inlined in config or
// logged (ADR 0012).
type Config struct {
	Host     string // host:port, e.g. smtp.gmail.com:587
	Username string
	Password string
}

// Factory constructs a Sender of a given type.
type Factory func(Config) (Sender, error)

var registry = map[string]Factory{}

// Register adds a named sender backend. It panics on a duplicate name.
func Register(name string, f Factory) {
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("backend: duplicate registration %q", name))
	}
	registry[name] = f
}

// New constructs the configured sender backend, or an error if senderType is not
// registered.
func New(senderType string, cfg Config) (Sender, error) {
	f, ok := registry[senderType]
	if !ok {
		return nil, fmt.Errorf("backend: unknown sender type %q (have %v)", senderType, Registered())
	}
	return f(cfg)
}

// Registered returns the names of all registered sender backends, sorted.
func Registered() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// IsPermanent reports whether a send error is a permanent (5xx) SMTP failure —
// which should bounce the agent (ADR 0006) — as opposed to a transient (4xx) or
// network failure, which leaves the message approved for a manual re-send and
// does NOT bounce. ErrSendPending (the stub) is neither.
func IsPermanent(err error) bool {
	if err == nil || errors.Is(err, ErrSendPending) {
		return false
	}
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se.Code >= 500
	}
	return false // network / unknown → transient
}
