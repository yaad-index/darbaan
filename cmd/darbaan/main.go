// Command darbaan is the Darbaan mail-gate proxy CLI.
//
// Configuration layers as file < env < flag: a YAML config file (default
// /etc/darbaan/config.yaml or --config PATH), overridden by DARBAAN_* env
// variables, overridden by command-line flags. See config.go for the mechanism
// and the adr/ directory for the design. cmd/darbaan stays thin (ADR 0013):
// parsing and wiring only; the logic lives in internal/.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kong"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/listener"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// version is the build version, overridden at link time via -ldflags.
var version = "dev"

// CLI is the Darbaan command surface and its configuration. Every config value
// resolves through file < env < flag (see config.go).
type CLI struct {
	Config string `help:"Path to a YAML config file (also searched at /etc/darbaan/config.yaml)." placeholder:"PATH" type:"path"`

	StoreType string `name:"store-type" default:"bbolt" help:"Message store backend." enum:"bbolt"`
	SluiceDB  string `name:"sluice-db" default:"darbaan.db" help:"Path to the sluice (message store) database." type:"path"`

	AuditType string `name:"audit-type" default:"bbolt" help:"Audit log backend: bbolt (hash-chained, on) or null (off)." enum:"bbolt,null"`
	AuditDB   string `name:"audit-db" default:"darbaan-audit.db" help:"Path to the audit database (audit-type=bbolt)." type:"path"`

	ListenerAddr          string `name:"listener-addr" default:":1465" help:"SMTP submission listen address."`
	ListenerDomain        string `name:"listener-domain" default:"localhost" help:"SMTP greeting domain."`
	ListenerTLSCert       string `name:"listener-tls-cert" help:"Path to the TLS certificate (PEM)." type:"path"`
	ListenerTLSKey        string `name:"listener-tls-key" help:"Path to the TLS private key (PEM)." type:"path"`
	ListenerAllowInsecure bool   `name:"listener-allow-insecure" help:"Allow AUTH over plaintext (local testing only)."`

	AgentUsername string `name:"agent-username" help:"The agent's Darbaan SMTP username. The password is supplied out-of-band via DARBAAN_AGENT_PASS, never inlined in config (ADR 0012)."`

	ApprovalStrict []string `name:"approval-strict" default:"manual" help:"Approver chain for the strict path."`
	ApprovalLight  []string `name:"approval-light" default:"manual" help:"Approver chain for the light path."`

	Serve   ServeCmd   `cmd:"" help:"Run the SMTP submission face and sluice."`
	Queue   QueueCmd   `cmd:"" help:"Inspect and decide held messages."`
	Version VersionCmd `cmd:"" help:"Print version and exit."`
}

func main() {
	var cli CLI
	parser, err := kong.New(&cli, kongOptions(resolveConfigPath(os.Args[1:]))...)
	if err != nil {
		panic(err)
	}
	ctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)
	ctx.FatalIfErrorf(ctx.Run(&cli))
}

func (c *CLI) router() *policy.Router {
	return policy.NewRouter(c.ApprovalStrict, c.ApprovalLight)
}

// openStore opens the audit log and the message store per config and returns
// the store plus a close func that closes both (store first, then audit).
func (c *CLI) openStore() (sluice.MessageStore, func(), error) {
	al, err := audit.New(c.AuditType, c.AuditDB)
	if err != nil {
		return nil, nil, err
	}
	ms, err := sluice.New(c.StoreType, c.SluiceDB, al)
	if err != nil {
		_ = al.Close()
		return nil, nil, err
	}
	return ms, func() { _ = ms.Close(); _ = al.Close() }, nil
}

// VersionCmd prints the build version.
type VersionCmd struct{}

func (*VersionCmd) Run() error {
	fmt.Println("darbaan", version)
	return nil
}

// ServeCmd runs the SMTP submission face and sluice.
type ServeCmd struct{}

func (*ServeCmd) Run(cli *CLI) error {
	// The password is a secret supplied at startup, kept in memory only; full
	// at-rest encryption (age) lands with the deployment/secrets component
	// (ADR 0012). Config carries only the username reference, never the secret.
	cred := listener.Credential{
		Username: cli.AgentUsername,
		Password: os.Getenv("DARBAAN_AGENT_PASS"),
	}
	if cred.Username == "" || cred.Password == "" {
		return errors.New("set agent-username (config/flag/DARBAAN_AGENT_USERNAME) and DARBAAN_AGENT_PASS")
	}

	var tlsConfig *tls.Config
	if cli.ListenerTLSCert != "" || cli.ListenerTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cli.ListenerTLSCert, cli.ListenerTLSKey)
		if err != nil {
			return fmt.Errorf("load TLS keypair: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	q, closeStore, err := cli.openStore()
	if err != nil {
		return err
	}
	defer closeStore()

	srv, err := listener.NewServer(listener.ServerConfig{
		Addr:          cli.ListenerAddr,
		Domain:        cli.ListenerDomain,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, cred, q)
	if err != nil {
		return err
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		_ = srv.Close()
	}()

	fmt.Fprintf(os.Stderr, "darbaan: SMTP submission face on %s (db %s)\n", cli.ListenerAddr, cli.SluiceDB)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// QueueCmd groups the queue inspection and decision subcommands.
type QueueCmd struct {
	Ls      QueueLsCmd      `cmd:"" help:"List held outbound messages."`
	Show    QueueShowCmd    `cmd:"" help:"Dump a held message's raw RFC 822."`
	Approve QueueApproveCmd `cmd:"" help:"Approve a held message (runs the approval chain)."`
	Reject  QueueRejectCmd  `cmd:"" help:"Reject a held message."`
}

// QueueLsCmd lists held messages.
type QueueLsCmd struct{}

func (*QueueLsCmd) Run(cli *CLI) error {
	q, closeStore, err := cli.openStore()
	if err != nil {
		return err
	}
	defer closeStore()

	metas, err := q.List()
	if err != nil {
		return err
	}
	if len(metas) == 0 {
		fmt.Fprintln(os.Stderr, "queue is empty")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSTATUS\tAGENT\tFROM\tRCPT\tSIZE\tRECEIVED")
	for _, m := range metas {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			m.ID, m.Status, m.Agent, m.From, len(m.Rcpt), m.Size, m.ReceivedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

// QueueShowCmd dumps a held message's raw RFC 822.
type QueueShowCmd struct {
	ID string `arg:"" help:"Message id."`
}

func (c *QueueShowCmd) Run(cli *CLI) error {
	q, closeStore, err := cli.openStore()
	if err != nil {
		return err
	}
	defer closeStore()

	msg, err := q.Get(c.ID)
	if err != nil {
		return err
	}
	// Raw message/rfc822 to stdout so a human (or the future hold-for-human
	// approval flow) can read exactly what is held.
	_, err = os.Stdout.Write(msg.Raw)
	return err
}

// QueueApproveCmd approves a held message.
type QueueApproveCmd struct {
	ID string `arg:"" help:"Message id."`
}

func (c *QueueApproveCmd) Run(cli *CLI) error {
	q, closeStore, err := cli.openStore()
	if err != nil {
		return err
	}
	defer closeStore()

	m, err := decideAndApply(context.Background(), q, backend.StubSender{}, cli.router(),
		c.ID, approver.Verdict{Disposition: approver.Approve})
	if err != nil {
		return err
	}
	switch m.Status {
	case sluice.StatusApproved:
		fmt.Printf("message %s approved by %s\n", m.ID, m.DecidedBy)
		if m.SendErr != "" {
			fmt.Printf("  send: %s — nothing left Darbaan\n", m.SendErr)
		}
	default:
		fmt.Printf("message %s: still %s, no verdict applied\n", m.ID, m.Status)
	}
	return nil
}

// QueueRejectCmd rejects a held message.
type QueueRejectCmd struct {
	ID        string `arg:"" help:"Message id."`
	Reason    string `required:"" help:"Rejection reason."`
	Retryable bool   `help:"Mark the rejection transient (revise & resubmit) rather than permanent."`
}

func (c *QueueRejectCmd) Run(cli *CLI) error {
	q, closeStore, err := cli.openStore()
	if err != nil {
		return err
	}
	defer closeStore()

	m, err := decideAndApply(context.Background(), q, backend.StubSender{}, cli.router(),
		c.ID, approver.Verdict{Disposition: approver.Reject, Reason: c.Reason, Retryable: c.Retryable})
	if err != nil {
		return err
	}
	switch m.Status {
	case sluice.StatusRejected:
		kind := "permanent"
		if m.Retryable {
			kind = "transient"
		}
		fmt.Printf("message %s rejected by %s (%s): %s\n", m.ID, m.DecidedBy, kind, m.Reason)
	default:
		fmt.Printf("message %s: still %s, no verdict applied\n", m.ID, m.Status)
	}
	return nil
}

// decideAndApply runs the approval chain for one message and applies the
// outcome. The human verdict is injected into the human stage of the chain — it
// is one stage, never an override of the others (ADR 0004). On approval the
// message is marked approved and handed to the (stubbed) Sender; the send result
// is recorded and audited, never silently dropped (ADR 0003). On rejection the
// reason is recorded. A Hold leaves the message pending.
func decideAndApply(ctx context.Context, q sluice.MessageStore, sender backend.Sender, router *policy.Router, id string, human approver.Verdict) (sluice.Message, error) {
	msg, err := q.Get(id)
	if err != nil {
		return sluice.Message{}, err
	}
	if msg.Status != sluice.StatusPending {
		return sluice.Message{}, fmt.Errorf("message %s is %s, not pending", id, msg.Status)
	}

	// No pre-screener exists, so the router runs with no risk signal and
	// returns the strict chain (the ADR 0005 fail-safe).
	_, names := router.Select(nil)
	stages := make([]approver.Approver, 0, len(names))
	for _, name := range names {
		a, err := approver.New(name)
		if err != nil {
			return sluice.Message{}, err
		}
		if h, ok := a.(approver.HumanApprover); ok {
			h.SetVerdict(human)
		}
		stages = append(stages, a)
	}

	outcome, err := approver.Run(ctx, msg, stages)
	if err != nil {
		return sluice.Message{}, err
	}

	switch outcome.Disposition {
	case approver.Approve:
		if _, err := q.Approve(id, outcome.DecidedBy, outcome.Released); err != nil {
			return sluice.Message{}, err
		}
		approved, err := q.Get(id)
		if err != nil {
			return sluice.Message{}, err
		}
		sendErr := sender.Send(ctx, approved)
		return q.RecordSendAttempt(id, sendErr)
	case approver.Reject:
		return q.Reject(id, outcome.DecidedBy, outcome.Reason, outcome.Retryable)
	default: // Hold — stays pending, fail-closed
		return msg, nil
	}
}
