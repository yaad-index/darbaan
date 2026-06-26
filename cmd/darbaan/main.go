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
	"github.com/yaad-index/darbaan/internal/bounce"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/listener"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/signer"
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

	InboundType string `name:"inbound-type" default:"bbolt" help:"Inbound (served mailbox) store backend." enum:"bbolt"`
	InboundDB   string `name:"inbound-db" default:"darbaan-inbound.db" help:"Path to the inbound store database." type:"path"`

	DKIMKeyFile  string `name:"dkim-key-file" help:"Path to the PEM-encoded ed25519 DKIM private key used to sign bounces (ADR 0007)." type:"path"`
	DKIMSelector string `name:"dkim-selector" default:"darbaan" help:"DKIM selector for bounce signatures."`
	DKIMDomain   string `name:"dkim-domain" help:"DKIM signing domain (d=) for bounce signatures."`

	SenderType   string `name:"sender-type" default:"stub" help:"Upstream sender: stub (default — nothing sends, default-deny holds) or smtp (real delivery; the deliberate flip)." enum:"stub,smtp"`
	SMTPHost     string `name:"smtp-host" default:"smtp.gmail.com:587" help:"Upstream SMTP submission host:port (sender-type=smtp)."`
	SMTPUsername string `name:"smtp-username" help:"Upstream SMTP username (sender-type=smtp). The app password is supplied via DARBAAN_SMTP_PASSWORD, never inlined."`

	ListenerAddr          string `name:"listener-addr" default:":1465" help:"SMTP submission listen address."`
	ListenerDomain        string `name:"listener-domain" default:"localhost" help:"SMTP greeting domain."`
	ListenerTLSCert       string `name:"listener-tls-cert" help:"Path to the TLS certificate (PEM)." type:"path"`
	ListenerTLSKey        string `name:"listener-tls-key" help:"Path to the TLS private key (PEM)." type:"path"`
	ListenerAllowInsecure bool   `name:"listener-allow-insecure" help:"Allow AUTH over plaintext (local testing only)."`

	IMAPAddr string `name:"imap-addr" default:":1143" help:"IMAP read-face listen address (serves the agent's bounces); reuses the agent credential and listener TLS."`

	AgentUsername string `name:"agent-username" help:"The agent's Darbaan SMTP username. The password is supplied out-of-band via DARBAAN_AGENT_PASS, never inlined in config (ADR 0012)."`

	ApprovalStrict []string `name:"approval-strict" default:"manual" help:"Approver chain for the strict path."`
	ApprovalLight  []string `name:"approval-light" default:"manual" help:"Approver chain for the light path."`

	Serve      ServeCmd      `cmd:"" help:"Run the SMTP submission face and sluice."`
	Queue      QueueCmd      `cmd:"" help:"Inspect and decide held messages."`
	DkimPubkey DkimPubkeyCmd `cmd:"" name:"dkim-pubkey" help:"Print the DKIM public-key record to pin to the agent."`
	Version    VersionCmd    `cmd:"" help:"Print version and exit."`
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

// openInbound opens the inbound (served mailbox) store per config.
func (c *CLI) openInbound() (inbound.InboundStore, error) {
	return inbound.New(c.InboundType, c.InboundDB)
}

// openSigner loads the DKIM signer from config. It fails closed: bounce signing
// is required (ADR 0007), so a missing or invalid key is an error rather than a
// silently-unsigned bounce.
func (c *CLI) openSigner() (*signer.Signer, error) {
	return signer.New(c.DKIMKeyFile, c.DKIMSelector, c.DKIMDomain)
}

// openSender constructs the configured upstream Sender. The default (stub)
// sends nothing, so default-deny holds until an operator sets sender-type=smtp
// with credentials — the flip is a deliberate operator act, not a merge effect.
func (c *CLI) openSender() (backend.Sender, error) {
	return backend.New(c.SenderType, backend.Config{
		Host:     c.SMTPHost,
		Username: c.SMTPUsername,
		Password: os.Getenv("DARBAAN_SMTP_PASSWORD"),
	})
}

// bounceSigner signs a bounce before it is stored. *signer.Signer implements it.
type bounceSigner interface {
	Sign(raw []byte) ([]byte, error)
}

// DkimPubkeyCmd prints the DKIM public-key record for out-of-band pinning.
type DkimPubkeyCmd struct{}

func (*DkimPubkeyCmd) Run(cli *CLI) error {
	s, err := cli.openSigner()
	if err != nil {
		return err
	}
	fmt.Println(s.PublicKeyTXT())
	return nil
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

	inbox, err := cli.openInbound()
	if err != nil {
		return err
	}
	defer func() { _ = inbox.Close() }()

	// One local service hosts both faces (ADR 0001): the SMTP submission face
	// (outbound trap) and the IMAP read face (the agent reads its bounces).
	smtpSrv, err := listener.NewServer(listener.ServerConfig{
		Addr:          cli.ListenerAddr,
		Domain:        cli.ListenerDomain,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, cred, q)
	if err != nil {
		return err
	}
	imapSrv, err := listener.NewIMAPServer(listener.IMAPServerConfig{
		Addr:          cli.IMAPAddr,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, cred, inbox)
	if err != nil {
		return err
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		_ = smtpSrv.Close()
		_ = imapSrv.Close()
	}()

	ignoreClosed := func(err error) error {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	errs := make(chan error, 2)
	go func() { errs <- ignoreClosed(smtpSrv.ListenAndServe()) }()
	go func() { errs <- ignoreClosed(imapSrv.ListenAndServe(cli.IMAPAddr)) }()

	fmt.Fprintf(os.Stderr, "darbaan: SMTP on %s, IMAP on %s (sluice %s, inbound %s)\n",
		cli.ListenerAddr, cli.IMAPAddr, cli.SluiceDB, cli.InboundDB)

	// Return on the first face to exit; close the other and drain it.
	err = <-errs
	_ = smtpSrv.Close()
	_ = imapSrv.Close()
	<-errs
	return err
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

	sender, err := cli.openSender()
	if err != nil {
		return err
	}

	m, err := decideAndApply(context.Background(), q, cli.router(),
		c.ID, approver.Verdict{Disposition: approver.Approve})
	if err != nil {
		return err
	}
	if m.Status != sluice.StatusApproved {
		fmt.Printf("message %s: still %s, no verdict applied\n", m.ID, m.Status)
		return nil
	}
	fmt.Printf("message %s approved by %s\n", m.ID, m.DecidedBy)

	// Bounce deps are only needed if a real Sender can permanently fail; the
	// stub never does, so don't require DKIM config in stub mode.
	var inbox inbound.InboundStore
	var sgn bounceSigner
	if cli.SenderType != "stub" {
		inbox, err = cli.openInbound()
		if err != nil {
			return err
		}
		defer func() { _ = inbox.Close() }()
		if sgn, err = cli.openSigner(); err != nil {
			return err
		}
	}
	return sendApproved(context.Background(), q, sender, inbox, sgn, m, cli.ListenerDomain)
}

// sendApproved delivers an already-approved message to the upstream Sender and
// applies the result — downstream of the approval commit, never inside the
// decision (ADR 0003). On success the message is marked sent. On a permanent
// (5xx) failure the agent is bounced (ADR 0006); on a transient failure the
// message stays approved for a manual re-send and is NOT bounced. The stub
// Sender's ErrSendPending is neither: default-deny simply holds.
func sendApproved(ctx context.Context, q sluice.MessageStore, sender backend.Sender, inbox inbound.InboundStore, sgn bounceSigner, m sluice.Message, domain string) error {
	sendErr := sender.Send(ctx, m)
	if _, err := q.RecordSendAttempt(m.ID, sendErr); err != nil {
		return err
	}

	switch {
	case sendErr == nil:
		fmt.Printf("  sent upstream\n")
		return nil
	case errors.Is(sendErr, backend.ErrSendPending):
		fmt.Printf("  send pending: no real Sender configured — nothing left Darbaan\n")
		return nil
	case backend.IsPermanent(sendErr):
		// Permanent failure: bounce the agent with a generic reason that never
		// echoes the upstream response body.
		if inbox == nil || sgn == nil {
			return fmt.Errorf("message %s approved but upstream send FAILED permanently (no bounce path configured): %w", m.ID, sendErr)
		}
		if bErr := deliverBounce(inbox, sgn, m, "upstream delivery failed permanently", false, domain); bErr != nil {
			return fmt.Errorf("message %s send FAILED permanently AND bounce delivery failed: %v (send: %w)", m.ID, bErr, sendErr)
		}
		fmt.Printf("  send FAILED permanently — bounced to %s\n", m.Agent)
		return fmt.Errorf("message %s approved but upstream send FAILED permanently (bounced): %w", m.ID, sendErr)
	default:
		// Transient: stays approved for a manual re-send; no bounce, no retry loop.
		return fmt.Errorf("message %s approved but upstream send failed (transient; stays approved for re-send): %w", m.ID, sendErr)
	}
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

	// Reject generates a DSN bounce delivered to the agent's inbound mailbox.
	inbox, err := cli.openInbound()
	if err != nil {
		return err
	}
	defer func() { _ = inbox.Close() }()

	// Bounce signing is required (ADR 0007): fail closed if the key is not set
	// or invalid, rather than emit a bounce the agent will not trust.
	sgn, err := cli.openSigner()
	if err != nil {
		return err
	}

	m, err := decideAndApply(context.Background(), q, cli.router(),
		c.ID, approver.Verdict{Disposition: approver.Reject, Reason: c.Reason, Retryable: c.Retryable})
	if err != nil {
		return err
	}
	if m.Status != sluice.StatusRejected {
		fmt.Printf("message %s: still %s, no verdict applied\n", m.ID, m.Status)
		return nil
	}

	// The rejection has committed; report it first. Bounce delivery is a
	// distinct, downstream step.
	kind := "permanent"
	if m.Retryable {
		kind = "transient"
	}
	fmt.Printf("message %s rejected by %s (%s): %s\n", m.ID, m.DecidedBy, kind, m.Reason)

	if err := deliverBounce(inbox, sgn, m, m.Reason, m.Retryable, cli.ListenerDomain); err != nil {
		// The reject stuck; only the bounce failed. Surface it as its own signal
		// — the agent was NOT notified and the bounce needs redelivery — never as
		// a reject failure (ADR 0006).
		return fmt.Errorf("message %s rejected, but bounce delivery FAILED (agent not notified, needs redelivery): %w", m.ID, err)
	}
	fmt.Printf("  bounce delivered to %s\n", m.Agent)
	return nil
}

// deliverBounce generates, signs, and delivers the DSN bounce for an
// already-rejected message. It is a distinct step from the rejection: a failure
// here means "rejected, but the agent was not notified," not a reject failure
// (ADR 0006). Signing is required (ADR 0007).
func deliverBounce(inbox inbound.InboundStore, sgn bounceSigner, m sluice.Message, reason string, retryable bool, domain string) error {
	b, err := bounce.Generate(m, reason, retryable, domain)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	signed, err := sgn.Sign(b.Raw)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if _, err := inbox.Add(inbound.Delivery{
		Owner: b.Owner, From: b.From, To: b.To, Subject: b.Subject, Raw: signed,
	}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// decideAndApply runs the approval chain for one message and commits the
// outcome — nothing more. The human verdict is injected into the human stage of
// the chain — it is one stage, never an override of the others (ADR 0004).
// Approve commits status=approved, Reject commits status=rejected, Hold leaves
// it pending. Everything downstream of the commit (sending an approved message,
// recording the send, bouncing on failure) lives in the caller, so this stays
// pure and the send/bounce paths never re-entangle the decision.
func decideAndApply(ctx context.Context, q sluice.MessageStore, router *policy.Router, id string, human approver.Verdict) (sluice.Message, error) {
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
		// Commit only. The send is a distinct, downstream step (sendApproved)
		// so a send failure is never mistaken for an approval failure.
		return q.Approve(id, outcome.DecidedBy, outcome.Released)
	case approver.Reject:
		// Commit the rejection. The DSN bounce is a distinct, downstream step
		// (deliverBounce) so a delivery failure is never mistaken for a reject
		// failure (ADR 0006).
		return q.Reject(id, outcome.DecidedBy, outcome.Reason, outcome.Retryable)
	default: // Hold — stays pending, fail-closed
		return msg, nil
	}
}
