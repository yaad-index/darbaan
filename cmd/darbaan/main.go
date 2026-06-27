// Command darbaan is the Darbaan mail-gate proxy CLI.
//
// Configuration layers as file < env < flag: a YAML config file (default
// /etc/darbaan/config.yaml or --config PATH), overridden by DARBAAN_* env
// variables, overridden by command-line flags. See config.go for the mechanism
// and the adr/ directory for the design. cmd/darbaan stays thin (ADR 0013):
// parsing and wiring only; the logic lives in internal/.
//
// Because bbolt is single-writer, a running `serve` owns the stores and exposes
// the queue over a localhost-only admin API; `darbaan queue ...` is a thin
// client of it (it does not open the database directly).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kong"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/listener"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/signer"
	"github.com/yaad-index/darbaan/internal/sluice"
	"github.com/yaad-index/darbaan/internal/telegram"
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

	AdminAddr string `name:"admin-addr" default:"127.0.0.1:1144" help:"Operator admin API address. Loopback-only / container-internal; the queue subcommands connect here. Token from DARBAAN_ADMIN_TOKEN."`

	InboundIMAPHost         string        `name:"inbound-imap-host" help:"Upstream IMAP host:port to sync the agent's mailbox FROM (ADR 0019). Empty disables sync. App password via DARBAAN_INBOUND_IMAP_PASSWORD."`
	InboundIMAPUsername     string        `name:"inbound-imap-username" help:"Upstream IMAP username for the sync."`
	InboundIMAPMailbox      string        `name:"inbound-imap-mailbox" default:"INBOX" help:"Upstream mailbox to sync."`
	InboundIMAPPollInterval time.Duration `name:"inbound-imap-poll-interval" default:"60s" help:"How often to poll the upstream mailbox for new mail."`
	InboundSyncDB           string        `name:"inbound-sync-db" default:"darbaan-sync.db" help:"Path to the inbound sync-state (UIDVALIDITY + last UID) database." type:"path"`

	AgentUsername string `name:"agent-username" help:"The agent's Darbaan SMTP username. The password is supplied out-of-band via DARBAAN_AGENT_PASS, never inlined in config (ADR 0012)."`

	TelegramOperatorID   int64         `name:"telegram-operator-id" help:"Telegram chat/user id permitted to approve/reject (only this id may act). Bot token via DARBAAN_TELEGRAM_TOKEN."`
	TelegramPollInterval time.Duration `name:"telegram-poll-interval" default:"10s" help:"How often the Telegram client polls the admin queue for new held messages."`

	ApprovalStrict []string `name:"approval-strict" default:"manual" help:"Approver chain for the strict path."`
	ApprovalLight  []string `name:"approval-light" default:"manual" help:"Approver chain for the light path."`

	Serve      ServeCmd      `cmd:"" help:"Run the SMTP + IMAP faces and the admin API."`
	Queue      QueueCmd      `cmd:"" help:"Inspect and decide held messages (via the running serve's admin API)."`
	Telegram   TelegramCmd   `cmd:"" help:"Run the Telegram approval client (a separate admin-API client process)."`
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

// newSyncer builds the inbound sync engine (ADR 0019) if an upstream is
// configured; otherwise returns nil (gated off by default like the stub sender).
// The returned stop func closes the sync-state store.
func (cli *CLI) newSyncer(inbox inbound.InboundStore) (*imapsync.Syncer, func(), error) {
	if cli.InboundIMAPHost == "" {
		return nil, func() {}, nil
	}
	state, err := imapsync.NewStateStore(cli.InboundSyncDB)
	if err != nil {
		return nil, nil, err
	}
	dial := imapsync.Dialer(cli.InboundIMAPHost, cli.InboundIMAPUsername, os.Getenv("DARBAAN_INBOUND_IMAP_PASSWORD"))
	syncer := imapsync.New(dial, cli.InboundIMAPMailbox, cli.AgentUsername, inbox, state)
	return syncer, func() { _ = state.Close() }, nil
}

// imapContentFetch is the read face's on-demand content resolver: the syncer's
// FetchContent when sync is on (serves a pending body by fetching upstream),
// else nil — the read face then reads content from the store (no pending records
// exist without sync).
func imapContentFetch(syncer *imapsync.Syncer) listener.ContentFetch {
	if syncer == nil {
		return nil
	}
	return syncer.FetchContent
}

// runSyncLoop polls the upstream mailbox on the configured interval until ctx is
// cancelled. Sync errors are logged, never fatal — a flaky or unreachable
// upstream must not take down serve.
func (cli *CLI) runSyncLoop(ctx context.Context, syncer *imapsync.Syncer) {
	fmt.Fprintf(os.Stderr, "darbaan: inbound sync on %s (%s as %s) every %s\n",
		cli.InboundIMAPHost, cli.InboundIMAPMailbox, cli.InboundIMAPUsername, cli.InboundIMAPPollInterval)
	t := time.NewTicker(cli.InboundIMAPPollInterval)
	defer t.Stop()
	runSync(ctx, syncer) // initial pull at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runSync(ctx, syncer)
		}
	}
}

func runSync(ctx context.Context, s *imapsync.Syncer) {
	n, err := s.Sync(ctx)
	if err != nil {
		log.Printf("darbaan: inbound sync: %v", err)
		return
	}
	if n > 0 {
		log.Printf("darbaan: inbound sync pulled %d new message(s)", n)
	}
}

// adminClient builds a thin client for the running serve's admin API. The token
// is the shared secret from DARBAAN_ADMIN_TOKEN.
func (c *CLI) adminClient() (*admin.Client, error) {
	token := os.Getenv("DARBAAN_ADMIN_TOKEN")
	if token == "" {
		return nil, errors.New("set DARBAAN_ADMIN_TOKEN (the running serve's admin token)")
	}
	return admin.NewClient(c.AdminAddr, token), nil
}

// TelegramCmd runs the Telegram approval client — a separate long-running
// process that is a client of the admin API (ADR 0017), not part of serve.
type TelegramCmd struct{}

func (*TelegramCmd) Run(cli *CLI) error {
	adminClient, err := cli.adminClient() // reuses admin-addr + DARBAAN_ADMIN_TOKEN
	if err != nil {
		return err
	}
	tc, err := telegram.New(os.Getenv("DARBAAN_TELEGRAM_TOKEN"), cli.TelegramOperatorID, cli.TelegramPollInterval, adminClient)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return tc.Run(ctx)
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

// ServeCmd runs the SMTP + IMAP faces and the operator admin API.
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

	sender, err := cli.openSender()
	if err != nil {
		return err
	}
	// serve handles reject and approve-failure bounces, which must be signed
	// (ADR 0007) — so the running daemon requires the DKIM signer (fail closed).
	sgn, err := cli.openSigner()
	if err != nil {
		return err
	}

	// The admin API owns the approval orchestration; it fails closed without a
	// token (no unauthenticated admin surface).
	svc := admin.NewService(q, inbox, sender, sgn, cli.router(), cli.ListenerDomain)
	adminSrv, err := admin.NewServer(cli.AdminAddr, os.Getenv("DARBAAN_ADMIN_TOKEN"), svc)
	if err != nil {
		return err
	}

	// One local service hosts both agent faces (ADR 0001): SMTP submission
	// (outbound trap) and IMAP read (the agent reads its bounces).
	smtpSrv, err := listener.NewServer(listener.ServerConfig{
		Addr:          cli.ListenerAddr,
		Domain:        cli.ListenerDomain,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, cred, q)
	if err != nil {
		return err
	}
	// Inbound mailbox sync (ADR 0019) — built before the read face so its
	// FetchContent serves pending bodies on demand. nil when no upstream is
	// configured (the read face then reads content straight from the store).
	syncer, stopSync, err := cli.newSyncer(inbox)
	if err != nil {
		return err
	}
	defer stopSync()

	imapSrv, err := listener.NewIMAPServer(listener.IMAPServerConfig{
		Addr:          cli.IMAPAddr,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, cred, inbox, imapContentFetch(syncer))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the sync poll loop (shares the shutdown ctx; errors logged, never fatal).
	if syncer != nil {
		go cli.runSyncLoop(ctx, syncer)
	} else {
		fmt.Fprintln(os.Stderr, "darbaan: inbound sync disabled (no inbound-imap-host configured)")
	}

	closeAll := func() {
		_ = smtpSrv.Close()
		_ = imapSrv.Close()
		_ = adminSrv.Close()
	}
	go func() {
		<-ctx.Done()
		closeAll()
	}()

	ignoreClosed := func(err error) error {
		if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	errs := make(chan error, 3)
	go func() { errs <- ignoreClosed(smtpSrv.ListenAndServe()) }()
	go func() { errs <- ignoreClosed(imapSrv.ListenAndServe(cli.IMAPAddr)) }()
	go func() { errs <- ignoreClosed(adminSrv.ListenAndServe()) }()

	fmt.Fprintf(os.Stderr, "darbaan: SMTP on %s, IMAP on %s, admin on %s\n",
		cli.ListenerAddr, cli.IMAPAddr, cli.AdminAddr)

	// Return on the first server to exit; close the rest and drain them.
	err = <-errs
	closeAll()
	<-errs
	<-errs
	return err
}

// QueueCmd groups the queue subcommands; each is a thin client of the admin API.
type QueueCmd struct {
	Ls      QueueLsCmd      `cmd:"" help:"List held messages."`
	Show    QueueShowCmd    `cmd:"" help:"Dump a held message's raw RFC 822."`
	Approve QueueApproveCmd `cmd:"" help:"Approve a held message (runs the chain in serve)."`
	Reject  QueueRejectCmd  `cmd:"" help:"Reject a held message."`
}

// QueueLsCmd lists held messages.
type QueueLsCmd struct{}

func (*QueueLsCmd) Run(cli *CLI) error {
	c, err := cli.adminClient()
	if err != nil {
		return err
	}
	metas, err := c.List(context.Background())
	if err != nil {
		return err
	}
	if len(metas) == 0 {
		fmt.Fprintln(os.Stderr, "queue is empty")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSTATUS\tAGENT\tFROM\tSUBJECT\tRCPT\tSIZE\tRECEIVED")
	for _, m := range metas {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			m.ID, m.Status, m.Agent, m.From, truncate(m.Subject, 40), len(m.Rcpt), m.Size, m.ReceivedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

// truncate shortens s to at most n runes for table display.
func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// QueueShowCmd dumps a held message's raw RFC 822.
type QueueShowCmd struct {
	ID string `arg:"" help:"Message id."`
}

func (c *QueueShowCmd) Run(cli *CLI) error {
	client, err := cli.adminClient()
	if err != nil {
		return err
	}
	raw, err := client.Show(context.Background(), c.ID)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(raw)
	return err
}

// QueueApproveCmd approves a held message.
type QueueApproveCmd struct {
	ID string `arg:"" help:"Message id."`
}

func (c *QueueApproveCmd) Run(cli *CLI) error {
	client, err := cli.adminClient()
	if err != nil {
		return err
	}
	out, err := client.Approve(context.Background(), c.ID)
	if err != nil {
		return err
	}
	return printOutcome(out)
}

// QueueRejectCmd rejects a held message.
type QueueRejectCmd struct {
	ID        string `arg:"" help:"Message id."`
	Reason    string `required:"" help:"Rejection reason."`
	Retryable bool   `help:"Mark the rejection transient (revise & resubmit) rather than permanent."`
}

func (c *QueueRejectCmd) Run(cli *CLI) error {
	client, err := cli.adminClient()
	if err != nil {
		return err
	}
	out, err := client.Reject(context.Background(), c.ID, c.Reason, c.Retryable)
	if err != nil {
		return err
	}
	return printOutcome(out)
}

// printOutcome reports an approve/reject result. A non-empty Warn is a
// downstream send/bounce issue (distinct from the verdict, which committed); it
// is surfaced and exits non-zero so an operator/script notices.
func printOutcome(out admin.Outcome) error {
	fmt.Printf("message %s: %s\n", out.ID, out.Detail)
	if out.Warn != "" {
		return fmt.Errorf("%s", out.Warn)
	}
	return nil
}
