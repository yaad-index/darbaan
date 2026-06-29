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
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kong"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/bounceguard"
	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/inboxcfg"
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
	InboundMaxAge           string        `name:"inbound-max-age" help:"Recency cutoff for the initial/full sync, e.g. 1y, 30d, 12h (ADR 0008). Empty = no cutoff (pull everything). Forward-only: widening it later needs a re-sync."`
	InboundFilter           string        `name:"inbound-filter" help:"Path to the inbound filter rules (YAML, ADR 0021): serve-time allow/hide over synced mail. Empty = no filter (allow all)." type:"path"`

	BounceGuardEnabled bool   `name:"bounce-guard-enabled" default:"true" help:"Inbound bounce-spoof guard (ADR 0024): hide mail posing as a delivery-status bounce that lacks a valid Darbaan signature. On by default; false is an explicit opt-out."`
	BounceGuardOnSpoof string `name:"bounce-guard-on-spoof" default:"hide" enum:"hide,hold-for-human" help:"What to do with a spoof candidate: hide it from the agent (default), or hold-for-human (route to the inbound approval queue)."`

	AgentUsername string `name:"agent-username" help:"The agent's Darbaan SMTP username. The password is supplied out-of-band via DARBAAN_AGENT_PASS, never inlined in config (ADR 0012)."`

	TelegramOperatorID   int64         `name:"telegram-operator-id" help:"Telegram chat/user id permitted to approve/reject (only this id may act). Bot token via DARBAAN_TELEGRAM_TOKEN."`
	TelegramPollInterval time.Duration `name:"telegram-poll-interval" default:"10s" help:"How often the Telegram client polls the admin queue for new held messages."`

	ApprovalStrict []string `name:"approval-strict" default:"manual" help:"Approver chain for the strict path."`
	ApprovalLight  []string `name:"approval-light" default:"manual" help:"Approver chain for the light path."`

	Serve      ServeCmd      `cmd:"" help:"Run the SMTP + IMAP faces and the admin API."`
	Queue      QueueCmd      `cmd:"" help:"Inspect and decide held messages (via the running serve's admin API)."`
	Holds      HoldsCmd      `cmd:"" help:"Inspect and decide inbound messages held for a human (ADR 0021)."`
	Filter     FilterCmd     `cmd:"" help:"Inspect the inbound filter without starting serve (ADR 0021/0022)."`
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

// configBytes returns the bytes of the resolved config file (the same path kong
// loaded — --config / DARBAAN_CONFIG / a default), or nil if none. The inboxes:
// list (ADR 0023) is read from it directly, since kong's flat flags don't model
// a list of inbox objects.
func (c *CLI) configBytes() ([]byte, error) {
	path := c.Config
	if path == "" {
		for _, p := range defaultConfigPaths {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return data, nil
}

// resolveInboxes resolves the configured inboxes (ADR 0023), or a single implicit
// "default" inbox built from the legacy top-level flags when no inboxes: is
// configured — so an existing single-inbox config is unchanged. Each inbox's
// filter is validated (compiles) by Validate.
func (c *CLI) resolveInboxes() ([]inboxcfg.Inbox, error) {
	data, err := c.configBytes()
	if err != nil {
		return nil, err
	}
	parsed, err := inboxcfg.Parse(data)
	if err != nil {
		return nil, err
	}
	implicit := inboxcfg.Inbox{
		Name:       inbound.DefaultInbox,
		Identity:   c.SMTPUsername,
		FilterFile: c.InboundFilter,
		Backend: inboxcfg.Backend{
			IMAPHost:     c.InboundIMAPHost,
			IMAPUsername: c.InboundIMAPUsername,
			IMAPMailbox:  c.InboundIMAPMailbox,
			MaxAge:       c.InboundMaxAge,
			SenderType:   c.SenderType,
			SMTPHost:     c.SMTPHost,
			SMTPUsername: c.SMTPUsername,
		},
	}
	inboxes := inboxcfg.Resolve(parsed, implicit)
	if err := inboxcfg.Validate(inboxes); err != nil {
		return nil, err
	}
	return inboxes, nil
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
	maxAge, err := parseMaxAge(cli.InboundMaxAge)
	if err != nil {
		return nil, nil, fmt.Errorf("inbound-max-age: %w", err)
	}
	state, err := imapsync.NewStateStore(cli.InboundSyncDB)
	if err != nil {
		return nil, nil, err
	}
	pass := os.Getenv("DARBAAN_INBOUND_IMAP_PASSWORD")
	dial := imapsync.Dialer(cli.InboundIMAPHost, cli.InboundIMAPUsername, pass)
	syncer := imapsync.New(dial, cli.InboundIMAPMailbox, cli.AgentUsername, inbound.DefaultInbox, inbox, state, maxAge)
	// Gmail label write-through (ADR 0020 20c): capability-gated, so harmless on a
	// non-Gmail backend (reports not-supported → WriteKeywords uses plain keywords).
	syncer.SetLabelStore(imapsync.RawGmailLabelStore(cli.InboundIMAPHost, cli.InboundIMAPUsername, pass, cli.InboundIMAPMailbox))
	return syncer, func() { _ = state.Close() }, nil
}

// parseMaxAge parses the recency-cutoff duration: time.ParseDuration units
// (h/m/s) plus the calendar-ish d/w/y suffixes it lacks (kong/ParseDuration would
// reject "1y"). Empty or "0" means no cutoff. y is treated as 365 days.
func parseMaxAge(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	units := map[byte]time.Duration{
		'd': 24 * time.Hour,
		'w': 7 * 24 * time.Hour,
		'y': 365 * 24 * time.Hour,
	}
	if mult, ok := units[s[len(s)-1]]; ok {
		val, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		if val < 0 {
			return 0, fmt.Errorf("invalid duration %q: must not be negative", s)
		}
		return time.Duration(val * float64(mult)), nil
	}
	return time.ParseDuration(s)
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

// imapKeywordWriter is the read face's label write-through (ADR 0020): the
// syncer's WriteKeywords when sync is on, else nil (local-only labels — a
// sync-disabled deploy has no upstream to replicate to).
func imapKeywordWriter(syncer *imapsync.Syncer) listener.KeywordWriter {
	if syncer == nil {
		return nil
	}
	return syncer.WriteKeywords
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

// FilterCmd groups inbound-filter inspection subcommands (no serve, no stores).
type FilterCmd struct {
	Explain FilterExplainCmd `cmd:"" help:"Resolve and print the filter: the default disposition and each rule's resolved action (bare rules show the action implied by default_visibility)."`
}

// FilterExplainCmd compiles the inbound filter and prints its resolved shape — a
// dry-run that surfaces what a bare (action-less) rule resolves to under the
// configured default visibility (ADR 0022), so the disposition is auditable
// without reading mail or starting serve.
type FilterExplainCmd struct {
	Path string `arg:"" optional:"" help:"Filter YAML path (defaults to --inbound-filter)." type:"path"`
}

func (c *FilterExplainCmd) Run(cli *CLI) error {
	path := c.Path
	if path == "" {
		path = cli.InboundFilter
	}
	if path == "" {
		return errors.New("no filter path: pass an argument or set --inbound-filter")
	}
	flt, err := filter.Load(path)
	if err != nil {
		return err
	}
	def := flt.Default()
	fmt.Printf("filter: %s\n", path)
	fmt.Printf("default: %s  (no match → %s)\n", def, visibilityWord(def))
	rules := flt.Rules()
	if len(rules) == 0 {
		fmt.Println("rules: (none)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "#\tMATCH\tACTION\tSOURCE")
	for i, r := range rules {
		source := "explicit"
		if r.Implied {
			source = "implied by default_visibility"
		}
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", i+1, r.Match, r.Action, source)
	}
	return w.Flush()
}

// visibilityWord renders a no-match action as its operator-facing disposition.
func visibilityWord(a filter.Action) string {
	switch a {
	case filter.Hide:
		return "hidden"
	case filter.Hold:
		return "held for human"
	default:
		return "visible"
	}
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

	// Resolve the configured inboxes (ADR 0023): a config with no inboxes: is one
	// implicit "default" inbox built from the legacy top-level flags, so a
	// single-inbox deployment is unchanged. Each inbox's filter is compiled up
	// front (fail-fast on a bad rule set). 3a wires the resolution + per-inbox
	// filter map; the read face still serves the default inbox here — N mailboxes
	// land in 3b.
	inboxes, err := cli.resolveInboxes()
	if err != nil {
		return err
	}
	filters := make(map[string]*filter.Filter, len(inboxes))
	for _, in := range inboxes {
		f, ferr := in.Filter()
		if ferr != nil {
			return fmt.Errorf("inbox %q: %w", in.Name, ferr)
		}
		filters[in.Name] = f
	}
	flt := filters[inbound.DefaultInbox]
	// The inbound bounce-spoof guard (ADR 0024) runs ahead of the user filter on
	// both faces, verifying with the bounce signer's own key. On by default; an
	// explicit opt-out is logged. on_spoof=hold-for-human routes spoofs to the
	// inbound approval queue instead of hiding them.
	var guard *bounceguard.Guard
	if cli.BounceGuardEnabled {
		guard = bounceguard.New(sgn.Verify)
	} else {
		fmt.Fprintln(os.Stderr, "darbaan: bounce-spoof guard DISABLED (bounce-guard-enabled=false)")
	}
	holdSpoof := cli.BounceGuardOnSpoof == "hold-for-human"
	// The admin hold-for-human queue and the read face share one filter + owner +
	// guard (ADR 0021/0024): the read face hides held/spoof mail, the admin surface
	// decides it.
	svc.SetInboundHolds(flt, cli.AgentUsername, guard, holdSpoof)
	imapSrv, err := listener.NewIMAPServer(listener.IMAPServerConfig{
		Addr:          cli.IMAPAddr,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, cred, inbox, imapContentFetch(syncer), imapKeywordWriter(syncer), filters, guard, holdSpoof)
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

// HoldsCmd decides inbound messages held for a human (ADR 0021), the inbound
// mirror of `queue`.
type HoldsCmd struct {
	Ls     HoldsLsCmd     `cmd:"" help:"List inbound messages held for a decision."`
	Expose HoldsExposeCmd `cmd:"" help:"Expose a held message to the agent (approve)."`
	Drop   HoldsDropCmd   `cmd:"" help:"Keep a held message hidden from the agent (reject)."`
}

type HoldsLsCmd struct{}

func (*HoldsLsCmd) Run(cli *CLI) error {
	c, err := cli.adminClient()
	if err != nil {
		return err
	}
	held, err := c.HeldList(context.Background())
	if err != nil {
		return err
	}
	if len(held) == 0 {
		fmt.Fprintln(os.Stderr, "no messages held for a decision")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tFROM\tSUBJECT\tRECEIVED")
	for _, m := range held {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			m.ID, m.From, truncate(m.Subject, 40), m.ReceivedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

// HoldsExposeCmd exposes a held message to the agent.
type HoldsExposeCmd struct {
	ID string `arg:"" help:"Message id."`
}

func (c *HoldsExposeCmd) Run(cli *CLI) error {
	client, err := cli.adminClient()
	if err != nil {
		return err
	}
	m, err := client.Expose(context.Background(), c.ID)
	if err != nil {
		return err
	}
	fmt.Printf("message %s exposed to the agent\n", m.ID)
	return nil
}

// HoldsDropCmd keeps a held message hidden from the agent.
type HoldsDropCmd struct {
	ID string `arg:"" help:"Message id."`
}

func (c *HoldsDropCmd) Run(cli *CLI) error {
	client, err := cli.adminClient()
	if err != nil {
		return err
	}
	m, err := client.Drop(context.Background(), c.ID)
	if err != nil {
		return err
	}
	fmt.Printf("message %s dropped (stays hidden from the agent)\n", m.ID)
	return nil
}
