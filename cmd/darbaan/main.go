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
	"log/slog"
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
	"github.com/yaad-index/darbaan/internal/agentcfg"
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

	LogLevel  string `name:"log-level" default:"info" enum:"debug,info,warn,error" help:"Log verbosity."`
	LogFormat string `name:"log-format" default:"text" enum:"text,json" help:"Log handler: text (human-readable) or json (structured ingest)."`

	Serve      ServeCmd      `cmd:"" help:"Run the SMTP + IMAP faces and the admin API."`
	Queue      QueueCmd      `cmd:"" help:"Inspect and decide held messages (via the running serve's admin API)."`
	Holds      HoldsCmd      `cmd:"" help:"Inspect and decide inbound messages held for a human (ADR 0021)."`
	Reconcile  ReconcileCmd  `cmd:"" help:"Inspect and release inboxes held by the reconcile safety cap (ADR 0026)."`
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
	parser.FatalIfErrorf(cli.setupLogging())
	ctx.FatalIfErrorf(ctx.Run(&cli))
}

// setupLogging builds the structured logger from --log-level/--log-format and
// installs it as the slog default, so every subcommand (and every component that
// falls back to slog.Default()) logs through it.
func (c *CLI) setupLogging() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch c.LogFormat {
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default: // "text"
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
	return nil
}

func (c *CLI) router() *policy.Router {
	return policy.NewRouter(c.ApprovalStrict, c.ApprovalLight)
}

// openStore opens the message store per config, writing best-effort audit
// entries to al. al is created and closed by the caller (it is shared with the
// reconcile pass, which audits each retraction — ADR 0026), so the returned close
// func closes only the store.
func (c *CLI) openStore(al audit.AuditLog) (sluice.MessageStore, func(), error) {
	ms, err := sluice.New(c.StoreType, c.SluiceDB, al)
	if err != nil {
		return nil, nil, err
	}
	return ms, func() { _ = ms.Close() }, nil
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

// principalWiring is the resolved multi-agent auth for the serve loop (ADR 0027):
// the login principals, the synced-mail owner key per inbox, and whether the
// mail-owner is decoupled from the login (multi-agent mode).
type principalWiring struct {
	principals []listener.Principal
	// mailOwner is an inbox's synced-mail store owner: its own name in multi-agent
	// mode (so agents sharing an inbox read the same records), or the single
	// implicit agent in back-compat mode (unchanged store keys).
	mailOwner func(inbox string) string
	// decoupled is true in multi-agent mode, where synced mail is keyed by inbox
	// name and existing records are rekeyed once at startup.
	decoupled bool
}

// resolvePrincipals resolves the configured agent principals (ADR 0027): the
// `agents:` list, each a login with per-inbox grants and a password read from
// DARBAAN_AGENT_<NAME>_PASSWORD (ADR 0012). With no `agents:` list it returns a
// single implicit agent authenticated by DARBAAN_AGENT_PASS, granted every inbox
// read+send — the back-compat single-agent path, whose store keys are unchanged.
func (c *CLI) resolvePrincipals(inboxes []inboxcfg.Inbox) (principalWiring, error) {
	data, err := c.configBytes()
	if err != nil {
		return principalWiring{}, err
	}
	agents, err := agentcfg.Parse(data)
	if err != nil {
		return principalWiring{}, err
	}
	if len(agents) == 0 {
		pass := os.Getenv("DARBAAN_AGENT_PASS")
		if c.AgentUsername == "" || pass == "" {
			return principalWiring{}, errors.New("set agent-username (config/flag/DARBAAN_AGENT_USERNAME) and DARBAAN_AGENT_PASS")
		}
		owner := c.AgentUsername
		return principalWiring{
			principals: []listener.Principal{{Name: owner, Password: pass}},
			mailOwner:  func(string) string { return owner },
		}, nil
	}
	inboxNames := make(map[string]bool, len(inboxes))
	for _, in := range inboxes {
		inboxNames[in.Name] = true
	}
	if err := agentcfg.Validate(agents, inboxNames); err != nil {
		return principalWiring{}, err
	}
	principals := make([]listener.Principal, 0, len(agents))
	for _, a := range agents {
		env := agentcfg.PasswordEnv(a.Name)
		pass := os.Getenv(env)
		if pass == "" {
			return principalWiring{}, fmt.Errorf("agent %q: set %s (the password is supplied out-of-band, never in config — ADR 0012)", a.Name, env)
		}
		def, err := agentcfg.DefaultInbox(a)
		if err != nil {
			return principalWiring{}, err
		}
		reads := make(map[string]bool, len(a.Grants))
		sends := make(map[string]bool, len(a.Grants))
		for _, g := range a.Grants {
			if g.HasAccess(agentcfg.AccessRead) {
				reads[g.Inbox] = true
			}
			if g.HasAccess(agentcfg.AccessSend) {
				sends[g.Inbox] = true
			}
		}
		principals = append(principals, listener.Principal{
			Name: a.Name, Password: pass,
			DefaultInbox: def, Reads: reads, Sends: sends,
		})
	}
	return principalWiring{
		principals: principals,
		mailOwner:  func(inbox string) string { return inbound.NormInbox(inbox) },
		decoupled:  true,
	}, nil
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

// inboxIMAPPassword resolves an inbox's upstream IMAP password (ADR 0012/0023):
// the per-inbox env DARBAAN_INBOX_<EnvPrefix>_IMAP_PASSWORD, falling back to the
// legacy DARBAAN_INBOUND_IMAP_PASSWORD for the implicit default inbox (and for an
// inbox literally named "default" when the per-inbox var is unset).
func inboxIMAPPassword(name string) string {
	if v := os.Getenv("DARBAAN_INBOX_" + inboxcfg.EnvPrefix(name) + "_IMAP_PASSWORD"); v != "" {
		return v
	}
	if name == inbound.DefaultInbox {
		return os.Getenv("DARBAAN_INBOUND_IMAP_PASSWORD")
	}
	return ""
}

// inboxSMTPPassword resolves an inbox's upstream SMTP password (ADR 0012/0023):
// the per-inbox env DARBAAN_INBOX_<EnvPrefix>_SMTP_PASSWORD, falling back to the
// legacy DARBAAN_SMTP_PASSWORD for the implicit default inbox.
func inboxSMTPPassword(name string) string {
	if v := os.Getenv("DARBAAN_INBOX_" + inboxcfg.EnvPrefix(name) + "_SMTP_PASSWORD"); v != "" {
		return v
	}
	if name == inbound.DefaultInbox {
		return os.Getenv("DARBAAN_SMTP_PASSWORD")
	}
	return ""
}

// newSenders builds one upstream Sender per configured inbox (ADR 0023), keyed by
// inbox name, from each inbox's backend coords + per-inbox SMTP secret. An inbox
// with no sender_type uses the stub (default-deny holds, ADR 0003). At N=1 the
// implicit default carries the legacy SMTP flags, so its sender is unchanged.
func (cli *CLI) newSenders(inboxes []inboxcfg.Inbox) (map[string]backend.Sender, error) {
	senders := make(map[string]backend.Sender, len(inboxes))
	for _, in := range inboxes {
		st := in.Backend.SenderType
		if st == "" {
			st = "stub"
		}
		snd, err := backend.New(st, backend.Config{
			Host:     in.Backend.SMTPHost,
			Username: in.Backend.SMTPUsername,
			Password: inboxSMTPPassword(in.Name),
		})
		if err != nil {
			return nil, fmt.Errorf("inbox %q sender: %w", in.Name, err)
		}
		senders[in.Name] = snd
	}
	return senders, nil
}

// newSyncers builds one inbound sync engine per configured inbox that has an
// upstream IMAP backend (ADR 0019/0023), keyed by inbox name; inboxes with no
// backend host are skipped (no sync). The syncers share one sync-state store
// (keyed per inbox internally); the returned stop func closes it. An empty map
// means no inbox syncs (gated off, like the stub sender).
func (cli *CLI) newSyncers(inboxes []inboxcfg.Inbox, store inbound.InboundStore, mailOwner func(inbox string) string) (map[string]*imapsync.Syncer, func(), error) {
	syncers := map[string]*imapsync.Syncer{}
	var state imapsync.StateStore
	stop := func() {
		if state != nil {
			_ = state.Close()
		}
	}
	for _, in := range inboxes {
		if in.Backend.IMAPHost == "" {
			continue // no upstream → no syncer (bounce-only / sync-disabled inbox)
		}
		if state == nil {
			st, err := imapsync.NewStateStore(cli.InboundSyncDB)
			if err != nil {
				return nil, nil, err
			}
			state = st
		}
		maxAge, err := parseMaxAge(in.Backend.MaxAge)
		if err != nil {
			stop()
			return nil, nil, fmt.Errorf("inbox %q max_age: %w", in.Name, err)
		}
		mailbox := in.Backend.IMAPMailbox
		if mailbox == "" {
			mailbox = "INBOX"
		}
		pass := inboxIMAPPassword(in.Name)
		dial := imapsync.Dialer(in.Backend.IMAPHost, in.Backend.IMAPUsername, pass)
		syn := imapsync.New(dial, mailbox, mailOwner(in.Name), in.Name, store, state, maxAge)
		// Per-inbox structured logger (#151): every sync/reconcile record this
		// syncer emits is tagged with its inbox.
		syn.SetLogger(slog.Default().With("inbox", in.Name))
		// Gmail label write-through (ADR 0020 20c): capability-gated, harmless on a
		// non-Gmail backend (reports not-supported → WriteKeywords uses plain keywords).
		syn.SetLabelStore(imapsync.RawGmailLabelStore(in.Backend.IMAPHost, in.Backend.IMAPUsername, pass, mailbox))
		syncers[in.Name] = syn
	}
	return syncers, stop, nil
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

// imapContentFetch is the read face's on-demand content resolver: it dispatches a
// FETCH to the SELECTed inbox's syncer (serves a pending body by fetching that
// inbox's upstream), and falls back to a direct store read for an inbox with no
// syncer (no upstream → no pending records).
func imapContentFetch(syncers map[string]*imapsync.Syncer, store inbound.InboundStore) listener.ContentFetch {
	return func(owner, inbox, id string) (inbound.Message, error) {
		if syn := syncers[inbox]; syn != nil {
			return syn.FetchContent(owner, inbox, id)
		}
		return store.Get(owner, inbox, id)
	}
}

// imapKeywordWriter is the read face's label write-through (ADR 0020): it
// dispatches to the SELECTed inbox's syncer; an inbox with no syncer replicates
// nowhere (local-only labels). nil when no inbox has an upstream.
func imapKeywordWriter(syncers map[string]*imapsync.Syncer) listener.KeywordWriter {
	if len(syncers) == 0 {
		return nil
	}
	return func(owner, inbox, id string, add, remove []string) error {
		if syn := syncers[inbox]; syn != nil {
			return syn.WriteKeywords(owner, inbox, id, add, remove)
		}
		return nil
	}
}

// runSyncLoop polls one inbox's upstream on the configured interval until ctx is
// cancelled. Sync errors are logged, never fatal — a flaky or unreachable
// upstream must not take down serve.
func (cli *CLI) runSyncLoop(ctx context.Context, inbox string, syncer *imapsync.Syncer) {
	slog.Info("inbound sync loop started", "inbox", inbox, "interval", cli.InboundIMAPPollInterval.String())
	t := time.NewTicker(cli.InboundIMAPPollInterval)
	defer t.Stop()
	runSync(ctx, inbox, syncer) // initial pull at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runSync(ctx, inbox, syncer)
		}
	}
}

func runSync(ctx context.Context, inbox string, s *imapsync.Syncer) {
	n, err := s.Sync(ctx)
	if err != nil {
		slog.Error("inbound sync failed", "inbox", inbox, "err", err)
		return
	}
	if n > 0 {
		slog.Info("inbound sync pulled messages", "inbox", inbox, "count", n)
	}
}

// DefaultSyncOnStatusInterval is the on-demand-sync debounce window for an inbox
// that enables sync_on_status without setting one (ADR 0028): the minimum gap
// between STATUS-triggered upstream pulls. A minute is coarse enough that STATUS
// stays cheap under bursty polling, fine enough that "sync now" feels immediate
// after the first call.
const DefaultSyncOnStatusInterval = time.Minute

// newOnDemandSync builds the STATUS-triggered on-demand sync coordinator
// (ADR 0028): it registers each inbox that opted in (sync_on_status) AND has an
// upstream syncer, with its debounce window (sync_on_status_interval, or the
// runtime default). An inbox with no syncer is skipped (nothing to pull). The
// returned coordinator is empty when no inbox opted in — Trigger is then a pure
// no-op — so it is always safe to wire onto the read face.
func newOnDemandSync(inboxes []inboxcfg.Inbox, syncers map[string]*imapsync.Syncer) *imapsync.OnDemandSync {
	od := imapsync.NewOnDemandSync()
	for _, in := range inboxes {
		if !in.SyncOnStatus {
			continue
		}
		syn, ok := syncers[in.Name]
		if !ok {
			slog.Warn("sync_on_status enabled but inbox has no upstream; ignoring", "inbox", in.Name)
			continue
		}
		iv, _ := in.SyncOnStatusDuration() // validated at load; 0 ⇒ default
		if iv <= 0 {
			iv = DefaultSyncOnStatusInterval
		}
		od.Register(in.Name, syn, iv)
	}
	return od
}

// DefaultReconcileInterval is the reconcile-pass period for an inbox that enables
// reconciliation without setting one (ADR 0026). A full UID listing is heavier
// than the incremental forward poll, so the default is deliberately coarse.
const DefaultReconcileInterval = time.Hour

// reconcileTarget is one inbox whose reconciliation is enabled and has an upstream
// syncer — the input to a per-inbox reconcile loop (ADR 0026).
type reconcileTarget struct {
	inbox    string
	syncer   *imapsync.Syncer
	interval time.Duration
	opts     imapsync.ReconcileOptions
}

// reconcileTargets selects the inboxes to run a reconcile loop for: those with
// reconcile_enabled AND an upstream syncer (a bounce-only inbox has none). The
// interval is the inbox's reconcile_interval or DefaultReconcileInterval; the cap
// fraction/floor and the shared audit log ride in the pass options.
func reconcileTargets(inboxes []inboxcfg.Inbox, syncers map[string]*imapsync.Syncer, al audit.AuditLog) []reconcileTarget {
	var targets []reconcileTarget
	for _, in := range inboxes {
		if !in.ReconcileEnabled {
			continue
		}
		syn, ok := syncers[in.Name]
		if !ok {
			continue
		}
		interval, _ := in.ReconcileDuration() // validated at load; 0 ⇒ default
		if interval <= 0 {
			interval = DefaultReconcileInterval
		}
		targets = append(targets, reconcileTarget{
			inbox:    in.Name,
			syncer:   syn,
			interval: interval,
			opts: imapsync.ReconcileOptions{
				Audit:       al,
				CapFraction: in.ReconcileCapFraction,
				CapFloor:    in.ReconcileCapFloor,
			},
		})
	}
	return targets
}

// runReconcileLoop runs one inbox's reconcile pass on its interval until ctx is
// cancelled (ADR 0026). Like the sync loop, errors are logged, never fatal — a
// flaky upstream or a held cap must not take down serve.
func (cli *CLI) runReconcileLoop(ctx context.Context, t reconcileTarget) {
	slog.Info("reconcile loop started", "inbox", t.inbox, "interval", t.interval.String())
	tk := time.NewTicker(t.interval)
	defer tk.Stop()
	runReconcile(ctx, t) // initial pass at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			runReconcile(ctx, t)
		}
	}
}

func runReconcile(ctx context.Context, t reconcileTarget) {
	n, err := t.syncer.Reconcile(ctx, t.opts)
	switch {
	case errors.Is(err, imapsync.ErrReconcileHeld):
		// The syncer logs the "reconcile held" event once on the transition; this
		// per-cycle line stays at debug so a held inbox does not spam the log.
		slog.Debug("reconcile still held", "inbox", t.inbox)
	case err != nil:
		slog.Error("reconcile failed", "inbox", t.inbox, "err", err)
	case n > 0:
		slog.Info("reconcile retracted messages", "inbox", t.inbox, "count", n)
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

// ReconcileCmd groups the reconcile safety-cap controls (ADR 0026), each a thin
// client of the running serve's admin API.
type ReconcileCmd struct {
	Status  ReconcileStatusCmd  `cmd:"" help:"List inboxes whose reconciliation the safety cap has held."`
	Release ReconcileReleaseCmd `cmd:"" help:"Release a held inbox: confirm the large retraction and resume reconciliation."`
}

// ReconcileStatusCmd lists inboxes the reconcile safety cap has suspended.
type ReconcileStatusCmd struct{}

func (*ReconcileStatusCmd) Run(cli *CLI) error {
	client, err := cli.adminClient()
	if err != nil {
		return err
	}
	st, err := client.ReconcileStatus(context.Background())
	if err != nil {
		return err
	}
	held := 0
	for _, s := range st {
		if s.Suspended {
			fmt.Printf("%s\tHELD\t%d candidate(s)\n", s.Inbox, s.HeldCount)
			held++
		}
	}
	if held == 0 {
		fmt.Println("no inboxes are held by the reconcile safety cap")
	}
	return nil
}

// ReconcileReleaseCmd releases a held inbox: the operator confirms the large
// retraction is legitimate, so it completes once and reconciliation resumes.
type ReconcileReleaseCmd struct {
	Inbox string `arg:"" help:"Inbox name to release."`
}

func (c *ReconcileReleaseCmd) Run(cli *CLI) error {
	client, err := cli.adminClient()
	if err != nil {
		return err
	}
	res, err := client.ReleaseReconcile(context.Background(), c.Inbox)
	if err != nil {
		return err
	}
	fmt.Printf("released %s: retracted %d message(s)\n", res.Inbox, res.Purged)
	return nil
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
	tc.SetLogger(slog.Default().With("component", "telegram"))
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
	var tlsConfig *tls.Config
	if cli.ListenerTLSCert != "" || cli.ListenerTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cli.ListenerTLSCert, cli.ListenerTLSKey)
		if err != nil {
			return fmt.Errorf("load TLS keypair: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	// The audit log is opened once and shared: the message store writes verdict
	// entries to it, and the reconcile pass writes a retract entry per retraction
	// (ADR 0026). Closed last (after the stores) so a final commit can still audit.
	al, err := audit.New(cli.AuditType, cli.AuditDB)
	if err != nil {
		return err
	}
	defer func() { _ = al.Close() }()

	q, closeStore, err := cli.openStore(al)
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

	// Resolve the configured inboxes (ADR 0023): a config with no inboxes: is one
	// implicit "default" inbox built from the legacy top-level flags, so a
	// single-inbox deployment is unchanged. Each inbox's filter is compiled up
	// front (fail-fast on a bad rule set).
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

	// Resolve the agent principals (ADR 0027): the `agents:` list, each a login
	// with per-inbox grants and a password from DARBAAN_AGENT_<NAME>_PASSWORD; or,
	// with no `agents:`, a single implicit agent (DARBAAN_AGENT_PASS) granted every
	// inbox — the back-compat single-agent path. The secret is kept in memory only
	// (ADR 0012). Grants are validated here; their enforcement lands in a later
	// increment.
	pw, err := cli.resolvePrincipals(inboxes)
	if err != nil {
		return err
	}
	auth := listener.NewAuth(pw.principals)

	// Multi-agent mode keys synced mail by inbox name (ADR 0027 mail-owner
	// decoupling), so agents sharing an inbox read the same records. Rekey existing
	// synced records once at startup; bounces (UpstreamUID==0) keep their
	// originating-agent owner and are never touched. The rekey is idempotent, so it
	// is safe to run every start.
	if pw.decoupled {
		if n, rerr := inbox.RekeyOwnersToInbox(); rerr != nil {
			return fmt.Errorf("rekey inbound owners: %w", rerr)
		} else if n > 0 {
			slog.Info("rekeyed inbound owners to inbox name (multi-agent)", "count", n)
		}
	}

	// One upstream sender per inbox (ADR 0023): an approved message is delivered
	// via the sender of the inbox it was submitted as. At N=1 this is the legacy
	// sender under the default inbox.
	senders, err := cli.newSenders(inboxes)
	if err != nil {
		return err
	}
	svc.SetSenders(senders)

	// The configured inbox send identities feed the Change-sender picker + the
	// ApproveAs From-rewrite (ADR 0023 slice 5). Only inboxes with an identity.
	identities := make(map[string]string, len(inboxes))
	for _, in := range inboxes {
		if in.Identity != "" {
			identities[in.Name] = in.Identity
		}
	}
	svc.SetInboxIdentities(identities)

	// One local service hosts both agent faces (ADR 0001): SMTP submission
	// (outbound trap) and IMAP read (the agent reads its bounces). The submission
	// face routes each From to an inbox (ADR 0023): matched Identity → that inbox,
	// else the default catch-all, else refused at MAIL FROM.
	// The catch-all target is chosen per-agent by the submission face (ADR 0027):
	// the connecting agent's default_inbox, or the global default at N=1.
	route := func(from, catchAll string) (string, bool) {
		return inboxcfg.Route(inboxes, from, catchAll)
	}
	smtpSrv, err := listener.NewServer(listener.ServerConfig{
		Addr:          cli.ListenerAddr,
		Domain:        cli.ListenerDomain,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, auth, q, route)
	if err != nil {
		return err
	}

	// One inbound syncer per inbox with an upstream (ADR 0019/0023), built before
	// the read face so per-inbox FetchContent serves pending bodies on demand. An
	// empty map = no inbox syncs.
	syncers, stopSync, err := cli.newSyncers(inboxes, inbox, pw.mailOwner)
	if err != nil {
		return err
	}
	defer stopSync()

	// On-demand sync (ADR 0028): STATUS for an opted-in inbox triggers a debounced
	// upstream pull before the counts are computed, so the agent can "sync now"
	// instead of waiting out the background poll interval. Empty (no inbox opted
	// in) ⇒ the trigger is a no-op. It runs the same read-only forward Sync as the
	// background loop, on the connection's goroutine.
	onDemand := newOnDemandSync(inboxes, syncers)
	syncNow := func(inbox string) error {
		_, _, terr := onDemand.Trigger(context.Background(), inbox)
		return terr
	}

	// Wire the reconcile safety-cap controls onto the admin surface (ADR 0026):
	// release a latched inbox (clear + cap-bypassed purge once) and report each
	// inbox's latch. Only when an inbox has an upstream — otherwise the endpoints
	// report unavailable.
	if len(syncers) > 0 {
		svc.SetReconcileControls(
			func(ctx context.Context, name string) (int, error) {
				syn, ok := syncers[name]
				if !ok {
					return 0, fmt.Errorf("inbox %q has no upstream to reconcile", name)
				}
				n, rerr := syn.ReleaseReconcile(ctx, imapsync.ReconcileOptions{Audit: al})
				if errors.Is(rerr, imapsync.ErrReconcileNotHeld) {
					return 0, admin.ErrReconcileNotHeld // → 409 at the API
				}
				return n, rerr
			},
			func() ([]admin.ReconcileStatus, error) {
				out := make([]admin.ReconcileStatus, 0, len(syncers))
				for name, syn := range syncers {
					rs, lerr := syn.ReconcileLatch()
					if lerr != nil {
						return nil, lerr
					}
					out = append(out, admin.ReconcileStatus{Inbox: name, Suspended: rs.Suspended, HeldCount: rs.HeldCount})
				}
				return out, nil
			},
		)
	}
	// The inbound bounce-spoof guard (ADR 0024) runs ahead of the user filter on
	// both faces, verifying with the bounce signer's own key. On by default; an
	// explicit opt-out is logged. on_spoof=hold-for-human routes spoofs to the
	// inbound approval queue instead of hiding them.
	var guard *bounceguard.Guard
	if cli.BounceGuardEnabled {
		guard = bounceguard.New(sgn.Verify)
	} else {
		slog.Warn("bounce-spoof guard disabled", "reason", "bounce-guard-enabled=false")
	}
	holdSpoof := cli.BounceGuardOnSpoof == "hold-for-human"
	// The admin hold-for-human queue and the read face share one filter + mail-owner
	// + guard (ADR 0021/0024/0027): the read face hides held/spoof mail, the admin
	// surface decides it. The held queue is synced mail, keyed by the inbox
	// mail-owner (per-inbox in multi-agent mode).
	svc.SetInboundHolds(filters, pw.mailOwner, guard, holdSpoof)
	imapSrv, err := listener.NewIMAPServer(listener.IMAPServerConfig{
		Addr:          cli.IMAPAddr,
		TLSConfig:     tlsConfig,
		AllowInsecure: cli.ListenerAllowInsecure,
	}, auth, inbox, imapContentFetch(syncers, inbox), imapKeywordWriter(syncers), filters, guard, holdSpoof, pw.mailOwner, syncNow)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run one sync poll loop per inbox with an upstream (shared shutdown ctx;
	// errors logged, never fatal).
	if len(syncers) == 0 {
		slog.Info("inbound sync disabled", "reason", "no inbox has an upstream configured")
	}
	for name, syn := range syncers {
		go cli.runSyncLoop(ctx, name, syn)
	}

	// Per-inbox reconcile loops (ADR 0026): retract local copies of messages that
	// left the source, for inboxes that opted in (reconcile_enabled) and have an
	// upstream. Off by default; the cap latch holds an anomalous mass purge.
	for _, in := range inboxes {
		if in.ReconcileEnabled {
			if _, ok := syncers[in.Name]; !ok {
				slog.Warn("reconcile enabled but inbox has no upstream; not running", "inbox", in.Name)
			}
		}
	}
	for _, rt := range reconcileTargets(inboxes, syncers, al) {
		go cli.runReconcileLoop(ctx, rt)
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

	slog.Info("serve listening", "smtp", cli.ListenerAddr, "imap", cli.IMAPAddr, "admin", cli.AdminAddr)

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
