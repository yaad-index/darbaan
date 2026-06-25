// Command darbaan is the Darbaan mail-gate proxy CLI.
//
// Subcommands:
//
//	darbaan serve                       run the SMTP submission face + sluice
//	darbaan queue ls                    list held outbound messages
//	darbaan queue show <id>             dump a held message's raw RFC 822
//	darbaan queue approve <id>          approve a held message (runs the chain)
//	darbaan queue reject -reason "" <id>  reject a held message
//	darbaan version                     print version
//
// See the adr/ directory for the design.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/listener"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// version is the build version, overridden at link time via -ldflags.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "queue":
		err = runQueue(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println("darbaan", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "darbaan:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: darbaan <serve|queue|version> [flags]")
	fmt.Fprintln(os.Stderr, "  serve            run the SMTP submission face + sluice")
	fmt.Fprintln(os.Stderr, "  queue ls         list held outbound messages")
	fmt.Fprintln(os.Stderr, "  queue show <id>  dump a held message's raw RFC 822")
	fmt.Fprintln(os.Stderr, "  queue approve <id>            approve a held message")
	fmt.Fprintln(os.Stderr, "  queue reject -reason \"\" <id>   reject a held message")
	fmt.Fprintln(os.Stderr, "  version          print version")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":1465", "SMTP submission listen address")
	domain := fs.String("domain", "localhost", "SMTP greeting domain")
	dbPath := fs.String("db", "darbaan.db", "path to the sluice database file")
	tlsCert := fs.String("tls-cert", "", "path to the TLS certificate (PEM)")
	tlsKey := fs.String("tls-key", "", "path to the TLS private key (PEM)")
	allowInsecure := fs.Bool("allow-insecure", false, "allow AUTH over plaintext (local testing only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// v1: the single agent credential is supplied at startup via the
	// environment and kept in memory only. Full at-rest encryption (age) lands
	// with the deployment/secrets component (ADR 0012).
	cred := listener.Credential{
		Username: os.Getenv("DARBAAN_AGENT_USER"),
		Password: os.Getenv("DARBAAN_AGENT_PASS"),
	}
	if cred.Username == "" || cred.Password == "" {
		return errors.New("set DARBAAN_AGENT_USER and DARBAAN_AGENT_PASS")
	}

	var tlsConfig *tls.Config
	if *tlsCert != "" || *tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return fmt.Errorf("load TLS keypair: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	q, err := sluice.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = q.Close() }()

	srv, err := listener.NewServer(listener.ServerConfig{
		Addr:          *addr,
		Domain:        *domain,
		TLSConfig:     tlsConfig,
		AllowInsecure: *allowInsecure,
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

	fmt.Fprintf(os.Stderr, "darbaan: SMTP submission face on %s (db %s)\n", *addr, *dbPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func runQueue(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: darbaan queue <ls|show|approve|reject> [flags] [id]")
	}
	sub := args[0]

	// Flags precede the positional id, e.g. `queue reject -reason "no" <id>`.
	fs := flag.NewFlagSet("queue "+sub, flag.ExitOnError)
	dbPath := fs.String("db", "darbaan.db", "path to the sluice database file")
	var reason string
	var retryable bool
	if sub == "reject" {
		fs.StringVar(&reason, "reason", "", "rejection reason (required)")
		fs.BoolVar(&retryable, "retryable", false, "mark the rejection transient (revise & resubmit) rather than permanent")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	id := fs.Arg(0)

	q, err := sluice.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = q.Close() }()

	switch sub {
	case "ls":
		return queueList(q)
	case "show":
		if id == "" {
			return errors.New("usage: darbaan queue show <id>")
		}
		return queueShow(q, id)
	case "approve":
		if id == "" {
			return errors.New("usage: darbaan queue approve <id>")
		}
		return runApprove(q, id)
	case "reject":
		if id == "" || reason == "" {
			return errors.New(`usage: darbaan queue reject -reason "..." <id>`)
		}
		return runReject(q, id, reason, retryable)
	default:
		return fmt.Errorf("unknown queue subcommand %q", sub)
	}
}

// defaultStrictChain and defaultLightChain are the v1 approval chains. Both
// resolve to the manual approver until a pre-screener and more approvers land;
// these become operator-configurable later. If a named approver is not compiled
// in, the chain fails closed (nothing can be approved).
var (
	defaultStrictChain = []string{"manual"}
	defaultLightChain  = []string{"manual"}
)

func runApprove(q *sluice.Sluice, id string) error {
	m, err := decideAndApply(context.Background(), q, backend.StubSender{},
		policy.NewRouter(defaultStrictChain, defaultLightChain),
		id, approver.Verdict{Disposition: approver.Approve})
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

func runReject(q *sluice.Sluice, id, reason string, retryable bool) error {
	m, err := decideAndApply(context.Background(), q, backend.StubSender{},
		policy.NewRouter(defaultStrictChain, defaultLightChain),
		id, approver.Verdict{Disposition: approver.Reject, Reason: reason, Retryable: retryable})
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
func decideAndApply(ctx context.Context, q *sluice.Sluice, sender backend.Sender, router *policy.Router, id string, human approver.Verdict) (sluice.Message, error) {
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
		// Attempt the (stubbed) upstream send; record the result either way.
		approved, _ := q.Get(id)
		sendErr := sender.Send(ctx, approved)
		return q.RecordSendAttempt(id, sendErr)
	case approver.Reject:
		return q.Reject(id, outcome.DecidedBy, outcome.Reason, outcome.Retryable)
	default: // Hold — stays pending, fail-closed
		return msg, nil
	}
}

func queueList(q *sluice.Sluice) error {
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
			m.ID, m.Status, m.Agent, m.From, len(m.Rcpt), m.Size,
			m.ReceivedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

func queueShow(q *sluice.Sluice, id string) error {
	msg, err := q.Get(id)
	if err != nil {
		return err
	}
	// Raw message/rfc822 to stdout so a human (or the future hold-for-human
	// approval flow) can read exactly what is held.
	_, err = os.Stdout.Write(msg.Raw)
	return err
}
