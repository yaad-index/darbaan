// Command darbaan is the Darbaan mail-gate proxy CLI.
//
// Subcommands:
//
//	darbaan serve            run the SMTP submission face + sluice
//	darbaan queue ls         list held (pending) outbound messages
//	darbaan queue show <id>  dump a held message's raw RFC 822
//	darbaan version          print version
//
// See the adr/ directory for the design.
package main

import (
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

	"github.com/yaad-index/darbaan/internal/listener"
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
	fmt.Fprintln(os.Stderr, "  queue ls         list held (pending) outbound messages")
	fmt.Fprintln(os.Stderr, "  queue show <id>  dump a held message's raw RFC 822")
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
	fs := flag.NewFlagSet("queue", flag.ExitOnError)
	dbPath := fs.String("db", "darbaan.db", "path to the sluice database file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: darbaan queue <ls|show <id>> [-db path]")
	}

	q, err := sluice.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = q.Close() }()

	switch rest[0] {
	case "ls":
		return queueList(q)
	case "show":
		if len(rest) < 2 {
			return errors.New("usage: darbaan queue show <id>")
		}
		return queueShow(q, rest[1])
	default:
		return fmt.Errorf("unknown queue subcommand %q", rest[0])
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
