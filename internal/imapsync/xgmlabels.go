package imapsync

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrNotXGM means the upstream did not advertise X-GM-EXT-1 (not Gmail), so the
// caller should fall back to plain IMAP keywords.
var ErrNotXGM = errors.New("imapsync: backend does not support X-GM-LABELS")

// LabelStoreFunc replicates a label change to a Gmail backend via X-GM-LABELS, by
// the message's upstream UID. It returns ErrNotXGM when the backend isn't Gmail
// (the caller then falls back to plain keywords). add/remove are label names.
type LabelStoreFunc func(uid, uidValidity uint32, add, remove []string) error

// RawGmailLabelStore builds a LabelStoreFunc that applies +/-X-GM-LABELS over a
// dedicated raw IMAP session (ADR 0020 20c). go-imap/v2 has no X-GM-LABELS
// support and no extension hook, so this speaks the few needed commands directly
// — it is the narrow label-write exception to read-only upstream, reusing the
// app password. Write-only: it never reads/parses X-GM-LABELS. Capability-gated
// (X-GM-EXT-1); on any other backend it reports ErrNotXGM and the caller uses
// plain keywords. Issue #103 tracks swapping this for upstream go-imap support
// when it lands.
func RawGmailLabelStore(addr, username, password, mailbox string) LabelStoreFunc {
	host := addr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host = addr[:i]
	}
	dial := func() (net.Conn, error) { return tls.Dial("tcp", addr, &tls.Config{ServerName: host}) }
	return newLabelStore(dial, username, password, mailbox)
}

// newLabelStore is the dialer-injected core of RawGmailLabelStore (production
// uses a TLS dialer; tests inject a plaintext one).
func newLabelStore(dial func() (net.Conn, error), username, password, mailbox string) LabelStoreFunc {
	return func(uid, _ uint32, add, remove []string) error {
		if len(add) == 0 && len(remove) == 0 {
			return nil
		}
		rc, err := dialRaw(dial)
		if err != nil {
			return err
		}
		defer rc.close()

		if err := rc.do("a1", fmt.Sprintf("LOGIN %s %s", imapQuote(username), imapQuote(password))); err != nil {
			return err
		}
		caps, err := rc.collect("a2", "CAPABILITY")
		if err != nil {
			return err
		}
		if !hasCap(caps, "X-GM-EXT-1") {
			return ErrNotXGM
		}
		if err := rc.do("a3", fmt.Sprintf("SELECT %s", imapQuote(mailbox))); err != nil {
			return err
		}
		if len(add) > 0 {
			if err := rc.do("a4", fmt.Sprintf("UID STORE %d +X-GM-LABELS (%s)", uid, labelList(add))); err != nil {
				return err
			}
		}
		if len(remove) > 0 {
			if err := rc.do("a5", fmt.Sprintf("UID STORE %d -X-GM-LABELS (%s)", uid, labelList(remove))); err != nil {
				return err
			}
		}
		_ = rc.do("a6", "LOGOUT")
		return nil
	}
}

// rawConn is a minimal IMAP client: just enough to log in, select, and issue a
// fixed handful of commands, reading each tagged response. It deliberately does
// not parse untagged data beyond capability scanning.
type rawConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialRaw(dial func() (net.Conn, error)) (*rawConn, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("imapsync: xgm dial: %w", err)
	}
	rc := &rawConn{conn: conn, r: bufio.NewReader(conn)}
	if _, err := rc.r.ReadString('\n'); err != nil { // server greeting
		_ = conn.Close()
		return nil, fmt.Errorf("imapsync: xgm greeting: %w", err)
	}
	return rc, nil
}

func (rc *rawConn) close() { _ = rc.conn.Close() }

// do sends a tagged command and waits for its tagged completion, discarding
// untagged data. A non-OK completion is an error.
func (rc *rawConn) do(tag, cmd string) error {
	_, err := rc.collect(tag, cmd)
	return err
}

// collect sends a tagged command and returns the untagged response lines up to
// the tagged completion (used to read CAPABILITY).
func (rc *rawConn) collect(tag, cmd string) ([]string, error) {
	if _, err := fmt.Fprintf(rc.conn, "%s %s\r\n", tag, cmd); err != nil {
		return nil, fmt.Errorf("imapsync: xgm write: %w", err)
	}
	var untagged []string
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("imapsync: xgm read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if rest, ok := strings.CutPrefix(line, tag+" "); ok {
			if strings.HasPrefix(rest, "OK") {
				return untagged, nil
			}
			return nil, fmt.Errorf("imapsync: xgm %q: %s", firstWord(cmd), rest)
		}
		untagged = append(untagged, line)
	}
}

func hasCap(lines []string, want string) bool {
	for _, l := range lines {
		for _, tok := range strings.Fields(l) {
			if strings.EqualFold(tok, want) {
				return true
			}
		}
	}
	return false
}

// labelList renders label names as a space-separated, individually-quoted list
// for an X-GM-LABELS parenthesized argument.
func labelList(labels []string) string {
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = imapQuote(l)
	}
	return strings.Join(parts, " ")
}

// imapQuote renders an IMAP quoted-string (RFC 3501), escaping " and \.
func imapQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}
