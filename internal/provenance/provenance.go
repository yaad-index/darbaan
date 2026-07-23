// Package provenance owns darbaan's reserved X-Darbaan-* trust/provenance header
// namespace on inbound mail (ADR 0030): it strips any inbound namespace header
// (the Layer-1 anti-spoof floor) and stamps darbaan's own X-Darbaan-Trust.
package provenance

import (
	"bufio"
	"bytes"
	"io"
	"net/mail"
	"strings"

	"github.com/emersion/go-message/textproto"
)

// From extracts the sender address from a raw message's From header, normalized
// to a lower-cased RFC 5321 address (e.g. "alice@example.com"), or "" when there
// is no parseable From. Per-sender trust rules match on this (ADR 0031). It is
// read from the message, so it is only meaningful under the upstream-
// authentication boundary the README states; the trust asymmetry keeps that safe
// (a From only ever raises trust to `trusted` on an authenticated upstream).
func From(raw []byte) string {
	hdr, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return ""
	}
	addr, err := mail.ParseAddress(hdr.Get("From"))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr.Address))
}

// Namespace is the header-name prefix darbaan reserves for its own
// trust/provenance headers. Every inbound header whose name begins with it (in
// any case) is under darbaan's exclusive control and is stripped before darbaan
// stamps its own, so a sender can never pre-forge one (ADR 0030).
const Namespace = "X-Darbaan-"

// TrustHeader carries the gate's trust verdict; NoteHeader carries an optional
// operator directive. Both values are computed from the authenticated source,
// never from message content (ADR 0030). TrustTrusted / TrustUntrusted /
// TrustUnknown are the only trust values.
const (
	TrustHeader    = "X-Darbaan-Trust"
	NoteHeader     = "X-Darbaan-Note"
	TrustTrusted   = "trusted"
	TrustUntrusted = "untrusted"
	TrustUnknown   = "unknown"
)

var namespaceLower = strings.ToLower(Namespace)

// Stamp is the provenance darbaan writes onto a message (ADR 0030): the trust
// verdict and an optional operator note, both resolved from the authenticated
// source by the caller, never from the message. An empty field leaves its header
// unset.
type Stamp struct {
	Trust  string // one of the Trust* values; "" leaves X-Darbaan-Trust unset
	Note   string // optional directive; "" leaves X-Darbaan-Note unset
	Banner bool   // also emit a fenced top-of-body banner (top-level text/plain only)
}

// Strip removes every X-Darbaan-* header from a raw RFC 822 message without
// stamping anything — the pure Layer-1 floor. See rewrite for the parse-failure
// contract.
func Strip(raw []byte) ([]byte, error) { return rewrite(raw, Stamp{}) }

// Sanitize is the atomic strip-then-stamp the content-write chokepoint uses: it
// removes the whole X-Darbaan-* namespace and then stamps darbaan's own trust
// (and note, if any) in one header-block rewrite, so a caller can never persist
// a blob that is un-stripped OR carrying a forged namespace header. See rewrite
// for the parse-failure contract.
func Sanitize(raw []byte, s Stamp) ([]byte, error) { return rewrite(raw, s) }

// rewrite deletes the namespace and stamps X-Darbaan-Trust / X-Darbaan-Note for
// the non-empty fields of s, re-serializing only the header block (body
// preserved byte-for-byte, the same mechanism as the send-path From rewrite).
// The note is header-sanitized at stamp time so a value can never inject a
// second header (one X-Darbaan-Note max via Set).
//
// The chokepoint feeds this both untrusted upstream mail (always well-formed
// RFC 822) and darbaan's own locally-generated blobs (bounces), some of which
// are not full messages. So a blob whose header block does not parse is passed
// through unchanged — it has no RFC 822 header block a compliant consumer reads
// a trust header from — UNLESS its header region already contains a namespace
// line, in which case rewrite errors and (by the caller's contract) the blob is
// not persisted, rather than risk a lenient consumer reading a smuggled
// look-alike.
func rewrite(raw []byte, s Stamp) ([]byte, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	hdr, err := textproto.ReadHeader(br)
	if err != nil {
		if hasNamespaceHeaderLine(raw) {
			return nil, err
		}
		return raw, nil
	}
	for fields := hdr.Fields(); fields.Next(); {
		if strings.HasPrefix(strings.ToLower(fields.Key()), namespaceLower) {
			fields.Del()
		}
	}
	if s.Trust != "" {
		hdr.Set(TrustHeader, s.Trust)
	}
	if s.Note != "" {
		hdr.Set(NoteHeader, headerSafe(s.Note))
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	if s.Banner {
		// Best-effort, never errors the message: only a top-level text/plain body is
		// bannered; any other shape keeps just the (authoritative) headers.
		body = maybeBanner(hdr, body, s)
	}
	var buf bytes.Buffer
	if err := textproto.WriteHeader(&buf, hdr); err != nil {
		return nil, err
	}
	buf.Write(body)
	return buf.Bytes(), nil
}

// headerSafe drops CR, LF, and other control characters from a header value so a
// templated note can never inject a second header (ADR 0030) — belt-and-
// suspenders over the config-load validation that already rejects them.
func headerSafe(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// hasNamespaceHeaderLine reports whether raw's header region (up to the first
// blank line) begins any X-Darbaan-* field. It is a byte-level scan used only on
// the parse-failure path, to tell an inert non-message blob (pass through) from
// one smuggling a namespace look-alike (refuse). Folded continuation lines are
// skipped; a blank line ends the header region.
func hasNamespaceHeaderLine(raw []byte) bool {
	for len(raw) > 0 {
		var line []byte
		if nl := bytes.IndexByte(raw, '\n'); nl < 0 {
			line, raw = raw, nil
		} else {
			line, raw = raw[:nl], raw[nl+1:]
		}
		line = bytes.TrimRight(line, "\r")
		switch {
		case len(line) == 0:
			return false // header/body boundary
		case line[0] == ' ' || line[0] == '\t':
			continue // folded continuation
		case len(line) >= len(Namespace) && strings.EqualFold(string(line[:len(Namespace)]), Namespace):
			return true
		}
	}
	return false
}
