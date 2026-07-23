// Package provenance owns darbaan's reserved X-Darbaan-* trust/provenance header
// namespace on inbound mail (ADR 0030): it strips any inbound namespace header
// (the Layer-1 anti-spoof floor) and stamps darbaan's own X-Darbaan-Trust.
package provenance

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message/textproto"
)

// Namespace is the header-name prefix darbaan reserves for its own
// trust/provenance headers. Every inbound header whose name begins with it (in
// any case) is under darbaan's exclusive control and is stripped before darbaan
// stamps its own, so a sender can never pre-forge one (ADR 0030).
const Namespace = "X-Darbaan-"

// TrustHeader carries the gate's trust verdict for a message; TrustTrusted /
// TrustUntrusted / TrustUnknown are its only values. The value is computed from
// the authenticated source, never from message content (ADR 0030).
const (
	TrustHeader    = "X-Darbaan-Trust"
	TrustTrusted   = "trusted"
	TrustUntrusted = "untrusted"
	TrustUnknown   = "unknown"
)

var namespaceLower = strings.ToLower(Namespace)

// Strip removes every X-Darbaan-* header from a raw RFC 822 message without
// stamping anything — the pure Layer-1 floor. See rewrite for the parse-failure
// contract.
func Strip(raw []byte) ([]byte, error) { return rewrite(raw, "") }

// Sanitize is the atomic strip-then-stamp the content-write chokepoint uses: it
// removes the whole X-Darbaan-* namespace and then stamps a single
// X-Darbaan-Trust: <trust> in one header-block rewrite, so a caller can never
// persist a blob that is un-stripped OR un-stamped. trust must be one of the
// Trust* values; it is computed from the authenticated source by the caller and
// is never derived from the message. See rewrite for the parse-failure contract.
func Sanitize(raw []byte, trust string) ([]byte, error) { return rewrite(raw, trust) }

// rewrite deletes the namespace and, when trust != "", stamps X-Darbaan-Trust,
// re-serializing only the header block (body preserved byte-for-byte, the same
// mechanism as the send-path From rewrite).
//
// The chokepoint feeds this both untrusted upstream mail (always well-formed
// RFC 822) and darbaan's own locally-generated blobs (bounces), some of which
// are not full messages. So a blob whose header block does not parse is passed
// through unchanged — it has no RFC 822 header block a compliant consumer reads
// a trust header from — UNLESS its header region already contains a namespace
// line, in which case rewrite errors and (by the caller's contract) the blob is
// not persisted, rather than risk a lenient consumer reading a smuggled
// look-alike.
func rewrite(raw []byte, trust string) ([]byte, error) {
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
	if trust != "" {
		hdr.Set(TrustHeader, trust)
	}
	var buf bytes.Buffer
	if err := textproto.WriteHeader(&buf, hdr); err != nil {
		return nil, err
	}
	if _, err := io.Copy(&buf, br); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
