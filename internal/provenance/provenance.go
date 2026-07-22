// Package provenance sanitizes darbaan's reserved X-Darbaan-* trust/provenance
// header namespace on inbound mail. This slice implements the ADR 0030 Layer-1
// floor (the unconditional strip); later slices add trust stamping on top.
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

var namespaceLower = strings.ToLower(Namespace)

// Strip removes every X-Darbaan-* header from a raw RFC 822 message —
// regardless of value, count, or position — and returns the message with its
// body preserved byte-for-byte (only the header block is re-serialized, the
// same mechanism as the send-path From rewrite). This is the ADR 0030 Layer-1
// anti-spoof floor: because the whole namespace is deleted unconditionally, a
// sender cannot smuggle in e.g. `X-Darbaan-Trust: trusted`.
//
// The content-write chokepoint feeds Strip both untrusted upstream mail (always
// well-formed RFC 822) and darbaan's own locally-generated blobs (bounces, etc.),
// some of which are not full messages. So a blob whose header block does not
// parse is passed through unchanged — it has no RFC 822 header block a compliant
// consumer would read a trust header from — UNLESS its header region actually
// contains a namespace line, in which case Strip errors and (by the caller's
// contract) the blob is not persisted, rather than risk a lenient consumer
// reading a smuggled look-alike.
func Strip(raw []byte) ([]byte, error) {
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
