// Package bounceguard implements the inbound bounce-spoof guard (ADR 0024):
// detect mail that LOOKS like a delivery-status notification (a bounce) but does
// not carry a valid Darbaan bounce signature, so the read face can hide it ahead
// of the user filter (ADR 0021/0022). It makes ADR 0007's "quarantine external
// mail posing as a bounce" concrete: shape detection is deliberately broad and
// cheap (headers/structure only); the precise gate is the signature check, so a
// genuine Darbaan-issued bounce (ADR 0006) always passes and only unsigned
// bounce-shaped mail is caught.
package bounceguard

import (
	"bytes"
	"net/mail"
	"strings"

	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // register charsets so non-UTF-8 headers parse
)

// Verifier reports whether raw carries a valid Darbaan bounce signature (the
// signer.Verify trust check, ADR 0007). It is injected so this package depends
// only on the function shape, not on the signer.
type Verifier func(raw []byte) (bool, error)

// Guard decides whether a bounce-shaped message is a spoof — bounce-shaped but
// not validly signed by Darbaan.
type Guard struct{ verify Verifier }

// New builds a Guard that uses verify as its trust check.
func New(verify Verifier) *Guard { return &Guard{verify: verify} }

// IsSpoof reports whether raw is a bounce-shaped message lacking a valid Darbaan
// signature — a spoof candidate the read face should hide/hold (ADR 0024).
// Secure by default:
//
//   - not bounce-shaped         → false (ordinary mail; the guard ignores it)
//   - shaped + valid signature  → false (a genuine Darbaan-issued bounce, ADR 0006)
//   - shaped + unsigned/invalid → true
//   - shaped + verify error     → true, with the error (can't confirm ⇒ fail closed)
//
// Shape (cheap, header/structure) is checked first; the signature (which reads
// the body) runs only on a shape hit, so ordinary mail never incurs the verify.
func (g *Guard) IsSpoof(raw []byte) (bool, error) {
	if !Shaped(raw) {
		return false, nil
	}
	ok, err := g.verify(raw)
	if err != nil {
		return true, err // bounce-shaped and we couldn't confirm a valid signature → fail closed
	}
	return !ok, nil
}

// Candidate reports whether any of a message's envelope From local-parts looks
// like a bounce sender (mailer-daemon / postmaster, case-insensitive) — the
// cheap, metadata-only pre-check that bounds the on-demand raw fetch at the lazy
// read face (ADR 0024 v1; ADR 0019 keeps SELECT metadata-only). The null sender
// <> is not in the stored envelope (it is the SMTP reverse-path, not the From
// header), so it is caught only by the full Shaped() check once raw is in hand,
// and by the follow-up shape-flag work — not by this pre-check.
func Candidate(fromLocalParts []string) bool {
	for _, lp := range fromLocalParts {
		switch strings.ToLower(strings.TrimSpace(lp)) {
		case "mailer-daemon", "postmaster":
			return true
		}
	}
	return false
}

// Verdict decides spoof for one message while honoring the lazy read face: the
// full Shaped()+verify needs raw, so it is reached only when raw is cheaply
// available. If rawInHand is non-empty it is checked directly (covers ALL shape
// signals, no fetch). Otherwise, only a From-precheck Candidate triggers getRaw
// (the bounded on-demand fetch) and a full check; a non-candidate passes without
// a fetch. A getRaw failure is fail-OPEN (returns false with the error to log) —
// a transient fetch error must not hide legitimate mail; the signature check
// inside IsSpoof remains fail-closed.
func (g *Guard) Verdict(fromLocalParts []string, rawInHand []byte, getRaw func() ([]byte, error)) (bool, error) {
	if len(rawInHand) > 0 {
		return g.IsSpoof(rawInHand)
	}
	if !Candidate(fromLocalParts) {
		return false, nil
	}
	raw, err := getRaw()
	if err != nil {
		return false, err
	}
	return g.IsSpoof(raw)
}

// Shaped reports whether raw looks like a bounce / DSN — header and structure
// shape only, no signature check (ADR 0024). Deliberately broad: the signature is
// the precise gate, so a false shape-positive only costs a verify on otherwise
// ordinary mail. Unparseable input is treated as not-shaped (the user filter
// still applies).
func Shaped(raw []byte) bool {
	ent, err := gomessage.Read(bytes.NewReader(raw))
	if err != nil || ent == nil {
		return false
	}
	h := ent.Header
	ct, params, _ := h.ContentType()

	// multipart/report; report-type=delivery-status (RFC 6522)
	if ct == "multipart/report" && strings.EqualFold(params["report-type"], "delivery-status") {
		return true
	}
	// a message/delivery-status part anywhere in the structure
	if hasDeliveryStatus(ent) {
		return true
	}
	// null sender (<>) or MAILER-DAEMON / postmaster local-part, on Return-Path or From
	if bounceSender(h.Get("Return-Path")) || bounceSender(h.Get("From")) {
		return true
	}
	// RFC 3834 auto-reply combined with a delivery-status content type
	if strings.Contains(strings.ToLower(h.Get("Auto-Submitted")), "auto-replied") &&
		(ct == "multipart/report" || ct == "message/delivery-status") {
		return true
	}
	return false
}

// hasDeliveryStatus reports whether the entity or any nested part is a
// message/delivery-status (the machine-readable DSN part). It walks the in-memory
// raw — no upstream fetch.
func hasDeliveryStatus(ent *gomessage.Entity) bool {
	mr := ent.MultipartReader()
	if mr == nil {
		ct, _, _ := ent.Header.ContentType()
		return ct == "message/delivery-status"
	}
	for {
		p, err := mr.NextPart()
		if err != nil {
			return false
		}
		if hasDeliveryStatus(p) {
			return true
		}
	}
}

// bounceSender reports whether an address-header value is the null sender (<>,
// RFC 5321's empty reverse-path) or has a MAILER-DAEMON / postmaster local-part,
// case-insensitively — the classic bounce originators.
func bounceSender(headerValue string) bool {
	v := strings.TrimSpace(headerValue)
	switch v {
	case "":
		return false
	case "<>":
		return true
	}
	addr, err := mail.ParseAddress(v)
	if err != nil {
		// Unparseable (e.g. a bare "MAILER-DAEMON"): scan the raw value instead.
		lower := strings.ToLower(v)
		return strings.Contains(lower, "mailer-daemon") || strings.Contains(lower, "postmaster")
	}
	local := addr.Address
	if i := strings.LastIndex(local, "@"); i >= 0 {
		local = local[:i]
	}
	local = strings.ToLower(local)
	return local == "mailer-daemon" || local == "postmaster"
}
