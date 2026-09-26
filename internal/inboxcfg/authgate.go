package inboxcfg

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/emersion/go-message/textproto"
	"github.com/emersion/go-msgauth/authres"
)

// authenticated reports whether the upstream's own Authentication-Results for raw
// show the From domain authenticated (ADR 0031 slice 2, as amended 2026-09-26):
//
//   - Only fields whose authserv-id equals authservID are read, and only the top
//     run of them: from the topmost such field down to the next Received field.
//     The upstream prepends its results above everything the message carried
//     when it arrived, so its own field is the topmost one with its identity, and
//     the first Received below it was already in the message: the sender's hop.
//     Anything from there down is the sender's and is ignored. Received fields
//     above the topmost match are the upstream's own later hops and do not end
//     the run.
//   - A field in the run passes on dmarc=pass for fromDomain. Only when it
//     carries no DMARC result for fromDomain does it fall back to an aligned
//     dkim=pass, whose header.d equals fromDomain; a dkim=pass for another domain
//     never counts.
//   - Every field in the run must pass: if they disagree, the gate fails closed
//     rather than trusting the more favourable reading. So a field the sender
//     placed directly under the upstream's can refuse trust but never grant it.
//     An Authentication-Results field that cannot be parsed fails the gate too,
//     since it could be the upstream's.
//
// Its strength rests on the upstream adding its own field and stripping forged
// fields that claim its identity (RFC 8601 section 5); the gate assumes both and
// cannot check them.
func authenticated(raw []byte, authservID, fromDomain string) bool {
	if authservID == "" || fromDomain == "" {
		return false
	}
	hdr, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return false
	}
	counted := 0
	for fields := hdr.Fields(); fields.Next(); {
		switch strings.ToLower(fields.Key()) {
		case "received":
			if counted > 0 {
				return true // the run ended at the sender's hop, every field passing
			}
		case "authentication-results":
			id, results, err := authres.Parse(fields.Value())
			if err != nil {
				return false
			}
			if !strings.EqualFold(strings.TrimSpace(id), authservID) {
				continue
			}
			counted++
			if !domainPasses(results, fromDomain) {
				return false
			}
		}
	}
	return counted > 0
}

// domainPasses reports whether results show domain authenticated: its DMARC
// result when there is one for domain, otherwise a DKIM pass whose signing domain
// is domain.
func domainPasses(results []authres.Result, domain string) bool {
	dmarcSeen, dkimPass := false, false
	for _, r := range results {
		switch v := r.(type) {
		case *authres.DMARCResult:
			if strings.EqualFold(v.From, domain) {
				if v.Value != authres.ResultPass {
					return false
				}
				dmarcSeen = true
			}
		case *authres.DKIMResult:
			if v.Value == authres.ResultPass && strings.EqualFold(v.Domain, domain) {
				dkimPass = true
			}
		}
	}
	return dmarcSeen || dkimPass
}
