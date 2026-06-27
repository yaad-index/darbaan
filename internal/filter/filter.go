package filter

import (
	"regexp"
	"strings"
	"time"

	"github.com/yaad-index/darbaan/internal/inbound"
)

// Action is a rule outcome (ADR 0008/0021).
type Action string

const (
	Allow Action = "allow"
	Hide  Action = "hide"
	Hold  Action = "hold-for-human"
)

// Match fields and operators (ADR 0021). v1 matches metadata only — never the
// body. `header` is restricted to envelope headers (the stored set).
const (
	fieldFrom    = "from"
	fieldTo      = "to"
	fieldCc      = "cc"
	fieldSubject = "subject"
	fieldHeader  = "header"
	fieldLabel   = "label"
	fieldAge     = "age"

	opEquals    = "equals"
	opContains  = "contains"
	opRegex     = "regex"
	opDomain    = "domain"
	opOlderThan = "older_than" // age fields only
	opNewerThan = "newer_than" // age fields only
)

// envelopeHeaders are the only headers matchable in v1 (the stored envelope set);
// an arbitrary header would require the body, which v1 excludes.
var envelopeHeaders = map[string]bool{
	"from": true, "to": true, "cc": true, "subject": true,
	"date": true, "message-id": true, "reply-to": true,
}

// Filter is a compiled, ordered rule set evaluated top-down, first-match-wins,
// with a configurable default action on no match. It is evaluated fresh per serve
// (no caching of rule-derived verdicts), so an edited rule set takes effect on
// the next serve after a restart.
type Filter struct {
	rules []rule
	def   Action
}

type rule struct {
	conds  []cond
	action Action
}

type cond struct {
	field  string
	header string // lower-cased header name when field == header
	op     string
	value  string         // lower-cased for string ops
	re     *regexp.Regexp // compiled when op == regex
	dur    time.Duration  // parsed when field == age
}

// Decide returns the action for a message: the first matching rule's action, or
// the default. now is injected so callers (and tests) control the age clock.
func (f *Filter) Decide(m inbound.Message, now time.Time) Action {
	if f == nil {
		return Allow
	}
	for _, r := range f.rules {
		if r.matches(m, now) {
			return r.action
		}
	}
	return f.def
}

// Default returns the no-match action.
func (f *Filter) Default() Action {
	if f == nil {
		return Allow
	}
	return f.def
}

func (r rule) matches(m inbound.Message, now time.Time) bool {
	for _, c := range r.conds { // conditions are AND-ed
		if !c.matches(m, now) {
			return false
		}
	}
	return true
}

func (c cond) matches(m inbound.Message, now time.Time) bool {
	if c.field == fieldAge {
		age := now.Sub(m.ReceivedAt)
		if c.op == opOlderThan {
			return age > c.dur
		}
		return age < c.dur // opNewerThan
	}
	for _, v := range fieldValues(m, c.field, c.header) {
		if c.opMatch(v) {
			return true // any candidate value matches (e.g. one of several recipients)
		}
	}
	return false
}

func (c cond) opMatch(v string) bool {
	switch c.op {
	case opEquals:
		return strings.EqualFold(v, c.value)
	case opContains:
		return strings.Contains(strings.ToLower(v), c.value)
	case opRegex:
		return c.re.MatchString(v)
	case opDomain:
		return strings.EqualFold(domainOf(v), c.value)
	}
	return false
}

// fieldValues returns the candidate match strings for a field. Address fields
// yield mailbox@host strings (from the stored envelope when present, else the
// formatted header string); header fields resolve to their envelope value.
func fieldValues(m inbound.Message, field, header string) []string {
	switch field {
	case fieldFrom:
		return addrValues(m.Envelope, envFrom, m.From)
	case fieldTo:
		return addrValues(m.Envelope, envTo, m.To)
	case fieldCc:
		return addrValues(m.Envelope, envCc, "")
	case fieldSubject:
		return []string{m.Subject}
	case fieldLabel:
		return m.Keywords
	case fieldHeader:
		return headerValues(m, header)
	}
	return nil
}

type envSel int

const (
	envFrom envSel = iota
	envTo
	envCc
)

// addrValues yields "mailbox@host" strings for an address field, preferring the
// stored structured envelope; for records with no envelope (e.g. bounces) it
// falls back to the formatted header string.
func addrValues(e *inbound.Envelope, sel envSel, fallback string) []string {
	if e != nil {
		var as []inbound.Address
		switch sel {
		case envFrom:
			as = e.From
		case envTo:
			as = e.To
		case envCc:
			as = e.Cc
		}
		if len(as) > 0 {
			out := make([]string, 0, len(as))
			for _, a := range as {
				out = append(out, a.Mailbox+"@"+a.Host)
			}
			return out
		}
	}
	if fallback != "" {
		return []string{fallback}
	}
	return nil
}

func headerValues(m inbound.Message, header string) []string {
	switch header {
	case "from":
		return addrValues(m.Envelope, envFrom, m.From)
	case "to":
		return addrValues(m.Envelope, envTo, m.To)
	case "cc":
		return addrValues(m.Envelope, envCc, "")
	case "subject":
		return []string{m.Subject}
	}
	if m.Envelope == nil {
		return nil
	}
	switch header {
	case "date":
		if m.Envelope.Date.IsZero() {
			return nil
		}
		return []string{m.Envelope.Date.Format(time.RFC1123Z)}
	case "message-id":
		return []string{m.Envelope.MessageID}
	case "reply-to":
		out := make([]string, 0, len(m.Envelope.ReplyTo))
		for _, a := range m.Envelope.ReplyTo {
			out = append(out, a.Mailbox+"@"+a.Host)
		}
		return out
	}
	return nil
}

// domainOf extracts the domain from an address ("mailbox@host" or "Name <a@b>").
func domainOf(addr string) string {
	addr = strings.TrimSuffix(addr, ">")
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}
