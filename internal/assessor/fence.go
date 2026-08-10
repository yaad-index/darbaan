package assessor

import (
	"regexp"
	"strings"
)

// fenceMarker matches a fence begin/end marker in any case, so a mixed-case
// spoof ("[End Untrusted email body]") is neutralized just like the exact-case
// form (C44). ${1} is brace-delimited so the group ref is not read as the
// identifier "1_UNTRUSTED".
var fenceMarker = regexp.MustCompile(`(?i)\[(BEGIN|END) UNTRUSTED`)

// Fence wraps untrusted text so it crosses the boundary to the privileged agent
// as clearly-delimited, inert data — never as instructions (the ADR 0006
// principle: attacker text is never echoed as trusted). Any attempt to spoof the
// fence markers inside the payload is neutralized, so the content cannot break
// out of the fence and be read as a command.
//
// The assessor's own machine-consumed output (the factor list and summary) never
// contains attacker text, so it needs no fencing. Fence is for the separate case
// where raw content must accompany a held message for a human to read — that
// content is fenced, marked as quoted data, and kept out of any machine-consumed
// path.
func Fence(label, text string) string {
	label = sanitizeLabel(label)
	begin := "[BEGIN UNTRUSTED " + label + "]"
	end := "[END UNTRUSTED " + label + "]"
	// Neutralize any spoofed markers — in any case — so the payload cannot visually
	// terminate the fence for a human (or an LLM summarizing the alert) reading it.
	text = fenceMarker.ReplaceAllString(text, "[${1}_UNTRUSTED")
	return begin + "\n" + text + "\n" + end
}

// sanitizeLabel keeps the (trusted, caller-supplied) label from carrying line
// breaks or bracket characters that would disturb the fence framing.
func sanitizeLabel(label string) string {
	label = strings.NewReplacer("\n", " ", "\r", " ", "[", "(", "]", ")").Replace(label)
	label = strings.TrimSpace(label)
	if label == "" {
		return "content"
	}
	return label
}
