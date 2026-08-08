package assessor

import "strings"

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
	// Neutralize any spoofed markers so the payload cannot terminate the fence.
	text = strings.ReplaceAll(text, "[BEGIN UNTRUSTED", "[BEGIN_UNTRUSTED")
	text = strings.ReplaceAll(text, "[END UNTRUSTED", "[END_UNTRUSTED")
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
