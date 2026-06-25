// Package policy holds Darbaan's permission and routing decisions: the risk
// router that picks which approval chain a queued message takes (light vs
// strict, defaulting to strict when no pre-screener is compiled in) and the
// mechanical policy an agent cannot argue away (ADR 0002, 0005).
package policy
