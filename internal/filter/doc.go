// Package filter applies the inbound rules: declarative YAML matched top-down,
// first match wins, with actions hide | allow | hold-for-human. A per-inbox
// default_visibility (visible|hidden, ADR 0022) fixes the no-match default and
// what a bare (action-less) rule does — a match flips visibility — so the common
// allowlist/denylist inbox is a one-liner; an explicit action always wins and
// hold-for-human is never implied. It controls read-time noise and attack
// surface; it does not stop an injection from an allowed sender — the outbound
// sluice does (ADR 0008).
package filter
