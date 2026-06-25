// Package filter applies the inbound rules: declarative YAML matched top-down,
// first match wins, with actions hide | allow | hold-for-human and a
// configurable no-match default. It controls read-time noise and attack
// surface; it does not stop an injection from an allowed sender — the outbound
// sluice does (ADR 0008).
package filter
