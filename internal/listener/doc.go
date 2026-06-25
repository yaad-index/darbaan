// Package listener hosts Darbaan's IMAP (read) and SMTP (submission) faces: the
// protocol endpoints agents connect to. Agents authenticate here with per-agent
// Darbaan credentials over TLS and never reach the upstream mailbox directly
// (ADR 0001, 0002).
package listener
