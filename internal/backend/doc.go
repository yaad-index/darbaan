// Package backend is the pluggable upstream-connectivity layer. Backends
// advertise capabilities so features check support before use; v1 targets a
// generic IMAP/SMTP baseline and a Gmail provider. Non-safety rules degrade to
// a no-op on a missing capability, while safety rules fail closed (ADR 0009).
package backend
