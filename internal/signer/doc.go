// Package signer issues and signs Darbaan's bounces so an agent trusts only a
// rejection Darbaan itself produced. Signing is DKIM over a dedicated selector;
// Darbaan holds the private signing key and each agent holds only the pinned
// public key (ADR 0006, 0007).
package signer
