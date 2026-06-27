package main

// Register the manual (human) approver via blank import. It is always compiled
// in; approver selection is a runtime concern (the approval-strict/-light chains,
// ADR 0017), not a build-time one. The chain is fail-closed: with no approver
// registered for a path, nothing on it can be approved.
import _ "github.com/yaad-index/darbaan/internal/approver/manual"
