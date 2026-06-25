//go:build !no_manual_approver

package main

// Compile in the manual (human) approver by registering it via blank import
// (ADR 0004). Build with -tags no_manual_approver to exclude it; with no
// approver compiled in, the approval chain fails closed and nothing can be
// approved.
import _ "github.com/yaad-index/darbaan/internal/approver/manual"
