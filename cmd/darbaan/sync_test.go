package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Inbound sync is off by default: with no upstream host, startInboundSync is a
// no-op (no state store opened, no goroutine) and never errors.
func TestInboundSyncDisabledByDefault(t *testing.T) {
	cli := &CLI{} // InboundIMAPHost == ""
	stop, err := cli.startInboundSync(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, stop)
	stop() // no-op, must not panic
}
