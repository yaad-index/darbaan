package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Inbound sync is off by default: with no upstream host, newSyncer returns a nil
// syncer (no state store opened) and a no-op stop, and never errors. A nil
// syncer makes imapContentFetch nil too (the read face reads straight from the
// store).
func TestInboundSyncDisabledByDefault(t *testing.T) {
	cli := &CLI{} // InboundIMAPHost == ""
	syncer, stop, err := cli.newSyncer(nil)
	require.NoError(t, err)
	require.Nil(t, syncer)
	require.NotNil(t, stop)
	require.Nil(t, imapContentFetch(syncer))
	stop() // no-op, must not panic
}
