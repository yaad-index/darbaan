package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/inboxcfg"
)

func TestNewSyncersPerInbox(t *testing.T) {
	cli := &CLI{InboundSyncDB: filepath.Join(t.TempDir(), "sync.db"), AgentUsername: "agent"}
	inboxes := []inboxcfg.Inbox{
		{Name: "work", Backend: inboxcfg.Backend{IMAPHost: "imap.a.example:993"}},
		{Name: "personal", Backend: inboxcfg.Backend{IMAPHost: "imap.b.example:993"}},
		{Name: "local-only"}, // no upstream host → skipped (no syncer)
	}
	syncers, stop, err := cli.newSyncers(inboxes, nil, func(inbox string) string { return inbox }, nil)
	require.NoError(t, err)
	defer stop()
	require.Len(t, syncers, 2)
	require.NotNil(t, syncers["work"])
	require.NotNil(t, syncers["personal"])
	require.Nil(t, syncers["local-only"])
}

func TestInboxIMAPPassword(t *testing.T) {
	t.Setenv("DARBAAN_INBOX_WORK_IMAP_PASSWORD", "wpass")
	t.Setenv("DARBAAN_INBOUND_IMAP_PASSWORD", "legacy")
	assert.Equal(t, "wpass", inboxIMAPPassword("work"))                // per-inbox env
	assert.Equal(t, "legacy", inboxIMAPPassword(inbound.DefaultInbox)) // default → legacy fallback
	assert.Empty(t, inboxIMAPPassword("nopass"))                       // non-default, no env → empty
}

func TestInboxSMTPPassword(t *testing.T) {
	t.Setenv("DARBAAN_INBOX_WORK_SMTP_PASSWORD", "wpass")
	t.Setenv("DARBAAN_SMTP_PASSWORD", "legacy")
	assert.Equal(t, "wpass", inboxSMTPPassword("work"))                // per-inbox env
	assert.Equal(t, "legacy", inboxSMTPPassword(inbound.DefaultInbox)) // default → legacy fallback
	assert.Empty(t, inboxSMTPPassword("nopass"))                       // non-default, no env → empty
}

func TestNewSendersPerInbox(t *testing.T) {
	cli := &CLI{}
	inboxes := []inboxcfg.Inbox{
		{Name: inbound.DefaultInbox, Backend: inboxcfg.Backend{SenderType: "stub"}},
		{Name: "work", Backend: inboxcfg.Backend{SenderType: "stub"}},
		{Name: "no-type"}, // no sender_type → stub (default-deny)
	}
	senders, err := cli.newSenders(inboxes)
	require.NoError(t, err)
	require.Len(t, senders, 3)
	require.NotNil(t, senders["work"])
	require.NotNil(t, senders[inbound.DefaultInbox])
	require.NotNil(t, senders["no-type"])
}

// Inbound sync is off by default: with no inbox carrying an upstream host,
// newSyncers returns an empty map (no state store opened) and a no-op stop, and
// never errors. An empty map makes imapKeywordWriter nil (local-only labels);
// imapContentFetch still returns a resolver that reads straight from the store.
func TestInboundSyncDisabledByDefault(t *testing.T) {
	cli := &CLI{}
	inboxes := []inboxcfg.Inbox{{Name: inbound.DefaultInbox}} // no backend host → no syncer
	syncers, stop, err := cli.newSyncers(inboxes, nil, func(inbox string) string { return inbox }, nil)
	require.NoError(t, err)
	require.Empty(t, syncers)
	require.NotNil(t, stop)
	require.Nil(t, imapKeywordWriter(syncers))
	stop() // no-op, must not panic
}
