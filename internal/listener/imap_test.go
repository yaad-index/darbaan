package listener_test

import (
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/listener"
	"github.com/yaad-index/darbaan/internal/provenance"
)

func startIMAPServeStamp(t *testing.T, store inbound.InboundStore, ss listener.ServeStamp) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true, ServeStamp: ss},
		listener.SingleAuth("agent", "pw"), store, nil, nil, map[string]*filter.Filter{inbound.DefaultInbox: nil}, nil, false, nil, nil)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func seedInbound(t *testing.T) inbound.InboundStore {
	t.Helper()
	s, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.Add(inbound.Delivery{
		Owner:   "agent",
		From:    "MAILER-DAEMON@darbaan.test",
		To:      "sender@local",
		Subject: "Undelivered Mail Returned to Sender",
		Raw:     []byte("From: MAILER-DAEMON@darbaan.test\r\nSubject: Undelivered Mail\r\n\r\nrefused-marker\r\n"),
	})
	require.NoError(t, err)
	return s
}

func startIMAP(t *testing.T, store inbound.InboundStore) string {
	return startIMAPWithFetch(t, store, nil)
}

func startIMAPWithFetch(t *testing.T, store inbound.InboundStore, fetch listener.ContentFetch) string {
	return startIMAPFull(t, store, fetch, nil, nil)
}

func startIMAPFull(t *testing.T, store inbound.InboundStore, fetch listener.ContentFetch, wk listener.KeywordWriter, flt *filter.Filter) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		listener.SingleAuth("agent", "pw"), store, fetch, wk, map[string]*filter.Filter{inbound.DefaultInbox: flt}, nil, false, nil, nil)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func startIMAPMulti(t *testing.T, store inbound.InboundStore, filters map[string]*filter.Filter) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		listener.SingleAuth("agent", "pw"), store, nil, nil, filters, nil, false, nil, nil)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func startIMAPAuth(t *testing.T, store inbound.InboundStore, filters map[string]*filter.Filter, auth *listener.Auth) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		auth, store, nil, nil, filters, nil, false, nil, nil)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

// ADR 0027 read-scoping: LIST returns only the inboxes the agent has read on, the
// agent's default_inbox is exposed as INBOX, and SELECT/STATUS on an ungranted
// inbox is indistinguishable from a non-existent mailbox (privacy by omission).
func TestIMAPReadScoping(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	// One record in each of three inboxes, all owned by the connecting agent (no
	// owner decoupling in this slice).
	for _, in := range []string{inbound.DefaultInbox, "work", "personal"} {
		_, err = store.Add(inbound.Delivery{Owner: "agent-a", Inbox: in, Subject: in, Raw: []byte("Subject: " + in + "\r\n\r\nx")})
		require.NoError(t, err)
	}

	// agent-a reads work + personal (not the default inbox) and sees work as INBOX.
	auth := listener.NewAuth([]listener.Principal{{
		Name: "agent-a", Password: "pw", DefaultInbox: "work",
		Reads: map[string]bool{"work": true, "personal": true},
		Sends: map[string]bool{"work": true},
	}})
	filters := map[string]*filter.Filter{inbound.DefaultInbox: nil, "work": nil, "personal": nil}
	c, err := imapclient.DialInsecure(startIMAPAuth(t, store, filters, auth), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent-a", "pw").Wait())

	boxes, err := c.List("", "*", nil).Collect()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, b := range boxes {
		names[b.Mailbox] = true
	}
	assert.Equal(t, map[string]bool{"INBOX": true, "personal": true}, names,
		"LIST shows only granted inboxes; work (the default_inbox) is exposed as INBOX")

	// INBOX resolves to the agent's default_inbox (work); the other granted inbox
	// is reachable by name.
	selInbox, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), selInbox.NumMessages)
	_, err = c.Select("personal", nil).Wait()
	require.NoError(t, err)

	// The ungranted default inbox is indistinguishable from non-existent, and the
	// default_inbox is only reachable as INBOX, never by its own name.
	_, err = c.Select("default", nil).Wait()
	require.Error(t, err, "ungranted inbox is no-such-mailbox")
	_, err = c.Select("work", nil).Wait()
	require.Error(t, err, "default_inbox is only reachable as INBOX")
	_, err = c.Status("default", &imap.StatusOptions{NumMessages: true}).Wait()
	require.Error(t, err, "STATUS on an ungranted inbox is no-such-mailbox")
}

// ADR 0023: each configured inbox is a named IMAP mailbox (the default inbox as
// INBOX); SELECT serves that inbox's records, isolated from the others.
func TestIMAPMultiInbox(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, err = store.Add(inbound.Delivery{Owner: "agent", Subject: "d", Raw: []byte("Subject: d\r\n\r\nd")})
	require.NoError(t, err)
	_, err = store.Add(inbound.Delivery{Owner: "agent", Inbox: "work", Subject: "w", Raw: []byte("Subject: w\r\n\r\nw")})
	require.NoError(t, err)

	addr := startIMAPMulti(t, store, map[string]*filter.Filter{inbound.DefaultInbox: nil, "work": nil})
	c, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())

	// LIST advertises the default inbox as INBOX plus the named "work" mailbox.
	boxes, err := c.List("", "*", nil).Collect()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, b := range boxes {
		names[b.Mailbox] = true
	}
	assert.True(t, names["INBOX"], "LIST shows INBOX (default inbox)")
	assert.True(t, names["work"], "LIST shows the work mailbox")

	// Each mailbox serves only its own inbox's records.
	selWork, err := c.Select("work", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), selWork.NumMessages)
	selInbox, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), selInbox.NumMessages)

	// A mailbox that isn't configured does not exist.
	_, err = c.Select("nope", nil).Wait()
	require.Error(t, err)
}

// A body FETCH of a pending (headers-only) record resolves its content on demand
// via the ContentFetch; a flags-only FETCH does not touch the fetcher.
func TestIMAPFetchResolvesPendingOnDemand(t *testing.T) {
	store := seedInbound(t) // present bounce at seq 1
	_, m, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "lazy", UpstreamUID: 5, UIDValidity: 1,
	})
	require.NoError(t, err) // pending record at seq 2

	var fetchCalls int
	fetch := func(owner, inbox, id string) (inbound.Message, error) {
		fetchCalls++
		if id == m.ID { // simulate the on-demand upstream fill
			return store.SetContent(owner, inbound.DefaultInbox, id, []byte("Subject: lazy\r\n\r\nlazy-body"))
		}
		return store.Get(owner, inbound.DefaultInbox, id)
	}

	c, err := imapclient.DialInsecure(startIMAPWithFetch(t, store, fetch), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// Flags-only FETCH: no content needed → fetcher untouched.
	_, err = c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	require.NoError(t, err)
	assert.Equal(t, 0, fetchCalls, "flags-only fetch must not resolve content")

	// BODY[] FETCH of the pending record resolves it on demand.
	msgs, err := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, string(msgs[0].FindBodySection(&imap.FetchItemBodySection{})), "lazy-body")
	assert.GreaterOrEqual(t, fetchCalls, 1)

	got, err := store.Get("agent", inbound.DefaultInbox, m.ID)
	require.NoError(t, err)
	assert.False(t, got.Pending) // cached present after the on-demand fetch
}

// #190: a BODY[] fetch whose content is unresolvable (a stale upstream mapping)
// must NOT hang or error — it serves an empty body and completes, so the client
// proceeds. Critically, one poisoned UID must not stall the rest of the range.
func TestIMAPFetchContentUnavailableServesEmpty(t *testing.T) {
	store := seedInbound(t) // present bounce at seq 1
	_, m, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "gone", UpstreamUID: 7239, UIDValidity: 1,
	})
	require.NoError(t, err) // pending record at seq 2

	fetch := func(owner, inbox, id string) (inbound.Message, error) {
		if id == m.ID {
			return inbound.Message{}, inbound.ErrContentUnavailable // stale mapping
		}
		return store.Get(owner, inbound.DefaultInbox, id)
	}

	c, err := imapclient.DialInsecure(startIMAPWithFetch(t, store, fetch), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// BODY[] of the poisoned record completes cleanly with an empty body — the
	// command returns, it does not hang or error.
	msgs, err := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err, "an unresolvable body completes, it does not error/hang")
	require.Len(t, msgs, 1)
	// A degenerate empty body (at most the section terminator), never the missing
	// content or a hang.
	assert.LessOrEqual(t, len(msgs[0].FindBodySection(&imap.FetchItemBodySection{})), 2, "an empty body is served")

	// The whole range still returns both messages: one poisoned UID at the head
	// does not stall the fetch of everything after it (the outage this fixes).
	all, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	assert.Len(t, all, 2, "one unresolvable UID does not stall the whole fetch")
}

func TestIMAPFetchMarksSeenAndPersists(t *testing.T) {
	store := seedInbound(t)
	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	require.NoError(t, c.Login("agent", "pw").Wait())

	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel.NumMessages)

	// Non-peek BODY[] fetch returns the bounce and marks it \Seen.
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		UID:         true,
		Flags:       true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, string(msgs[0].FindBodySection(&imap.FetchItemBodySection{})), "refused-marker")

	got, err := store.Get("agent", inbound.DefaultInbox, "1")
	require.NoError(t, err)
	assert.True(t, got.Seen) // \Seen persisted across the fetch
}

func TestIMAPStoreUnsetSeenPersists(t *testing.T) {
	store := seedInbound(t)
	require.NoError(t, store.SetSeen("agent", inbound.DefaultInbox, "1", true))

	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	_, err = c.Store(imap.SeqSetNum(1),
		&imap.StoreFlags{Op: imap.StoreFlagsDel, Flags: []imap.Flag{imap.FlagSeen}}, nil).Collect()
	require.NoError(t, err)

	got, err := store.Get("agent", inbound.DefaultInbox, "1")
	require.NoError(t, err)
	assert.False(t, got.Seen) // \Seen cleared and persisted
}

func TestIMAPSameSessionSeenSync(t *testing.T) {
	store := seedInbound(t)
	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// A non-peek body fetch marks \Seen.
	_, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)

	// A later FLAGS-only fetch in the SAME session reflects \Seen (not stale).
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0].Flags, imap.FlagSeen)
}

func TestIMAPEmptyMailboxUIDNext(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "empty.db"))
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())

	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(0), sel.NumMessages)
	assert.Equal(t, imap.UID(1), sel.UIDNext) // UID 0 invalid; empty mailbox → 1
}

func TestIMAPSearch(t *testing.T) {
	store := seedInbound(t) // one unseen message, owner "agent"
	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// SEARCH ALL — previously returned NO [SERVERBUG] (#53).
	all, err := c.Search(&imap.SearchCriteria{}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, all.AllSeqNums())

	// SEARCH UNSEEN matches; SEARCH SEEN does not (message is unseen).
	unseen, err := c.Search(&imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, unseen.AllSeqNums())

	seen, err := c.Search(&imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	require.NoError(t, err)
	assert.Empty(t, seen.AllSeqNums())

	// UID SEARCH ALL returns the message's UID.
	uids, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{1}, uids.AllUIDs())
}

// A record with a stored envelope serves FETCH ENVELOPE + RFC822Size and SUBJECT
// SEARCH from metadata, touching no body; only a body FETCH resolves content.
// (Fully-lazy listing + the #92 SUBJECT-search [SERVERBUG] regression fix, #93.)
func TestIMAPEnvelopeAndHeaderSearchFromMetadata(t *testing.T) {
	// A fresh store holding ONLY an envelope-carrying synced record (seq 1) — so
	// no envelope-less record forces a raw fallback and muddies the fetch count.
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "Quarterly report", UpstreamUID: 5, UIDValidity: 1,
		Size: 4096,
		Envelope: &inbound.Envelope{
			Subject: "Quarterly report",
			From:    []inbound.Address{{Name: "Alice", Mailbox: "alice", Host: "x.test"}},
		},
	})
	require.NoError(t, err)

	var fetchCalls int
	fetch := func(owner, inbox, id string) (inbound.Message, error) {
		fetchCalls++
		return store.Get(owner, inbound.DefaultInbox, id)
	}
	c, err := imapclient.DialInsecure(startIMAPWithFetch(t, store, fetch), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// FETCH ENVELOPE + RFC822Size → served from metadata.
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		UID: true, Envelope: true, RFC822Size: true,
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.NotNil(t, msgs[0].Envelope)
	assert.Equal(t, "Quarterly report", msgs[0].Envelope.Subject)
	assert.Equal(t, int64(4096), msgs[0].RFC822Size)
	assert.Equal(t, 0, fetchCalls, "ENVELOPE/size served from metadata, no body fetch")

	// SUBJECT SEARCH → matches from metadata, no body fetch (was [SERVERBUG]).
	res, err := c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "quarterly"}},
	}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, res.AllSeqNums())
	assert.Equal(t, 0, fetchCalls, "SUBJECT search served from metadata, no body fetch")

	// A body FETCH does resolve content.
	_, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, fetchCalls, 1)
}

// A SUBJECT search over an envelope-less record (legacy/bounce) falls back to the
// raw header block — still works (and the bounce's subject is matchable).
func TestIMAPHeaderSearchFallsBackToRaw(t *testing.T) {
	store := seedInbound(t) // present bounce, no stored envelope, subject "Undelivered..."
	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	res, err := c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "Undelivered"}},
	}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, res.AllSeqNums())
}

// FETCH FLAGS serves a message's custom keywords (ADR 0020), and SELECT
// advertises them in FLAGS/PERMANENTFLAGS.
func TestIMAPFetchServesKeywords(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", UpstreamUID: 1, UIDValidity: 1, Keywords: []string{"useless", "$Important"},
	})
	require.NoError(t, err)

	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Contains(t, sel.Flags, imap.Flag("useless"))

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0].Flags, imap.Flag("useless"))
	assert.Contains(t, msgs[0].Flags, imap.Flag("$Important"))
}

// STORE +FLAGS of a keyword commits locally (canonical) and replicates upstream
// via the writer; on success the record is no longer dirty (ADR 0020).
func TestIMAPStoreKeywordWritesThrough(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, m, err := store.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)

	var wroteID string
	var wroteAdd []string
	wk := func(owner, inbox, id string, add, remove []string) error { wroteID, wroteAdd = id, add; return nil }

	c, err := imapclient.DialInsecure(startIMAPFull(t, store, nil, wk, nil), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	require.NoError(t, c.Store(imap.SeqSetNum(1),
		&imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{"useless"}}, nil).Close())

	got, err := store.Get("agent", inbound.DefaultInbox, m.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"useless"}, got.Keywords) // local store is canonical
	assert.Equal(t, m.ID, wroteID)
	assert.Equal(t, []string{"useless"}, wroteAdd) // replicated the add delta upstream
	dirty, err := store.DirtyKeywords("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Empty(t, dirty) // cleared on successful replicate
}

// If the upstream replicate fails, the keyword still commits locally and the
// record stays dirty for the sync to reconcile — never an error to the agent.
func TestIMAPStoreKeywordWriteFailureStaysDirty(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, m, err := store.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)

	wk := func(owner, inbox, id string, add, remove []string) error { return errors.New("upstream down") }

	c, err := imapclient.DialInsecure(startIMAPFull(t, store, nil, wk, nil), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// The STORE itself succeeds for the agent even though upstream failed.
	require.NoError(t, c.Store(imap.SeqSetNum(1),
		&imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{"useless"}}, nil).Close())

	got, err := store.Get("agent", inbound.DefaultInbox, m.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"useless"}, got.Keywords) // committed locally
	dirty, err := store.DirtyKeywords("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Len(t, dirty, 1) // stays dirty for reconcile
}

// A keyword STORE on a local-only record (a bounce, no UpstreamUID) commits
// locally but does NOT attempt an upstream write or mark the record dirty —
// nothing to replicate (ADR 0020).
func TestIMAPStoreKeywordLocalOnlyNoUpstream(t *testing.T) {
	store := seedInbound(t) // a bounce: Add → no UpstreamUID, seq 1
	called := false
	wk := func(owner, inbox, id string, add, remove []string) error { called = true; return nil }

	c, err := imapclient.DialInsecure(startIMAPFull(t, store, nil, wk, nil), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	require.NoError(t, c.Store(imap.SeqSetNum(1),
		&imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{"useless"}}, nil).Close())

	got, err := store.Get("agent", inbound.DefaultInbox, "1")
	require.NoError(t, err)
	assert.Equal(t, []string{"useless"}, got.Keywords) // local label still set
	assert.False(t, called, "no upstream write for a local-only record")
	dirty, err := store.DirtyKeywords("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Empty(t, dirty) // not dirty → never enters reconcile
}

// A hide rule omits matching messages from the read face (ADR 0021): SELECT
// counts and serves only the allowed ones.
func TestIMAPFilterHidesMessages(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "keep", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "keep"},
	})
	require.NoError(t, err)
	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "junk", UpstreamUID: 2, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "junk"}, Keywords: []string{"useless"},
	})
	require.NoError(t, err)

	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: useless}], action: hide}]"))
	require.NoError(t, err)

	c, err := imapclient.DialInsecure(startIMAPFull(t, store, nil, nil, flt), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel.NumMessages) // the "useless" message is hidden

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Envelope: true}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.NotNil(t, msgs[0].Envelope)
	assert.Equal(t, "keep", msgs[0].Envelope.Subject) // only the allowed one is served
}

// An UNDECIDED assessment hold is invisible to the agent until the operator
// decides; one approval reveals the real message (ADR 0032 Amendment 1). The
// rejected→tombstone case is covered separately.
func TestIMAPAssessmentHold(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "keep", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "keep"},
	})
	require.NoError(t, err)
	_, held, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "danger", UpstreamUID: 2, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "danger"},
	})
	require.NoError(t, err)
	_, err = store.SetContentAssessed("agent", inbound.DefaultInbox, held.ID,
		[]byte("Subject: danger\r\n\r\nx"),
		&inbound.Assessment{Disposition: inbound.AssessmentHeld, Summary: "flagged"})
	require.NoError(t, err)

	addr := startIMAPFull(t, store, nil, nil, nil) // no user filter
	c, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel.NumMessages, "assessment-held message hidden pending a decision")

	_, err = store.SetHoldDecision("agent", inbound.DefaultInbox, held.ID, inbound.HoldApproved)
	require.NoError(t, err)
	c2, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c2.Close() }()
	require.NoError(t, c2.Login("agent", "pw").Wait())
	sel2, err := c2.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(2), sel2.NumMessages, "one approval reveals the held message")
}

// A REJECTED assessment hold is visible but serves a system tombstone — subject,
// body, and size are all system-authored, never the real attacker-controlled
// content (ADR 0032 Amendment 1).
func TestIMAPAssessmentRejectedTombstone(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, held, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "danger", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "danger"},
	})
	require.NoError(t, err)
	_, err = store.SetContentAssessed("agent", inbound.DefaultInbox, held.ID,
		[]byte("Subject: danger\r\n\r\nattacker-body-do-this"),
		&inbound.Assessment{Disposition: inbound.AssessmentHeld, Summary: "flagged"})
	require.NoError(t, err)
	_, err = store.SetHoldDecision("agent", inbound.DefaultInbox, held.ID, inbound.HoldRejected)
	require.NoError(t, err)

	addr := startIMAPFull(t, store, nil, nil, nil)
	c, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel.NumMessages, "a rejected hold is visible as a tombstone")

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Envelope: true, BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "[message reviewed out]", msgs[0].Envelope.Subject, "tombstone subject, not the real one")
	body := string(msgs[0].FindBodySection(&imap.FetchItemBodySection{}))
	assert.Contains(t, body, "reviewed out by the operator", "tombstone body served")
	assert.NotContains(t, body, "attacker-body-do-this", "real content withheld")
}

// A REJECTED tombstone must not leak the withheld message's real metadata through
// SEARCH or FETCH FLAGS: matching Subject/From, size (LARGER/SMALLER), and custom
// keywords all resolve against the system tombstone, never the attacker-controlled
// record — closing the SEARCH/FLAGS oracle (ADR 0032 Amendment 1, C41). The prior
// tests cover the FETCH ENVELOPE/BODY/SIZE tombstone; this covers the match paths.
func TestIMAPAssessmentTombstoneSearchAndFlagsNoLeak(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, held, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "attack-subject", UpstreamUID: 1, UIDValidity: 1,
		Size:     100000, // real size, far larger than the tombstone
		Keywords: []string{"secretlabel"},
		Envelope: &inbound.Envelope{
			Subject: "attack-subject",
			From:    []inbound.Address{{Mailbox: "attacker", Host: "evil.test"}},
		},
	})
	require.NoError(t, err)
	_, err = store.SetContentAssessed("agent", inbound.DefaultInbox, held.ID,
		[]byte("Subject: attack-subject\r\n\r\nattacker-body-do-this"),
		&inbound.Assessment{Disposition: inbound.AssessmentHeld, Summary: "flagged"})
	require.NoError(t, err)
	_, err = store.SetHoldDecision("agent", inbound.DefaultInbox, held.ID, inbound.HoldRejected)
	require.NoError(t, err)

	c, err := imapclient.DialInsecure(startIMAPFull(t, store, nil, nil, nil), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), sel.NumMessages, "a rejected hold is visible as a tombstone")

	search := func(cr *imap.SearchCriteria) []uint32 {
		res, serr := c.Search(cr, nil).Wait()
		require.NoError(t, serr)
		return res.AllSeqNums()
	}

	// SUBJECT/FROM over the REAL values must NOT match — the oracle is closed...
	assert.Empty(t, search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "attack-subject"}},
	}), "real subject not searchable")
	assert.Empty(t, search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: "attacker"}},
	}), "real sender not searchable")
	// ...while the tombstone's own subject IS what's searchable (what's served).
	assert.Equal(t, []uint32{1}, search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "reviewed out"}},
	}), "tombstone subject is what's searchable")

	// LARGER/SMALLER resolve against the small tombstone size, never the real
	// 100000 — so the withheld message's size can't be probed.
	assert.Empty(t, search(&imap.SearchCriteria{Larger: 10000}),
		"real (large) size not probeable via LARGER")
	assert.Equal(t, []uint32{1}, search(&imap.SearchCriteria{Smaller: 10000}),
		"tombstone is small — matches SMALLER, confirming the real size is masked")

	// FETCH FLAGS must not carry the withheld message's real keyword.
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.NotContains(t, msgs[0].Flags, imap.Flag("secretlabel"),
		"real keyword withheld from tombstone FLAGS")
}

// Defense-in-depth (review C43 bypass): if a message is held by assessment but the
// session's SELECT snapshot predates that decision, the serve path must still
// withhold its real body — rawResolver re-checks the freshly-fetched hold state, so
// a stale snapshot can't serve an un-exposed held body on a repeat fetch.
func TestIMAPStaleSnapshotHeldBodyWithheld(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, m, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "ok", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "ok"},
	})
	require.NoError(t, err)
	// Present + CLEARED, so the message is visible at SELECT (not held in the snapshot).
	_, err = store.SetContentAssessed("agent", inbound.DefaultInbox, m.ID,
		[]byte("Subject: ok\r\n\r\nsecret-body"),
		&inbound.Assessment{Disposition: inbound.AssessmentAgentHandled})
	require.NoError(t, err)

	c, err := imapclient.DialInsecure(startIMAPFull(t, store, nil, nil, nil), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), sel.NumMessages, "visible at SELECT — the snapshot predates the hold")

	// The message is re-assessed HELD after SELECT: the session's snapshot is now stale.
	_, err = store.SetContentAssessed("agent", inbound.DefaultInbox, m.ID,
		[]byte("Subject: ok\r\n\r\nsecret-body"),
		&inbound.Assessment{Disposition: inbound.AssessmentHeld, Summary: "flagged"})
	require.NoError(t, err)

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	body := string(msgs[0].FindBodySection(&imap.FetchItemBodySection{}))
	assert.NotContains(t, body, "secret-body", "a held-unapproved body is withheld even from a stale snapshot")
	assert.Empty(t, strings.TrimSpace(body), "served an inert empty body, not the real content")
}

// A message held by BOTH assessment and a filter Hold stays hidden, and the
// single HoldDecision releases it past both sources (the documented model).
func TestIMAPAssessmentAndFilterHold(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, both, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "danger", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "danger"}, Keywords: []string{"review"},
	})
	require.NoError(t, err)
	_, err = store.SetContentAssessed("agent", inbound.DefaultInbox, both.ID,
		[]byte("Subject: danger\r\n\r\nx"),
		&inbound.Assessment{Disposition: inbound.AssessmentHeld, Summary: "flagged"})
	require.NoError(t, err)

	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	addr := startIMAPFull(t, store, nil, nil, flt)

	c, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(0), sel.NumMessages, "held by both → hidden")

	_, err = store.SetHoldDecision("agent", inbound.DefaultInbox, both.ID, inbound.HoldApproved)
	require.NoError(t, err)
	c2, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c2.Close() }()
	require.NoError(t, c2.Login("agent", "pw").Wait())
	sel2, err := c2.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel2.NumMessages, "one approval releases it past both hold sources")
}

// A hold-for-human message is hidden until approved, then becomes visible (ADR
// 0021): undecided → hidden; HoldApproved → served.
func TestIMAPHoldForHuman(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "keep", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "keep"},
	})
	require.NoError(t, err)
	_, held, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "review-me", UpstreamUID: 2, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "review-me"}, Keywords: []string{"review"},
	})
	require.NoError(t, err)

	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	addr := startIMAPFull(t, store, nil, nil, flt)

	c, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())

	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel.NumMessages) // held one hidden pending decision

	// A human approves exposure → it becomes visible on the next select.
	_, err = store.SetHoldDecision("agent", inbound.DefaultInbox, held.ID, inbound.HoldApproved)
	require.NoError(t, err)
	c2, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c2.Close() }()
	require.NoError(t, c2.Login("agent", "pw").Wait())
	sel, err = c2.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(2), sel.NumMessages) // now exposed
}

// UIDNEXT is derived from the full store, so hiding the highest-UID message does
// not under-report it (ADR 0021).
func TestIMAPUIDNextFromFullStore(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	_, _, err = store.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1}) // id 1, visible
	require.NoError(t, err)
	_, _, err = store.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 2, UIDValidity: 1, Keywords: []string{"junk"}}) // id 2, hidden
	require.NoError(t, err)

	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: junk}], action: hide}]"))
	require.NoError(t, err)

	c, err := imapclient.DialInsecure(startIMAPFull(t, store, nil, nil, flt), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel.NumMessages) // only id 1 visible
	assert.Equal(t, imap.UID(3), sel.UIDNext)   // but UIDNEXT reflects hidden id 2
}

func TestIMAPBadAuthRejected(t *testing.T) {
	c, err := imapclient.DialInsecure(startIMAP(t, seedInbound(t)), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.Error(t, c.Login("agent", "wrong").Wait())
}

func TestIMAPRequiresTLS(t *testing.T) {
	_, err := listener.NewIMAPServer(listener.IMAPServerConfig{},
		listener.SingleAuth("agent", "pw"), seedInbound(t), nil, nil, nil, nil, false, nil, nil)
	require.Error(t, err)
}

func startIMAPDecoupled(t *testing.T, store inbound.InboundStore, filters map[string]*filter.Filter, auth *listener.Auth, mailOwner func(string) string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		auth, store, nil, nil, filters, nil, false, mailOwner, nil)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

// ADR 0027 bounce privacy on a shared inbox: two agents share inbox "work". Its
// synced mail is owned by the inbox and visible to both; each agent's own bounce
// is owned by the agent and visible ONLY to that agent — a co-reader never sees
// it. This is the two-key-space read union.
func TestIMAPBouncePrivacyOnSharedInbox(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	// Shared synced mail owned by the inbox name (post-decoupling).
	_, _, err = store.AddSynced(inbound.Delivery{Owner: "work", Inbox: "work", UpstreamUID: 1, UIDValidity: 1, Raw: []byte("Subject: synced-w\r\n\r\nx")})
	require.NoError(t, err)
	// Each agent's private bounce (locally-generated, owned by the agent).
	_, err = store.Add(inbound.Delivery{Owner: "agent-a", Inbox: "work", Raw: []byte("Subject: bounce-a\r\n\r\nx")})
	require.NoError(t, err)
	_, err = store.Add(inbound.Delivery{Owner: "agent-b", Inbox: "work", Raw: []byte("Subject: bounce-b\r\n\r\nx")})
	require.NoError(t, err)

	principal := func(name string) listener.Principal {
		return listener.Principal{Name: name, Password: "pw", DefaultInbox: "work",
			Reads: map[string]bool{"work": true}, Sends: map[string]bool{"work": true}}
	}
	auth := listener.NewAuth([]listener.Principal{principal("agent-a"), principal("agent-b")})
	filters := map[string]*filter.Filter{"work": nil}
	mailOwner := func(inbox string) string { return inbox } // agents mode: owner = inbox name
	addr := startIMAPDecoupled(t, store, filters, auth, mailOwner)

	subjects := func(agent string) map[string]bool {
		c, err := imapclient.DialInsecure(addr, nil)
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		require.NoError(t, c.Login(agent, "pw").Wait())
		sel, err := c.Select("INBOX", nil).Wait()
		require.NoError(t, err)
		got := map[string]bool{}
		if sel.NumMessages == 0 {
			return got
		}
		seqs := make([]uint32, sel.NumMessages)
		for i := range seqs {
			seqs[i] = uint32(i) + 1
		}
		msgs, err := c.Fetch(imap.SeqSetNum(seqs...), &imap.FetchOptions{Envelope: true}).Collect()
		require.NoError(t, err)
		for _, m := range msgs {
			got[m.Envelope.Subject] = true
		}
		return got
	}

	assert.Equal(t, map[string]bool{"synced-w": true, "bounce-a": true}, subjects("agent-a"),
		"agent-a sees shared synced mail + its own bounce, never agent-b's")
	assert.Equal(t, map[string]bool{"synced-w": true, "bounce-b": true}, subjects("agent-b"),
		"agent-b sees shared synced mail + its own bounce, never agent-a's")
}

// The serve-path backstop (ADR 0030 slice 5) re-runs the sanitize+stamp on the
// raw before serving, keyed on the session's selected inbox — so a blob stored
// with one trust value serves with the CURRENT config's value (freshness /
// legacy gap), with exactly one trust header (idempotent, not stacked).
func TestIMAPServeStampReStampsFresh(t *testing.T) {
	store := seedInbound(t) // present bounce at seq 1, stored trust=unknown (default resolver)

	// Serve-path resolves TRUSTED for the inbox: it must override the stored value.
	ss := func(_ string, raw []byte, risk, riskFactors string) ([]byte, error) {
		return provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustTrusted, Risk: risk, RiskFactors: riskFactors})
	}

	c, err := imapclient.DialInsecure(startIMAPServeStamp(t, store, ss), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)

	body := string(msgs[0].FindBodySection(&imap.FetchItemBodySection{}))
	assert.Contains(t, body, "X-Darbaan-Trust: trusted", "serve-path stamps the current config value")
	assert.NotContains(t, body, "X-Darbaan-Trust: unknown", "stored value overridden on serve")
	assert.Equal(t, 1, strings.Count(body, "X-Darbaan-Trust:"), "exactly one trust header, not stacked")
	assert.Contains(t, body, "refused-marker", "body preserved")
}

// C23: a below-threshold (agent-handled) message is served with the agent-facing
// risk advisory (ADR 0032 §6) as system-authored X-Darbaan-* headers, stamped in
// the same sanitize pass so an inbound look-alike is stripped before the real
// value lands.
func TestIMAPServeStampAdvisoryHeaders(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, m, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "hello", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{Subject: "hello"},
	})
	require.NoError(t, err)
	// The raw carries an attacker-planted advisory header that must not survive.
	_, err = store.SetContentAssessed("agent", inbound.DefaultInbox, m.ID,
		[]byte("Subject: hello\r\nX-Darbaan-Risk: high; score=99\r\n\r\nbody-keep"),
		&inbound.Assessment{
			Disposition: inbound.AssessmentAgentHandled,
			Band:        "low", Score: 12,
			Factors: []string{"secrets_request"},
		})
	require.NoError(t, err)

	// Serve-path stamp mirrors production: the trust verdict and the advisory are
	// stamped together, after the namespace strip.
	ss := func(_ string, raw []byte, risk, riskFactors string) ([]byte, error) {
		return provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustUnknown, Risk: risk, RiskFactors: riskFactors})
	}

	c, err := imapclient.DialInsecure(startIMAPServeStamp(t, store, ss), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)

	body := string(msgs[0].FindBodySection(&imap.FetchItemBodySection{}))
	assert.Contains(t, body, "X-Darbaan-Risk: low; score=12", "advisory band+score is stamped from the assessment")
	assert.Contains(t, body, "X-Darbaan-Risk-Factors: secrets_request", "advisory factors are stamped")
	assert.NotContains(t, body, "score=99", "inbound advisory look-alike is stripped before the system value lands")
	assert.Equal(t, 1, strings.Count(body, "X-Darbaan-Risk:"), "exactly one advisory header, not stacked")
	assert.Contains(t, body, "body-keep", "body preserved")
}
