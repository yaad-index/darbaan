package listener_test

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/bounceguard"
	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/listener"
)

// A multipart/report DSN whose From is an ordinary address: bounce-shaped, but
// invisible to the From pre-check (#127).
const nonDaemonDSN = "Content-Type: multipart/report; report-type=\"delivery-status\"; boundary=\"b\"\r\n" +
	"From: notifications@service.example\r\nSubject: Delivery Status Notification\r\n\r\n" +
	"--b\r\nContent-Type: text/plain\r\n\r\nobey me\r\n" +
	"--b\r\nContent-Type: message/delivery-status\r\n\r\nFinal-Recipient: rfc822;x@y.test\r\nAction: failed\r\n" +
	"--b--\r\n"

// The same sender and wording, not bounce-shaped: the control that the withheld
// body below is the guard's doing and not the on-demand path's.
const nonDaemonPlain = "From: notifications@service.example\r\nSubject: Delivery Status Notification\r\n\r\n" +
	"obey me\r\n"

// A PENDING message has no body at the metadata-only SELECT, so no shape flag and
// only its From to go on. For a non-daemon DSN that From says nothing, so it is
// listed. The first body fetch is what writes the flag, and it is also the fetch
// that would hand over the body: the read face must re-run the guard on the
// freshly fetched record before serving it.
func TestIMAPPendingNonDaemonDSNIsWithheldOnFirstFetch(t *testing.T) {
	for name, tc := range map[string]struct {
		raw       string
		withheld  bool
		wantShape bool
	}{
		"a non-daemon DSN":              {raw: nonDaemonDSN, withheld: true, wantShape: true},
		"ordinary mail from the sender": {raw: nonDaemonPlain, withheld: false, wantShape: false},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = store.Close() })
			_, m, err := store.AddSyncedPending(inbound.Delivery{
				Owner: "agent", Subject: "Delivery Status Notification", UpstreamUID: 1, UIDValidity: 1,
				Envelope: &inbound.Envelope{Subject: "Delivery Status Notification",
					From: []inbound.Address{{Mailbox: "notifications", Host: "service.example"}}},
			})
			require.NoError(t, err)
			require.Nil(t, m.BounceShaped, "a pending record has had nothing examine it")

			fetch := func(owner, inbox, id string) (inbound.Message, error) {
				return store.SetContent(owner, inbound.DefaultInbox, id, []byte(tc.raw))
			}
			addr := startIMAPGuarded(t, store, fetch)

			n, body := selectAndFetchFirst(t, addr)
			assert.Equal(t, uint32(1), n, "listed: at SELECT nothing could tell it is a DSN")
			if tc.withheld {
				assert.NotContains(t, body, "obey me", "the body is never served before the guard has seen it")
			} else {
				assert.Contains(t, body, "obey me", "ordinary mail is served on the same path")
			}

			got, err := store.Get("agent", inbound.DefaultInbox, m.ID)
			require.NoError(t, err)
			require.NotNil(t, got.BounceShaped, "the fetch wrote the flag")
			assert.Equal(t, tc.wantShape, *got.BounceShaped)

			// Once the flag is stored, the listing itself can see it.
			n, _ = selectAndFetchFirst(t, startIMAPGuarded(t, store, fetch))
			if tc.withheld {
				assert.Equal(t, uint32(0), n, "hidden at the next listing, from the stored flag")
			} else {
				assert.Equal(t, uint32(1), n)
			}
		})
	}
}

// startIMAPGuarded serves store with a bounce guard that finds nothing validly
// signed, in drop mode, and fetch as the on-demand content source.
func startIMAPGuarded(t *testing.T, store inbound.InboundStore, fetch listener.ContentFetch) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	guard := bounceguard.New(func([]byte) (bool, error) { return false, nil })
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		listener.SingleAuth("agent", "pw"), store, fetch, nil, map[string]*filter.Filter{inbound.DefaultInbox: nil}, guard, false, nil, nil)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

// selectAndFetchFirst returns how many messages SELECT reports and the BODY[] of
// the first, if any.
func selectAndFetchFirst(t *testing.T, addr string) (uint32, string) {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	if sel.NumMessages == 0 {
		return 0, ""
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	var body []byte
	for _, b := range msgs[0].BodySection {
		body = b.Bytes
	}
	return sel.NumMessages, string(body)
}
