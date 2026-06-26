package listener

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"

	"github.com/yaad-index/darbaan/internal/inbound"
)

// imapMailbox is the only mailbox the v1 read face exposes.
const imapMailbox = "INBOX"

// errReadOnly is returned for every mutating IMAP operation: the v1 face serves
// Darbaan-generated bounces read-only (ADR 0006), it is not a managed mailbox.
var errReadOnly = errors.New("imap: read-only mailbox (serves Darbaan-generated messages only)")

// IMAPServerConfig configures the IMAP read face.
type IMAPServerConfig struct {
	Addr          string
	TLSConfig     *tls.Config // enables STARTTLS; required unless AllowInsecure
	AllowInsecure bool        // permit AUTH over plaintext — local/testing only
}

// IMAPServer serves the agent's mailbox (the InboundStore) over IMAP as a
// translation adapter (ADR 0016): the store is canonical, there is no upstream
// IMAP proxy and no upstream fetch in v1.
type IMAPServer struct {
	imap *imapserver.Server
}

// NewIMAPServer wires the IMAP read face. TLS is required unless AllowInsecure
// is set (local/testing), mirroring the SMTP face.
func NewIMAPServer(cfg IMAPServerConfig, cred Credential, store inbound.InboundStore) (*IMAPServer, error) {
	if cfg.TLSConfig == nil && !cfg.AllowInsecure {
		return nil, errors.New("listener: IMAP TLS required (set TLSConfig, or AllowInsecure for local testing)")
	}
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &imapSession{cred: cred, store: store}, nil, nil
		},
		TLSConfig:    cfg.TLSConfig,
		InsecureAuth: cfg.AllowInsecure,
	})
	return &IMAPServer{imap: srv}, nil
}

// ListenAndServe binds addr and serves until Close is called.
func (s *IMAPServer) ListenAndServe(addr string) error { return s.imap.ListenAndServe(addr) }

// Serve serves on an already-open listener (used by tests).
func (s *IMAPServer) Serve(l net.Listener) error { return s.imap.Serve(l) }

// Close stops the server.
func (s *IMAPServer) Close() error { return s.imap.Close() }

// imapSession is one IMAP connection, hard-scoped after Login to the
// authenticated agent (owner). Every store access is owner-keyed, so a session
// can only ever see the agent's own messages.
type imapSession struct {
	cred     Credential
	store    inbound.InboundStore
	owner    string
	authed   bool
	selected []inbound.Message // snapshot taken at Select
}

func (s *imapSession) Close() error { return nil }

func (s *imapSession) Login(username, password string) error {
	if !constEqual(username, s.cred.Username) || !constEqual(password, s.cred.Password) {
		return imapserver.ErrAuthFailed
	}
	s.owner = username
	s.authed = true
	return nil
}

func (s *imapSession) Select(mailbox string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	if mailbox != imapMailbox {
		return nil, fmt.Errorf("imap: no such mailbox %q", mailbox)
	}
	msgs, err := s.store.List(s.owner)
	if err != nil {
		return nil, err
	}
	s.selected = msgs

	firstUnseen, uidNext := uint32(0), uint32(1) // UID 0 is invalid (RFC 3501)
	for i, m := range msgs {
		uid := uint32(uidOf(m))
		if uid >= uidNext {
			uidNext = uid + 1
		}
		if !m.Seen && firstUnseen == 0 {
			firstUnseen = uint32(i) + 1
		}
	}
	return &imap.SelectData{
		Flags:             []imap.Flag{imap.FlagSeen},
		PermanentFlags:    []imap.Flag{imap.FlagSeen},
		NumMessages:       uint32(len(msgs)),
		FirstUnseenSeqNum: firstUnseen,
		UIDNext:           imap.UID(uidNext),
		UIDValidity:       1,
	}, nil
}

func (s *imapSession) Unselect() error {
	s.selected = nil
	return nil
}

func (s *imapSession) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if mailbox != imapMailbox {
		return nil, fmt.Errorf("imap: no such mailbox %q", mailbox)
	}
	msgs, err := s.store.List(s.owner)
	if err != nil {
		return nil, err
	}
	data := &imap.StatusData{Mailbox: mailbox}
	if options.NumMessages {
		n := uint32(len(msgs))
		data.NumMessages = &n
	}
	if options.NumUnseen {
		var unseen uint32
		for _, m := range msgs {
			if !m.Seen {
				unseen++
			}
		}
		data.NumUnseen = &unseen
	}
	uidNext := uint32(1) // UID 0 is invalid (RFC 3501)
	for _, m := range msgs {
		if u := uint32(uidOf(m)); u >= uidNext {
			uidNext = u + 1
		}
	}
	if options.UIDNext {
		data.UIDNext = imap.UID(uidNext)
	}
	if options.UIDValidity {
		data.UIDValidity = 1
	}
	return data, nil
}

func (s *imapSession) List(w *imapserver.ListWriter, _ string, patterns []string, _ *imap.ListOptions) error {
	if len(patterns) == 0 {
		return nil // LIST "" "" is a delimiter query; nothing to enumerate
	}
	return w.WriteList(&imap.ListData{
		Mailbox: imapMailbox,
		Delim:   '/',
	})
}

func (s *imapSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	markSeen := false
	for _, bs := range options.BodySection {
		if !bs.Peek {
			markSeen = true
			break
		}
	}

	var ferr error
	s.forEach(numSet, func(seqNum uint32, m *inbound.Message) {
		if ferr != nil {
			return
		}
		if markSeen && !m.Seen {
			if err := s.store.SetSeen(s.owner, m.ID, true); err != nil {
				ferr = err
				return
			}
			m.Seen = true // also updates s.selected via the pointer
		}
		ferr = fetchMessage(w.CreateMessage(seqNum), *m, options)
	})
	return ferr
}

func (s *imapSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	seen, touchesSeen := seenFromStoreFlags(flags)

	var serr error
	s.forEach(numSet, func(seqNum uint32, m *inbound.Message) {
		if serr != nil {
			return
		}
		if touchesSeen && m.Seen != seen {
			if err := s.store.SetSeen(s.owner, m.ID, seen); err != nil {
				serr = err
				return
			}
			m.Seen = seen // also updates s.selected via the pointer
		}
		if flags.Silent {
			return
		}
		rw := w.CreateMessage(seqNum)
		rw.WriteUID(uidOf(*m))
		rw.WriteFlags(flagList(*m))
		if err := rw.Close(); err != nil {
			serr = err
		}
	})
	return serr
}

// forEach calls fn for each selected message matching numSet, computing its
// sequence number (position) and resolving UID vs sequence membership. fn
// receives a pointer into s.selected, so flag updates it makes are reflected in
// later in-session reads (e.g. a FLAGS query after a body fetch).
func (s *imapSession) forEach(numSet imap.NumSet, fn func(seqNum uint32, m *inbound.Message)) {
	for i := range s.selected {
		m := &s.selected[i]
		seqNum := uint32(i) + 1
		var match bool
		switch set := numSet.(type) {
		case imap.SeqSet:
			match = set.Contains(seqNum)
		case imap.UIDSet:
			match = set.Contains(uidOf(*m))
		}
		if match {
			fn(seqNum, m)
		}
	}
}

// The mutating operations are unsupported: the v1 face is a read-only view of
// Darbaan-generated messages.
func (s *imapSession) Create(string, *imap.CreateOptions) error              { return errReadOnly }
func (s *imapSession) Delete(string) error                                   { return errReadOnly }
func (s *imapSession) Rename(string, string, *imap.RenameOptions) error      { return errReadOnly }
func (s *imapSession) Subscribe(string) error                                { return errReadOnly }
func (s *imapSession) Unsubscribe(string) error                              { return errReadOnly }
func (s *imapSession) Expunge(*imapserver.ExpungeWriter, *imap.UIDSet) error { return errReadOnly }
func (s *imapSession) Copy(imap.NumSet, string) (*imap.CopyData, error)      { return nil, errReadOnly }

func (s *imapSession) Append(string, imap.LiteralReader, *imap.AppendOptions) (*imap.AppendData, error) {
	return nil, errReadOnly
}

func (s *imapSession) Search(imapserver.NumKind, *imap.SearchCriteria, *imap.SearchOptions) (*imap.SearchData, error) {
	return nil, errors.New("imap: SEARCH not supported in v1 (FETCH 1:* instead)")
}

// No mailbox changes happen out-of-band, so polling and idling are no-ops.
func (s *imapSession) Poll(*imapserver.UpdateWriter, bool) error { return nil }

func (s *imapSession) Idle(_ *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

func fetchMessage(w *imapserver.FetchResponseWriter, m inbound.Message, options *imap.FetchOptions) error {
	w.WriteUID(uidOf(m))
	if options.Flags {
		w.WriteFlags(flagList(m))
	}
	if options.InternalDate {
		w.WriteInternalDate(m.ReceivedAt)
	}
	if options.RFC822Size {
		w.WriteRFC822Size(int64(len(m.Raw)))
	}
	if options.Envelope {
		if h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(m.Raw))); err == nil {
			w.WriteEnvelope(imapserver.ExtractEnvelope(h))
		}
	}
	if options.BodyStructure != nil {
		w.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(m.Raw)))
	}
	for _, bs := range options.BodySection {
		buf := imapserver.ExtractBodySection(bytes.NewReader(m.Raw), bs)
		wc := w.WriteBodySection(bs, int64(len(buf)))
		_, writeErr := wc.Write(buf)
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return w.Close()
}

func flagList(m inbound.Message) []imap.Flag {
	if m.Seen {
		return []imap.Flag{imap.FlagSeen}
	}
	return []imap.Flag{}
}

func seenFromStoreFlags(sf *imap.StoreFlags) (seen, touches bool) {
	hasSeen := false
	for _, f := range sf.Flags {
		if f == imap.FlagSeen {
			hasSeen = true
		}
	}
	switch sf.Op {
	case imap.StoreFlagsAdd:
		return true, hasSeen
	case imap.StoreFlagsDel:
		return false, hasSeen
	case imap.StoreFlagsSet:
		// SET replaces all flags, so \Seen's presence is the target value.
		return hasSeen, true
	}
	return false, false
}

func uidOf(m inbound.Message) imap.UID {
	n, _ := strconv.ParseUint(m.ID, 10, 32)
	return imap.UID(n)
}
