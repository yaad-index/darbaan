package inboxcfg_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/inboxcfg"
)

func TestInboxFilterFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("default_visibility: hidden\nrules:\n  - match: [{field: label, op: equals, value: x}]\n"), 0o600))

	// filter_file loads the filter from the path.
	flt, err := inboxcfg.Inbox{Name: "p", FilterFile: path}.Filter()
	require.NoError(t, err)
	assert.Equal(t, filter.Hide, flt.Default())

	// filter_file AND inline together is a config error (Filter + Validate).
	both := inboxcfg.Inbox{Name: "p", FilterFile: path, DefaultVisibility: "visible"}
	_, err = both.Filter()
	require.Error(t, err)
	require.Error(t, inboxcfg.Validate([]inboxcfg.Inbox{both}))
}

const twoInboxes = `
inboxes:
  - name: work
    identity: agent@company.example
    backend:
      imap_host: imap.company.example:993
      imap_username: agent@company.example
      sender_type: smtp
    default_visibility: visible
    rules:
      - match: [{field: from, op: domain, value: spam.example}]
  - name: personal
    identity: me@personal.example
    backend:
      imap_host: imap.personal.example:993
    default_visibility: hidden
    rules:
      - match: [{field: label, op: equals, value: keep}]
`

func TestParse(t *testing.T) {
	got, err := inboxcfg.Parse([]byte(twoInboxes))
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "work", got[0].Name)
	assert.Equal(t, "agent@company.example", got[0].Identity)
	assert.Equal(t, "imap.company.example:993", got[0].Backend.IMAPHost)
	assert.Equal(t, "smtp", got[0].Backend.SenderType)
	assert.Equal(t, "personal", got[1].Name)
	assert.Equal(t, "hidden", got[1].DefaultVisibility)

	// No inboxes: section → nil (caller substitutes the implicit default).
	none, err := inboxcfg.Parse([]byte("agent_username: agent\n"))
	require.NoError(t, err)
	assert.Nil(t, none)
}

func TestResolveImplicitDefault(t *testing.T) {
	implicit := inboxcfg.Inbox{Name: "default", Identity: "agent@x.test"}
	// No configured inboxes → the single implicit default (back-compat).
	got := inboxcfg.Resolve(nil, implicit)
	require.Len(t, got, 1)
	assert.Equal(t, "default", got[0].Name)
	// Configured inboxes take precedence over the implicit default.
	parsed, err := inboxcfg.Parse([]byte(twoInboxes))
	require.NoError(t, err)
	assert.Len(t, inboxcfg.Resolve(parsed, implicit), 2)
}

func TestValidate(t *testing.T) {
	ok, err := inboxcfg.Parse([]byte(twoInboxes))
	require.NoError(t, err)
	assert.NoError(t, inboxcfg.Validate(ok))

	assert.Error(t, inboxcfg.Validate(nil)) // no inboxes

	dup := []inboxcfg.Inbox{{Name: "a"}, {Name: "a"}}
	assert.Error(t, inboxcfg.Validate(dup)) // duplicate name

	noname := []inboxcfg.Inbox{{Name: " "}}
	assert.Error(t, inboxcfg.Validate(noname)) // empty name

	bad := []inboxcfg.Inbox{{Name: "x", DefaultVisibility: "bogus"}}
	assert.Error(t, inboxcfg.Validate(bad)) // filter fails to compile
}

func TestInboxFilter(t *testing.T) {
	in, err := inboxcfg.Parse([]byte(twoInboxes))
	require.NoError(t, err)
	now := time.Now()

	// personal: hidden (default-deny); a bare rule on label=keep flips to SHOW.
	flt, err := in[1].Filter()
	require.NoError(t, err)
	assert.Equal(t, filter.Hide, flt.Default())
	assert.Equal(t, filter.Allow, flt.Decide(inbound.Message{Keywords: []string{"keep"}}, now))
	assert.Equal(t, filter.Hide, flt.Decide(inbound.Message{Keywords: []string{"other"}}, now))

	// an inbox with no filter keys → pass-through (default-allow)
	passthrough, err := inboxcfg.Inbox{Name: "x"}.Filter()
	require.NoError(t, err)
	assert.Equal(t, filter.Allow, passthrough.Default())
}
