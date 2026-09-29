package telegram

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-telegram/bot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAPI stands in for the bot API: sendDocument and sendMessage answer with the
// configured outcome, and every sendMessage is recorded with its text and the
// message it replies to.
type fakeAPI struct {
	docOK bool
	msgOK bool

	mu    sync.Mutex
	docs  int
	sends []sentMessage
}

type sentMessage struct {
	text    string
	replyTo int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ok := false
	switch {
	case strings.HasSuffix(r.URL.Path, "/sendDocument"):
		f.mu.Lock()
		f.docs++
		f.mu.Unlock()
		ok = f.docOK
	case strings.HasSuffix(r.URL.Path, "/sendMessage"):
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m := sentMessage{text: r.FormValue("text")}
		if rp := r.FormValue("reply_parameters"); rp != "" {
			var p struct {
				MessageID int `json:"message_id"`
			}
			if err := json.Unmarshal([]byte(rp), &p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			m.replyTo = p.MessageID
		}
		f.mu.Lock()
		f.sends = append(f.sends, m)
		f.mu.Unlock()
		ok = f.msgOK
	}
	if !ok {
		_, _ = w.Write([]byte(`{"ok":false,"error_code":500,"description":"Internal Server Error"}`))
		return
	}
	_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"date":0,"chat":{"id":999,"type":"private"}}}`))
}

func newClientForAPI(t *testing.T, api *fakeAPI) *Client {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	b, err := bot.New("123:fake", bot.WithSkipGetMe(), bot.WithServerURL(srv.URL))
	require.NoError(t, err)
	return &Client{bot: b, operatorID: 999, logger: slog.Default()}
}

// #320: the card already promised the full body as an attachment, so when the
// upload fails the operator gets a notice threaded onto the same card saying it
// could not be attached.
func TestFullBodyUploadFailurePostsNotice(t *testing.T) {
	api := &fakeAPI{docOK: false, msgOK: true}
	c := newClientForAPI(t, api)

	c.sendFullBody(context.Background(), "42", 1001, "a long body")

	assert.Equal(t, 1, api.docs)
	require.Len(t, api.sends, 1, "exactly one notice after the failed upload")
	assert.Equal(t, fullBodyFailedNotice("42"), api.sends[0].text)
	assert.Contains(t, api.sends[0].text, "msg 42")
	assert.Equal(t, 1001, api.sends[0].replyTo, "threaded onto the decision card")
}

// A successful upload keeps its promise, so no notice is sent.
func TestFullBodyUploadSuccessSendsNoNotice(t *testing.T) {
	api := &fakeAPI{docOK: true, msgOK: true}
	c := newClientForAPI(t, api)

	c.sendFullBody(context.Background(), "42", 1001, "a long body")

	assert.Equal(t, 1, api.docs)
	assert.Empty(t, api.sends)
}

// The notice is best-effort like the upload: when it fails too, it is attempted
// once and not retried, and sendFullBody still returns.
func TestFullBodyNoticeFailureIsNotRetried(t *testing.T) {
	api := &fakeAPI{docOK: false, msgOK: false}
	c := newClientForAPI(t, api)

	c.sendFullBody(context.Background(), "42", 1001, "a long body")

	assert.Equal(t, 1, api.docs)
	assert.Len(t, api.sends, 1, "one attempt, no retry loop")
}

// With no captured anchor the notice is still sent, unthreaded, matching how the
// upload itself degrades.
func TestFullBodyNoticeWithoutAnchor(t *testing.T) {
	api := &fakeAPI{docOK: false, msgOK: true}
	c := newClientForAPI(t, api)

	c.sendFullBody(context.Background(), "42", 0, "a long body")

	require.Len(t, api.sends, 1)
	assert.Equal(t, 0, api.sends[0].replyTo)
}
