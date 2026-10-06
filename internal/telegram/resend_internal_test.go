package telegram

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// botCall is one Bot API call the client made: its method and decoded body.
type botCall struct {
	method string
	body   map[string]any
}

// recordingBot answers every Bot API call with success and records it.
type recordingBot struct {
	mu    sync.Mutex
	calls []botCall
}

func (r *recordingBot) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	method := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
	body := map[string]any{}
	if err := req.ParseMultipartForm(1 << 20); err == nil {
		for k, v := range req.MultipartForm.Value {
			var parsed any
			if json.Unmarshal([]byte(v[0]), &parsed) == nil {
				body[k] = parsed
			} else {
				body[k] = v[0]
			}
		}
	} else {
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &body)
	}
	r.mu.Lock()
	r.calls = append(r.calls, botCall{method: method, body: body})
	r.mu.Unlock()
	if method == "answerCallbackQuery" {
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		return
	}
	_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"date":0,"chat":{"id":999,"type":"private"}}}`))
}

func (r *recordingBot) methods() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.calls {
		out = append(out, c.method)
	}
	return out
}

func (r *recordingBot) last(method string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.calls) - 1; i >= 0; i-- {
		if r.calls[i].method == method {
			return r.calls[i].body
		}
	}
	return nil
}

// fakeQueue is the admin API's queue: the listing it returns and the re-sends
// it was asked for, answering each with resendStatus and resendBody.
type fakeQueue struct {
	mu           sync.Mutex
	metas        []sluice.Meta
	resends      []bool // the acknowledgement of each re-send asked for
	resendStatus int
	resendBody   string
}

func (q *fakeQueue) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q.mu.Lock()
	defer q.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/queue":
		_ = json.NewEncoder(w).Encode(q.metas)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/resend"):
		var req admin.ResendRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		q.resends = append(q.resends, req.AcknowledgeOutcomeUnknown)
		w.WriteHeader(q.resendStatus)
		_, _ = w.Write([]byte(q.resendBody))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newCardClient(t *testing.T, q *fakeQueue) (*Client, *recordingBot) {
	t.Helper()
	rb := &recordingBot{}
	botSrv := httptest.NewServer(rb)
	t.Cleanup(botSrv.Close)
	b, err := bot.New("123:fake", bot.WithSkipGetMe(), bot.WithServerURL(botSrv.URL))
	require.NoError(t, err)
	adminSrv := httptest.NewServer(q)
	t.Cleanup(adminSrv.Close)
	if q.resendStatus == 0 {
		q.resendStatus = http.StatusOK
		q.resendBody = `{"id":"7","status":"sent","detail":"re-sent upstream"}`
	}
	return &Client{
		bot: b, admin: admin.NewClient(strings.TrimPrefix(adminSrv.URL, "http://"), "t"),
		operatorID: 999, logger: slog.Default(), posted: map[string]bool{}, postedFailed: map[string]bool{},
	}, rb
}

func callback(data string, from int64) *models.Update {
	return &models.Update{CallbackQuery: &models.CallbackQuery{
		ID: "cq", From: models.User{ID: from}, Data: data,
		Message: models.MaybeInaccessibleMessage{Message: &models.Message{ID: 5, Chat: models.Chat{ID: 999}}},
	}}
}

// keyboardData is the callback data of every button in a sent keyboard.
func keyboardData(body map[string]any) []string {
	var out []string
	markup, _ := body["reply_markup"].(map[string]any)
	rows, _ := markup["inline_keyboard"].([]any)
	for _, row := range rows {
		for _, b := range row.([]any) {
			out = append(out, b.(map[string]any)["callback_data"].(string))
		}
	}
	return out
}

// Each approved message whose send failed gets one card; an unknown outcome
// gets its own warning; a pending, a sent, or a message being re-sent gets
// none. A message that recovers and fails again is carded again.
func TestFailedSendsAreCardedOnce(t *testing.T) {
	q := &fakeQueue{metas: []sluice.Meta{
		{ID: "1", Status: sluice.StatusPending},
		{ID: "2", Status: sluice.StatusApproved, SendErr: "451 4.3.0 try later", Subject: "hello"},
		{ID: "3", Status: sluice.StatusApproved, SendErr: "outcome unknown: no final reply from the server", OutcomeUnknown: true},
		{ID: "4", Status: sluice.StatusApproved, SendErr: "451 later", ResendInProgress: true},
		{ID: "5", Status: sluice.StatusSent},
	}}
	c, rb := newCardClient(t, q)
	ctx := context.Background()

	c.pollFailed(ctx, q.metas)
	var texts []string
	var keyboards [][]string
	for _, call := range rb.calls {
		if call.method == "sendMessage" {
			texts = append(texts, call.body["text"].(string))
			keyboards = append(keyboards, keyboardData(call.body))
		}
	}
	require.Len(t, texts, 2)
	assert.Equal(t, [][]string{{cbResend + "2"}, {cbResend + "3"}}, keyboards)
	assert.Contains(t, texts[0], "Send failed — message 2")
	assert.Contains(t, texts[0], "451 4.3.0 try later")
	assert.Contains(t, texts[1], "OUTCOME UNKNOWN — message 3")
	assert.Contains(t, texts[1], "MAY ALREADY HAVE BEEN DELIVERED")

	c.pollFailed(ctx, q.metas)
	assert.Len(t, rb.methods(), 2, "no second card")

	recovered := []sluice.Meta{{ID: "2", Status: sluice.StatusSent}}
	c.pollFailed(ctx, recovered)
	failedAgain := []sluice.Meta{{ID: "2", Status: sluice.StatusApproved, SendErr: "451 again"}}
	c.pollFailed(ctx, failedAgain)
	assert.Len(t, rb.methods(), 3, "a fresh failure after recovery gets a fresh card")
}

// Re-send on an ordinary failure re-sends without the acknowledgement and
// writes the result on the card.
func TestResendOnAFailedCardResends(t *testing.T) {
	q := &fakeQueue{metas: []sluice.Meta{{ID: "2", Status: sluice.StatusApproved, SendErr: "451 later"}}}
	c, rb := newCardClient(t, q)
	c.handleResend(context.Background(), c.bot, callback(cbResend+"2", 999))

	assert.Equal(t, []bool{false}, q.resends)
	assert.Contains(t, rb.last("editMessageText")["text"], "Re-sent 2")
}

// Re-send on an unknown outcome sends nothing: it asks to confirm, and only
// the confirmation re-sends, with the acknowledgement. Back restores Re-send.
func TestResendOnAnUnknownOutcomeAsksFirst(t *testing.T) {
	q := &fakeQueue{metas: []sluice.Meta{{ID: "3", Status: sluice.StatusApproved, SendErr: "outcome unknown: x", OutcomeUnknown: true}}}
	c, rb := newCardClient(t, q)
	ctx := context.Background()

	c.handleResend(ctx, c.bot, callback(cbResend+"3", 999))
	assert.Empty(t, q.resends, "nothing is sent before the confirmation")
	assert.Equal(t, []string{cbResendAck + "3", cbResendBack + "3"}, keyboardData(rb.last("editMessageReplyMarkup")))

	c.handleResendBack(ctx, c.bot, callback(cbResendBack+"3", 999))
	assert.Equal(t, []string{cbResend + "3"}, keyboardData(rb.last("editMessageReplyMarkup")))

	c.handleResendAck(ctx, c.bot, callback(cbResendAck+"3", 999))
	assert.Equal(t, []bool{true}, q.resends)
	assert.Contains(t, rb.last("editMessageText")["text"], "Re-sent 3")
}

// A card posted before the outcome became unknown: the service's refusal turns
// into the confirmation, not an error on the card.
func TestAnAckRefusalAsksToConfirm(t *testing.T) {
	q := &fakeQueue{
		metas:        []sluice.Meta{{ID: "2", Status: sluice.StatusApproved, SendErr: "451 later"}},
		resendStatus: http.StatusConflict, resendBody: `{"error":"x","code":"ack_required"}`,
	}
	c, rb := newCardClient(t, q)
	c.handleResend(context.Background(), c.bot, callback(cbResend+"2", 999))
	assert.Equal(t, []string{cbResendAck + "2", cbResendBack + "2"}, keyboardData(rb.last("editMessageReplyMarkup")))
	assert.Nil(t, rb.last("editMessageText"))
}

// A re-send already in progress leaves the card as it is and says so.
func TestAResendInProgressLeavesTheCard(t *testing.T) {
	q := &fakeQueue{
		metas:        []sluice.Meta{{ID: "2", Status: sluice.StatusApproved, SendErr: "451 later"}},
		resendStatus: http.StatusConflict, resendBody: `{"error":"x","code":"resend_in_progress"}`,
	}
	c, rb := newCardClient(t, q)
	c.handleResend(context.Background(), c.bot, callback(cbResend+"2", 999))
	assert.Contains(t, rb.last("answerCallbackQuery")["text"], "already in progress")
	assert.Nil(t, rb.last("editMessageText"))
	assert.Nil(t, rb.last("editMessageReplyMarkup"))
}

// Only the operator can re-send, acknowledge or go back.
func TestOnlyTheOperatorCanResend(t *testing.T) {
	q := &fakeQueue{metas: []sluice.Meta{{ID: "2", Status: sluice.StatusApproved, SendErr: "451 later"}}}
	c, rb := newCardClient(t, q)
	ctx := context.Background()
	c.handleResend(ctx, c.bot, callback(cbResend+"2", 1))
	c.handleResendAck(ctx, c.bot, callback(cbResendAck+"2", 1))
	c.handleResendBack(ctx, c.bot, callback(cbResendBack+"2", 1))
	assert.Empty(t, q.resends)
	assert.Equal(t, []string{"answerCallbackQuery", "answerCallbackQuery", "answerCallbackQuery"}, rb.methods())
}

// The card's prefixes route only to their own handlers: none is a prefix of
// another callback prefix the bot registers.
func TestResendPrefixesDoNotOverlap(t *testing.T) {
	all := []string{cbApprove, cbRejectPerm, cbRejectRetry, cbExpose, cbDrop, cbHeldFull, cbChange, cbApproveAs, cbChangeBack, cbResend, cbResendAck, cbResendBack}
	for _, p := range []string{cbResend, cbResendAck, cbResendBack} {
		for _, q := range all {
			if p != q {
				assert.False(t, strings.HasPrefix(q, p), "%q prefixes %q", p, q)
			}
		}
	}
}

// The queue poll cards failed sends too.
func TestThePollCardsFailedSends(t *testing.T) {
	q := &fakeQueue{metas: []sluice.Meta{{ID: "2", Status: sluice.StatusApproved, SendErr: "451 later"}}}
	c, rb := newCardClient(t, q)
	c.poll(context.Background())
	assert.Equal(t, []string{"sendMessage"}, rb.methods())
	assert.Contains(t, rb.last("sendMessage")["text"], "Send failed — message 2")
}

// A client built by New can record failed-send cards.
func TestNewTracksFailedSendCards(t *testing.T) {
	c, err := New("123:fake", 999, 0, admin.NewClient("127.0.0.1:1", "t"))
	require.NoError(t, err)
	assert.NotPanics(t, func() { c.markFailed("2", true) })
	assert.True(t, c.seenFailed("2"))
}

// A re-send that fails again, even with the same error, gets a fresh card: the
// old card now shows that attempt's result and has no buttons.
func TestAResendThatFailsAgainIsCardedAgain(t *testing.T) {
	failed := []sluice.Meta{{ID: "2", Status: sluice.StatusApproved, SendErr: "451 later"}}
	q := &fakeQueue{metas: failed, resendStatus: http.StatusOK,
		resendBody: `{"id":"2","status":"approved","detail":"re-send attempted","warn":"upstream re-send failed (transient)"}`}
	c, rb := newCardClient(t, q)
	ctx := context.Background()
	c.pollFailed(ctx, failed)
	c.handleResend(ctx, c.bot, callback(cbResend+"2", 999))
	c.pollFailed(ctx, failed)

	var cards int
	for _, m := range rb.methods() {
		if m == "sendMessage" {
			cards++
		}
	}
	assert.Equal(t, 2, cards)
}
