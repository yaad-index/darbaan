// Package telegram is the Telegram approval client (ADR 0017): a separate,
// long-running process that bridges the operator's Telegram chat to the
// localhost-only admin API (#52). It is NOT compiled into serve; it holds only
// a bot token and an admin-API token, never the mail credentials (ADR 0002).
//
// It polls the admin queue and posts each new held message to the operator
// chat with an [Approve] / [Reject permanent] / [Reject retryable] keyboard,
// then applies the operator's decision via the admin API: Approve sends through
// immediately; either Reject first prompts (force-reply) for a reason that
// becomes the DSN bounce reason. Only the configured operator may decide
// (ADR 0002) — both the button taps and the reason reply are gated to them.
package telegram

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// Callback-data prefixes for the decision buttons. The message id is appended;
// the handlers that parse these land in later increments.
const (
	cbApprove     = "approve:"
	cbRejectPerm  = "reject_perm:"
	cbRejectRetry = "reject_retry:"
)

// Client is the Telegram approval interface.
type Client struct {
	bot          *bot.Bot
	admin        *admin.Client
	operatorID   int64
	pollInterval time.Duration

	mu      sync.Mutex
	posted  map[string]bool     // message ids already sent to the operator
	pending map[int]rejectState // reject reason prompts awaiting the operator's reply, keyed by prompt message id
}

// rejectState remembers, for a reason force-reply prompt, which held message it
// is for and where to write the result. at bounds the map: prompts the operator
// never answers are pruned by TTL (#66).
type rejectState struct {
	id         string
	retryable  bool
	origChatID int64
	origMsgID  int
	at         time.Time
}

// pendingTTL is how long an unanswered reason prompt is retained before pruning.
const pendingTTL = time.Hour

// New builds the Telegram client. The bot token is never logged; operatorID is
// the only chat/user permitted to act (everyone else is ignored); adminClient
// is the admin-API client through which the queue is read and verdicts relayed.
// The bot is constructed without a network call (the connect happens in Run).
func New(token string, operatorID int64, pollInterval time.Duration, adminClient *admin.Client) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("telegram: bot token is required (DARBAAN_TELEGRAM_TOKEN)")
	}
	if operatorID == 0 {
		return nil, fmt.Errorf("telegram: a telegram-operator-id is required (only that chat may approve/reject)")
	}
	if adminClient == nil {
		return nil, fmt.Errorf("telegram: an admin client is required")
	}
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	b, err := bot.New(token, bot.WithSkipGetMe(), bot.WithDefaultHandler(ignoreUpdate))
	if err != nil {
		return nil, fmt.Errorf("telegram: init bot: %w", err)
	}
	c := &Client{
		bot:          b,
		admin:        adminClient,
		operatorID:   operatorID,
		pollInterval: pollInterval,
		posted:       make(map[string]bool),
		pending:      make(map[int]rejectState),
	}
	b.RegisterHandler(bot.HandlerTypeCallbackQueryData, cbApprove, bot.MatchTypePrefix, c.handleApprove)
	b.RegisterHandler(bot.HandlerTypeCallbackQueryData, cbRejectPerm, bot.MatchTypePrefix, c.handleRejectPermanent)
	b.RegisterHandler(bot.HandlerTypeCallbackQueryData, cbRejectRetry, bot.MatchTypePrefix, c.handleRejectRetryable)
	// The reason force-reply arrives as a normal reply message, not a callback.
	b.RegisterHandlerMatchFunc(isReply, c.handleReasonReply)
	return c, nil
}

// Run connects to Telegram, logs readiness, polls the queue for new held
// messages, and runs the update loop until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	me, err := c.bot.GetMe(ctx)
	if err != nil {
		return fmt.Errorf("telegram: connect: %w", err)
	}
	log.Printf("darbaan telegram: ready — bot @%s, operator %d, polling the queue every %s", me.Username, c.operatorID, c.pollInterval)

	go c.pollLoop(ctx)
	c.bot.Start(ctx) // long-poll loop; returns when ctx is cancelled
	return nil
}

func (c *Client) pollLoop(ctx context.Context) {
	t := time.NewTicker(c.pollInterval)
	defer t.Stop()
	c.poll(ctx) // post anything already pending at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.poll(ctx)
		}
	}
}

// poll lists the queue and notifies the operator of each new pending message.
// A message is marked posted only after a successful send, so a transient send
// failure simply retries on the next tick.
func (c *Client) poll(ctx context.Context) {
	metas, err := c.admin.List(ctx)
	if err != nil {
		log.Printf("darbaan telegram: poll: %v", err)
		return
	}
	c.prunePosted(metas)
	for _, m := range metas {
		if m.Status != sluice.StatusPending || c.seen(m.ID) {
			continue
		}
		if err := c.notify(ctx, m); err != nil {
			log.Printf("darbaan telegram: notify %s: %v", m.ID, err)
			continue
		}
		c.markPosted(m.ID)
	}
}

func (c *Client) notify(ctx context.Context, m sluice.Meta) error {
	// Fetch the raw message for the body + display addresses so the operator can
	// review what they're approving. De-dupe means one fetch per message; a
	// fetch failure still notifies, falling back to the envelope values.
	raw, err := c.admin.Show(ctx, m.ID)
	if err != nil {
		log.Printf("darbaan telegram: fetch body %s: %v", m.ID, err)
	}
	from, to, headerSet, parsed := headerAddrs(raw)
	if from == "" {
		from = m.From
	}
	if to == "" {
		to = strings.Join(m.Rcpt, ", ")
	}
	n := notification{
		id:      m.ID,
		from:    from,
		to:      to,
		subject: displaySubject(m.Subject),
		size:    m.Size,
		body:    bodyText(raw),
	}
	// Surface recipients that deliver but aren't visible in the headers (Bcc),
	// but only when we could actually read the headers.
	if parsed {
		n.hidden = hiddenRcpts(m.Rcpt, headerSet)
	}
	_, err = c.bot.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:      c.operatorID,
		Text:        formatNotification(n),
		ReplyMarkup: decisionKeyboard(m.ID),
	})
	return err
}

// prunePosted drops de-dup entries for messages no longer pending, bounding the
// set to the live queue (#66).
func (c *Client) prunePosted(metas []sluice.Meta) {
	live := make(map[string]bool, len(metas))
	for _, m := range metas {
		if m.Status == sluice.StatusPending {
			live[m.ID] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.posted {
		if !live[id] {
			delete(c.posted, id)
		}
	}
}

func (c *Client) seen(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.posted[id]
}

func (c *Client) markPosted(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.posted[id] = true
}

// notification is the display-ready content of an operator notification.
type notification struct {
	id      string
	from    string // header display form, falling back to the envelope sender
	to      string // header To/Cc display form, falling back to the envelope rcpts
	subject string
	size    int
	hidden  []string // envelope recipients not in the headers (Bcc)
	body    string
}

func displaySubject(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(no subject)"
	}
	return s
}

// maxNotificationRunes keeps the notification within Telegram's 4096-char cap
// with headroom for the keyboard and the truncation marker.
const maxNotificationRunes = 3900

// formatNotification renders the headers (human address forms, plus a flag for
// any hidden recipient) followed by the message body so the operator reviews
// the content before deciding. The body is truncated (rune-safe) with a marker
// when the whole notification would exceed the cap. Plain text — no parse mode,
// so addresses and subjects never need markdown escaping.
func formatNotification(n notification) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Held outbound message\nid: %s\nfrom: %s\nto: %s\nsubject: %s\nsize: %d bytes",
		n.id, n.from, n.to, n.subject, n.size)
	if len(n.hidden) > 0 {
		fmt.Fprintf(&b, "\n(!) also delivering to (not in headers): %s", strings.Join(n.hidden, ", "))
	}
	header := b.String()
	if n.body == "" {
		return header + "\n\n(no text body)"
	}
	prefix := header + "\n\n--- body ---\n"
	avail := maxNotificationRunes - len([]rune(prefix)) - 40 // room for the marker
	if avail < 0 {
		avail = 0
	}
	if br := []rune(n.body); len(br) > avail {
		return prefix + string(br[:avail]) + fmt.Sprintf("\n...(truncated, %d bytes)", len(n.body))
	}
	return prefix + n.body
}

// decisionKeyboard lays in all three decision buttons. The callbacks are wired
// in later increments; the callback data carries the action + message id.
func decisionKeyboard(id string) models.InlineKeyboardMarkup {
	return models.InlineKeyboardMarkup{
		InlineKeyboard: [][]models.InlineKeyboardButton{
			{{Text: "Approve", CallbackData: cbApprove + id}},
			{
				{Text: "Reject (permanent)", CallbackData: cbRejectPerm + id},
				{Text: "Reject (retryable)", CallbackData: cbRejectRetry + id},
			},
		},
	}
}

// handleApprove is the [Approve] button callback: verify the operator, approve
// via the admin API, and edit the notification to show the outcome.
func (c *Client) handleApprove(ctx context.Context, b *bot.Bot, update *models.Update) {
	cq := update.CallbackQuery
	if !c.isOperator(cq) {
		c.denyCallback(ctx, b, cq)
		return
	}
	id := strings.TrimPrefix(cq.Data, cbApprove)
	if !c.guardPending(ctx, b, cq, id) {
		return
	}
	out, err := c.admin.Approve(ctx, id)
	c.finishDecision(ctx, b, cq, "Approved", id, out, err)
}

// guardPending pre-checks a tapped message's status so a stale duplicate tap is
// explained rather than silently re-running. It returns true to proceed (still
// pending, or the status couldn't be looked up — the server-side not-pending
// guard is the backstop) and false after telling the operator the message is
// already decided / gone and stripping its notification.
func (c *Client) guardPending(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery, id string) bool {
	status, found, err := c.statusOf(ctx, id)
	proceed, msg := pendingGuardResult(id, status, found, err)
	if proceed {
		return true
	}
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
		CallbackQueryID: cq.ID, Text: msg, ShowAlert: true,
	})
	if m := cq.Message.Message; m != nil {
		c.editResult(ctx, b, m.Chat.ID, m.ID, msg)
	}
	return false
}

// statusOf looks up a message's current status from the queue listing.
func (c *Client) statusOf(ctx context.Context, id string) (sluice.Status, bool, error) {
	metas, err := c.admin.List(ctx)
	if err != nil {
		return "", false, err
	}
	for _, m := range metas {
		if m.ID == id {
			return m.Status, true, nil
		}
	}
	return "", false, nil
}

// pendingGuardResult decides whether to proceed with a decision and, if not,
// the message to show the operator. A lookup error proceeds (the server-side
// guard backstops); a still-pending message proceeds; anything else stops.
func pendingGuardResult(id string, status sluice.Status, found bool, listErr error) (proceed bool, msg string) {
	switch {
	case listErr != nil:
		return true, ""
	case found && status == sluice.StatusPending:
		return true, ""
	case !found:
		return false, fmt.Sprintf("Message %s: no longer in the queue", id)
	default:
		return false, fmt.Sprintf("Message %s: already %s", id, status)
	}
}

// isOperator reports whether a callback came from the configured operator — the
// core security property: only the operator may decide (ADR 0002).
func (c *Client) isOperator(cq *models.CallbackQuery) bool {
	return cq != nil && cq.From.ID == c.operatorID
}

// denyCallback rejects a callback from anyone but the operator.
func (c *Client) denyCallback(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery) {
	log.Printf("darbaan telegram: ignored callback from non-operator %d", cq.From.ID)
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
		CallbackQueryID: cq.ID, Text: "Not authorized.", ShowAlert: true,
	})
}

// finishDecision dismisses the button spinner and rewrites the notification to
// the outcome, clearing the keyboard so it cannot be tapped again.
func (c *Client) finishDecision(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery, verb, id string, out admin.Outcome, err error) {
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: cq.ID, Text: verb})
	if msg := cq.Message.Message; msg != nil {
		c.editResult(ctx, b, msg.Chat.ID, msg.ID, decisionResult(verb, id, out, err))
	}
}

// emptyKeyboard removes an inline keyboard on edit. It must carry a non-nil
// empty slice: the zero value InlineKeyboardMarkup{} marshals to
// `{"inline_keyboard":null}`, which Telegram treats as "no change" and leaves
// the buttons; an empty slice marshals to `[]`, which actually clears them.
func emptyKeyboard() models.InlineKeyboardMarkup {
	return models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{}}
}

// editResult rewrites a notification to a final outcome line, clearing the
// keyboard so a decided message cannot be tapped again.
func (c *Client) editResult(ctx context.Context, b *bot.Bot, chatID int64, msgID int, result string) {
	_, _ = b.EditMessageText(ctx, &bot.EditMessageTextParams{
		ChatID:      chatID,
		MessageID:   msgID,
		Text:        result,
		ReplyMarkup: emptyKeyboard(),
	})
	log.Printf("darbaan telegram: %s", result)
}

// handleRejectPermanent / handleRejectRetryable are the two reject buttons; both
// prompt for a reason (the only difference is the retryable flag carried into
// the DSN bounce).
func (c *Client) handleRejectPermanent(ctx context.Context, b *bot.Bot, update *models.Update) {
	c.promptReason(ctx, b, update.CallbackQuery, cbRejectPerm, false)
}

func (c *Client) handleRejectRetryable(ctx context.Context, b *bot.Bot, update *models.Update) {
	c.promptReason(ctx, b, update.CallbackQuery, cbRejectRetry, true)
}

// promptReason verifies the operator, then sends a force-reply asking for the
// rejection reason and remembers which message the eventual reply decides.
func (c *Client) promptReason(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery, prefix string, retryable bool) {
	if !c.isOperator(cq) {
		c.denyCallback(ctx, b, cq)
		return
	}
	msg := cq.Message.Message
	if msg == nil {
		_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: cq.ID})
		return
	}
	id := strings.TrimPrefix(cq.Data, prefix)
	if !c.guardPending(ctx, b, cq, id) {
		return // already decided / gone — don't prompt for a reason
	}
	kind := "permanent"
	if retryable {
		kind = "retryable"
	}
	prompt, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: msg.Chat.ID,
		Text:   fmt.Sprintf("Reason for the %s rejection of %s? Reply to this message.", kind, id),
		ReplyMarkup: models.ForceReply{
			ForceReply: true, InputFieldPlaceholder: "rejection reason", Selective: true,
		},
	})
	if err != nil {
		log.Printf("darbaan telegram: reject prompt %s: %v", id, err)
		// Dismiss the spinner so the button doesn't hang on a network error.
		_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
			CallbackQueryID: cq.ID, Text: "Could not start the reason prompt.",
		})
		return
	}
	c.mu.Lock()
	c.prunePendingLocked(time.Now())
	c.pending[prompt.ID] = rejectState{id: id, retryable: retryable, origChatID: msg.Chat.ID, origMsgID: msg.ID, at: time.Now()}
	c.mu.Unlock()
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: cq.ID, Text: "Reason?"})
	// Strip the keyboard on the original notification and show an interim state,
	// so a tapped-but-unfinished reject is visibly distinct from untouched
	// messages when several are open. handleReasonReply overwrites this with the
	// final outcome once the reason arrives.
	c.editResult(ctx, b, msg.Chat.ID, msg.ID, fmt.Sprintf("⏳ Rejecting %s — awaiting your reason", id))
}

// prunePendingLocked drops reason prompts older than pendingTTL — those the
// operator started but never answered — bounding the map (#66). Caller holds mu.
func (c *Client) prunePendingLocked(now time.Time) {
	for k, st := range c.pending {
		if now.Sub(st.at) > pendingTTL {
			delete(c.pending, k)
		}
	}
}

// handleReasonReply consumes the operator's reply to a reason prompt and applies
// the rejection. Gated to the operator and to a reply that matches a prompt we
// sent — anyone else's message, or a reply to anything else, is ignored.
func (c *Client) handleReasonReply(ctx context.Context, b *bot.Bot, update *models.Update) {
	m := update.Message
	if m.From == nil || m.From.ID != c.operatorID {
		return
	}
	c.mu.Lock()
	st, ok := c.pending[m.ReplyToMessage.ID]
	if ok {
		delete(c.pending, m.ReplyToMessage.ID)
	}
	c.mu.Unlock()
	if !ok {
		return
	}
	reason := strings.TrimSpace(m.Text)
	if reason == "" {
		reason = "(no reason given)"
	}
	out, err := c.admin.Reject(ctx, st.id, reason, st.retryable)
	c.editResult(ctx, b, st.origChatID, st.origMsgID, decisionResult("Rejected", st.id, out, err))
	// Tidy the prompt away (best-effort).
	_, _ = b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: m.Chat.ID, MessageID: m.ReplyToMessage.ID})
}

// isReply matches a message that is a reply (the reason force-reply arrives this
// way).
func isReply(u *models.Update) bool {
	return u.Message != nil && u.Message.ReplyToMessage != nil
}

// decisionResult renders the operator-facing outcome line. A committed verdict
// with a downstream send/bounce warning is shown as such (distinct from a
// failed verdict).
func decisionResult(verb, id string, out admin.Outcome, err error) string {
	switch {
	case err != nil:
		return fmt.Sprintf("%s failed (%s): %v", verb, id, err)
	case out.Warn != "":
		return fmt.Sprintf("%s %s — %s [warning: %s]", verb, id, out.Detail, out.Warn)
	default:
		return fmt.Sprintf("%s %s — %s", verb, id, out.Detail)
	}
}

// ignoreUpdate drops updates that aren't a wired decision callback.
func ignoreUpdate(context.Context, *bot.Bot, *models.Update) {}
