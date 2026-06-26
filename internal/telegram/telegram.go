// Package telegram is the Telegram approval client (ADR 0017): a separate,
// long-running process that bridges the operator's Telegram chat to the
// localhost-only admin API (#52). It is NOT compiled into serve; it holds only
// a bot token and an admin-API token, never the mail credentials (ADR 0002).
//
// It polls the admin queue and posts each new held message to the operator
// chat with an [Approve] / [Reject permanent] / [Reject retryable] keyboard.
// The button callbacks (the actual approve/reject) land in later increments
// (#60); this increment is notify + de-dupe only.
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

	mu     sync.Mutex
	posted map[string]bool // message ids already sent to the operator
}

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
	}
	// [Approve] button. The reject buttons are wired in the next increment.
	b.RegisterHandler(bot.HandlerTypeCallbackQueryData, cbApprove, bot.MatchTypePrefix, c.handleApprove)
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
	_, err := c.bot.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:      c.operatorID,
		Text:        formatPending(m),
		ReplyMarkup: decisionKeyboard(m.ID),
	})
	return err
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

// formatPending renders the operator-facing notification (plain text — no parse
// mode, so addresses and subjects never need markdown escaping). Subject comes
// from the queue listing (sluice.Meta), already parsed by the store.
func formatPending(m sluice.Meta) string {
	subject := m.Subject
	if strings.TrimSpace(subject) == "" {
		subject = "(no subject)"
	}
	return fmt.Sprintf("Held outbound message\nid: %s\nfrom: %s\nto: %s\nsubject: %s\nsize: %d bytes",
		m.ID, m.From, strings.Join(m.Rcpt, ", "), subject, m.Size)
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
	out, err := c.admin.Approve(ctx, id)
	c.finishDecision(ctx, b, cq, "Approved", id, out, err)
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
	result := decisionResult(verb, id, out, err)
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: cq.ID, Text: verb})
	if msg := cq.Message.Message; msg != nil {
		_, _ = b.EditMessageText(ctx, &bot.EditMessageTextParams{
			ChatID:      msg.Chat.ID,
			MessageID:   msg.ID,
			Text:        result,
			ReplyMarkup: models.InlineKeyboardMarkup{}, // clear the buttons
		})
	}
	log.Printf("darbaan telegram: %s", result)
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
