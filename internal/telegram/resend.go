package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// Callback-data prefixes of the failed-send card (ADR 0039 section 3). None is
// a prefix of another or of an existing one: "resend:" does not prefix
// "resend_ack:" or "resend_back:", and no "re…" prefix in use prefixes them.
const (
	cbResend     = "resend:"
	cbResendAck  = "resend_ack:"
	cbResendBack = "resend_back:"
)

// failedSend reports whether m is an approved message whose last send failed
// and that no re-send is running: what a failed-send card is for.
func failedSend(m sluice.Meta) bool {
	return m.Status == sluice.StatusApproved && m.SendErr != "" && !m.ResendInProgress
}

// pollFailed posts a card for each approved message whose send failed and has
// no card yet, so the operator can re-send it from the chat. A message whose
// outcome is unknown gets its own card, warning that it may already have been
// delivered (ADR 0039 section 3).
func (c *Client) pollFailed(ctx context.Context, metas []sluice.Meta) {
	c.pruneFailed(metas)
	for _, m := range metas {
		if !failedSend(m) || c.seenFailed(m.ID) {
			continue
		}
		if _, err := c.bot.SendMessage(ctx, &bot.SendMessageParams{
			ChatID:      c.operatorID,
			Text:        formatFailed(m),
			ReplyMarkup: failedKeyboard(m.ID),
		}); err != nil {
			c.logger.Warn("telegram notify failed send failed", "id", m.ID, "err", err)
			continue
		}
		c.markFailed(m.ID, true)
	}
}

// formatFailed is a failed-send card's text. The send error can carry the
// upstream server's reply, so it is cut to a line.
func formatFailed(m sluice.Meta) string {
	what := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s", m.From, strings.Join(m.Rcpt, ", "), displaySubject(m.Subject))
	if m.OutcomeUnknown {
		return fmt.Sprintf("⚠️ OUTCOME UNKNOWN — message %s\n%s\n\n"+
			"The server got the whole message but gave no final reply, or Darbaan stopped mid re-send. "+
			"It MAY ALREADY HAVE BEEN DELIVERED. No bounce was sent. Check with the recipient before re-sending.",
			m.ID, what)
	}
	return fmt.Sprintf("Send failed — message %s\n%s\n\nError: %s\nIt is approved and stays queued until re-sent.",
		m.ID, what, truncateUTF16(oneLine(m.SendErr), 300))
}

// failedKeyboard is the card's single Re-send button. For a message whose
// outcome is unknown it opens the confirmation instead of sending.
func failedKeyboard(id string) models.InlineKeyboardMarkup {
	return models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "Re-send", CallbackData: cbResend + id}},
	}}
}

// confirmKeyboard is the second step for a message that may already have been
// delivered: re-send anyway, acknowledging it, or go back.
func confirmKeyboard(id string) models.InlineKeyboardMarkup {
	return models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "Re-send anyway (may duplicate)", CallbackData: cbResendAck + id}},
		{{Text: "« Back", CallbackData: cbResendBack + id}},
	}}
}

// handleResend is the card's Re-send button. A message whose outcome is
// unknown gets the confirmation keyboard rather than a send; the service's
// own refusal (the outcome became unknown after the card was posted) does
// the same.
func (c *Client) handleResend(ctx context.Context, b *bot.Bot, update *models.Update) {
	cq := update.CallbackQuery
	if !c.isOperator(cq) {
		c.denyCallback(ctx, b, cq)
		return
	}
	id := strings.TrimPrefix(cq.Data, cbResend)
	if c.outcomeUnknown(ctx, id) {
		c.askToConfirm(ctx, b, cq, id)
		return
	}
	out, err := c.admin.ReSend(ctx, id, false)
	if errors.Is(err, admin.ErrAckRequired) {
		c.askToConfirm(ctx, b, cq, id)
		return
	}
	c.finishResend(ctx, b, cq, id, out, err)
}

// handleResendAck re-sends a message whose outcome is unknown, acknowledging
// that a copy may already have been delivered.
func (c *Client) handleResendAck(ctx context.Context, b *bot.Bot, update *models.Update) {
	cq := update.CallbackQuery
	if !c.isOperator(cq) {
		c.denyCallback(ctx, b, cq)
		return
	}
	id := strings.TrimPrefix(cq.Data, cbResendAck)
	out, err := c.admin.ReSend(ctx, id, true)
	c.finishResend(ctx, b, cq, id, out, err)
}

// handleResendBack restores the Re-send button from the confirmation.
func (c *Client) handleResendBack(ctx context.Context, b *bot.Bot, update *models.Update) {
	cq := update.CallbackQuery
	if !c.isOperator(cq) {
		c.denyCallback(ctx, b, cq)
		return
	}
	id := strings.TrimPrefix(cq.Data, cbResendBack)
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: cq.ID})
	if msg := cq.Message.Message; msg != nil {
		_, _ = b.EditMessageReplyMarkup(ctx, &bot.EditMessageReplyMarkupParams{
			ChatID: msg.Chat.ID, MessageID: msg.ID, ReplyMarkup: failedKeyboard(id),
		})
	}
}

// askToConfirm swaps the card's keyboard for the confirmation.
func (c *Client) askToConfirm(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery, id string) {
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
		CallbackQueryID: cq.ID, Text: "It may already have been delivered. Confirm to re-send.", ShowAlert: true,
	})
	if msg := cq.Message.Message; msg != nil {
		_, _ = b.EditMessageReplyMarkup(ctx, &bot.EditMessageReplyMarkupParams{
			ChatID: msg.Chat.ID, MessageID: msg.ID, ReplyMarkup: confirmKeyboard(id),
		})
	}
}

// finishResend writes the re-send's result on the card and clears its
// buttons. A re-send already running leaves the card as it is. After any other
// attempt the card is forgotten, so a message that is still failed gets a
// fresh card on the next poll.
func (c *Client) finishResend(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery, id string, out admin.Outcome, err error) {
	if errors.Is(err, admin.ErrResendInProgress) {
		_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
			CallbackQueryID: cq.ID, Text: "A re-send of this message is already in progress.", ShowAlert: true,
		})
		return
	}
	c.finishDecision(ctx, b, cq, "Re-sent", id, out, err)
	c.markFailed(id, false)
}

// outcomeUnknown reports whether the queue lists id with an unknown outcome.
// A failed listing reports false: the service still refuses an unacknowledged
// re-send, and handleResend turns that refusal into the confirmation.
func (c *Client) outcomeUnknown(ctx context.Context, id string) bool {
	metas, err := c.admin.List(ctx)
	if err != nil {
		return false
	}
	for _, m := range metas {
		if m.ID == id {
			return m.OutcomeUnknown
		}
	}
	return false
}

// oneLine joins s onto one line.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// pruneFailed forgets cards of messages no longer failed, so a message that
// fails again later gets a new card.
func (c *Client) pruneFailed(metas []sluice.Meta) {
	live := make(map[string]bool, len(metas))
	for _, m := range metas {
		if failedSend(m) || m.ResendInProgress {
			live[m.ID] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.postedFailed {
		if !live[id] {
			delete(c.postedFailed, id)
		}
	}
}

func (c *Client) seenFailed(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.postedFailed[id]
}

func (c *Client) markFailed(id string, posted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if posted {
		c.postedFailed[id] = true
	} else {
		delete(c.postedFailed, id)
	}
}
