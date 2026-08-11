package telegram

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/yaad-index/darbaan/internal/assessor"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// pollHolds lists the inbound hold-for-human queue (ADR 0021) and posts each new
// held message to the operator with an [Expose] / [Drop] keyboard — the inbound
// mirror of poll. Held metadata is enough to decide; no body is fetched (it would
// trigger an on-demand upstream pull).
func (c *Client) pollHolds(ctx context.Context) {
	held, err := c.admin.HeldList(ctx)
	if err != nil {
		c.logger.Error("telegram poll holds failed", "err", err)
		return
	}
	c.prunePostedHolds(held)
	for _, m := range held {
		if c.seenHold(m.ID) {
			continue
		}
		if err := c.notifyHold(ctx, m); err != nil {
			c.logger.Warn("telegram notify hold failed", "id", m.ID, "err", err)
			continue
		}
		c.markPostedHold(m.ID)
	}
}

func (c *Client) notifyHold(ctx context.Context, m inbound.Message) error {
	// The stored body accompanies the notification, fenced, so the operator can
	// read it to judge Expose/Drop (ADR 0032 change A). A fetch failure is not
	// fatal: fall back to the metadata-only notification rather than dropping the
	// alert.
	raw, err := c.admin.HeldContent(ctx, m.ID)
	fetchFailed := err != nil
	if err != nil {
		c.logger.Warn("telegram hold content fetch failed", "id", m.ID, "err", err)
		raw = nil
	}
	_, err = c.bot.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:      c.operatorID,
		Text:        formatHold(m, raw, fetchFailed),
		ReplyMarkup: holdKeyboard(m.ID),
	})
	return err
}

// telegramTextLimit is Telegram's per-message character ceiling; the fenced body
// is truncated to keep the whole notification under it (ADR 0032 change A).
const telegramTextLimit = 4096

// holdFieldMax bounds each metadata field (from/to/subject) in a hold
// notification, so a pathological header can't push the whole message past the
// Telegram limit and fail the send — the header is budgeted, not just the fenced
// body (ADR 0032 change A).
const holdFieldMax = 300

// clampField truncates an over-long metadata field on a rune boundary.
func clampField(s string) string {
	if r := []rune(s); len(r) > holdFieldMax {
		return string(r[:holdFieldMax]) + "…"
	}
	return s
}

func formatHold(m inbound.Message, raw []byte, fetchFailed bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Held inbound message — expose to the agent?\nid: %s\nfrom: %s\nto: %s\nsubject: %s",
		m.ID, clampField(m.From), clampField(m.To), clampField(displaySubject(m.Subject)))
	// clampField the assessment line too: its summary is system-set but unbounded, so
	// leaving it out of the budget is the same header-overflow gap C13 closed on the
	// outbound side — a long line could push the message past the limit and fail every
	// send, keeping the hold off the surface.
	if line := holdAssessmentLine(m.Assessment); line != "" {
		fmt.Fprintf(&b, "\nassessment: %s", clampField(line))
	}
	// C46: the stored body could not be read (HeldContent failed). Say so explicitly
	// rather than degrading silently to a metadata-only card the operator can't
	// distinguish from "no body yet" — and on this surface the body is often the whole
	// decision (a hold placed by injection assessment). Offer a retry and map its
	// outcomes: the body is treated as unavailable only on the retry's positive
	// "held with no stored body" signal; every other failure routes to the safe branch
	// (fix the tool and look again), never to deciding blind. A failed read only proves
	// "could not read it", never "it is not there".
	if fetchFailed {
		b.WriteString("\n\n(!) body could NOT be fetched — this is not an empty message. Retry with `darbaan holds show " + m.ID +
			"`: if it shows the body, the failure was transient — proceed on what it shows. " +
			"If it reports the message is no longer held, the decision has already been made — take no action. " +
			"If it reports the message is held with no stored body, the body is genuinely unavailable — decide from the metadata above knowing you have not seen it. " +
			"If it fails any other way (cannot connect, permission denied, a server error), that is the tool or its configuration, not the message — fix it and look again before deciding; do NOT approve unseen.")
		return b.String()
	}
	// Fence the stored body so attacker text crosses to the operator as inert,
	// clearly-delimited data — never as instructions (ADR 0006 / assessor.Fence).
	// It is human-facing only and never enters an agent-consumed path. Budget the
	// body in UTF-16 units (Telegram's cap unit, C45) so the whole message (header +
	// fence framing) stays under the limit.
	if len(raw) > 0 {
		header := b.String()
		budget := telegramTextLimit - utf16Len(header) - fenceOverhead
		if body := fencedBody(raw, budget); body != "" {
			b.WriteString("\n\n")
			b.WriteString(body)
		}
	}
	return b.String()
}

// fenceOverhead is a conservative allowance for Fence's begin/end marker lines,
// the truncation marker, and the joining newlines, so the budget arithmetic never
// undershoots the real framing cost.
const fenceOverhead = 80

// holdAssessmentLine renders the injection-assessment disposition for the
// operator (ADR 0032 change A): the system-defined band/score + factors +
// sanitized summary, and for a fail-safe hold a plain "could not be assessed"
// with no band/score. It draws only on the stored, system-set fields — never any
// message content. Nil (not assessed) renders nothing.
func holdAssessmentLine(a *inbound.Assessment) string {
	if a == nil {
		return ""
	}
	if a.NotCleared {
		if a.Summary != "" {
			return "could not be assessed — " + a.Summary
		}
		return "could not be assessed (held fail-safe)"
	}
	line := fmt.Sprintf("%s risk, score %d", a.Band, a.Score)
	if len(a.Factors) > 0 {
		line += " [" + strings.Join(a.Factors, ", ") + "]"
	}
	if a.Summary != "" {
		line += " — " + a.Summary
	}
	return line
}

// fencedBody truncates the raw body to the UTF-16 budget (marking the cut) and
// wraps it in an untrusted fence. A non-positive budget yields no body.
func fencedBody(raw []byte, budget int) string {
	if budget <= 0 {
		return ""
	}
	text := string(raw)
	if utf16Len(text) > budget {
		text = truncateUTF16(text, budget) + "\n[truncated]"
	}
	return assessor.Fence("email body", text)
}

func holdKeyboard(id string) models.InlineKeyboardMarkup {
	return models.InlineKeyboardMarkup{
		InlineKeyboard: [][]models.InlineKeyboardButton{
			{
				{Text: "Expose", CallbackData: cbExpose + id},
				{Text: "Drop", CallbackData: cbDrop + id},
			},
		},
	}
}

// handleExpose is the [Expose] button: verify the operator, confirm it's still
// held, expose it to the agent, and rewrite the notification.
func (c *Client) handleExpose(ctx context.Context, b *bot.Bot, update *models.Update) {
	cq := update.CallbackQuery
	if !c.isOperator(cq) {
		c.denyCallback(ctx, b, cq)
		return
	}
	id := strings.TrimPrefix(cq.Data, cbExpose)
	if !c.guardHeld(ctx, b, cq, id) {
		return
	}
	_, err := c.admin.Expose(ctx, id)
	c.finishHold(ctx, b, cq, "Exposed", id, err)
}

// handleDrop is the [Drop] button: keep the message hidden from the agent.
func (c *Client) handleDrop(ctx context.Context, b *bot.Bot, update *models.Update) {
	cq := update.CallbackQuery
	if !c.isOperator(cq) {
		c.denyCallback(ctx, b, cq)
		return
	}
	id := strings.TrimPrefix(cq.Data, cbDrop)
	if !c.guardHeld(ctx, b, cq, id) {
		return
	}
	_, err := c.admin.Drop(ctx, id)
	c.finishHold(ctx, b, cq, "Dropped", id, err)
}

// guardHeld pre-checks that a tapped message is still awaiting a decision, so a
// stale tap on an already-decided hold is explained rather than silently flipping
// the decision (there is no reconsider/undo in v1 — a deferred follow-up). It
// returns true to proceed; on a lookup error it proceeds (acting is idempotent
// for the live case).
func (c *Client) guardHeld(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery, id string) bool {
	held, err := c.admin.HeldList(ctx)
	if err != nil {
		return true // can't look up — let the action run (re-setting the same decision is harmless)
	}
	for _, m := range held {
		if m.ID == id {
			return true
		}
	}
	msg := fmt.Sprintf("Message %s: already decided or gone", id)
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
		CallbackQueryID: cq.ID, Text: msg, ShowAlert: true,
	})
	if m := cq.Message.Message; m != nil {
		c.editResult(ctx, b, m.Chat.ID, m.ID, msg)
	}
	return false
}

// finishHold dismisses the spinner and rewrites the notification to the outcome,
// clearing the keyboard so the decided hold can't be tapped again.
func (c *Client) finishHold(ctx context.Context, b *bot.Bot, cq *models.CallbackQuery, verb, id string, err error) {
	_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: cq.ID, Text: verb})
	if msg := cq.Message.Message; msg != nil {
		c.editResult(ctx, b, msg.Chat.ID, msg.ID, holdResult(verb, id, err))
	}
}

func holdResult(verb, id string, err error) string {
	if err != nil {
		return fmt.Sprintf("%s failed (%s): %v", verb, id, err)
	}
	if verb == "Exposed" {
		return fmt.Sprintf("Exposed %s — now visible to the agent", id)
	}
	return fmt.Sprintf("Dropped %s — stays hidden from the agent", id)
}

// prunePostedHolds drops de-dup entries for holds no longer awaiting a decision,
// bounding the set to the live held queue.
func (c *Client) prunePostedHolds(held []inbound.Message) {
	live := make(map[string]bool, len(held))
	for _, m := range held {
		live[m.ID] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.postedHolds {
		if !live[id] {
			delete(c.postedHolds, id)
		}
	}
}

func (c *Client) seenHold(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.postedHolds[id]
}

func (c *Client) markPostedHold(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.postedHolds[id] = true
}
