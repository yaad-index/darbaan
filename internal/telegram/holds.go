package telegram

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/yaad-index/darbaan/internal/assessor"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/mailtext"
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
		fmt.Fprintf(&b, "\nwhy: %s", clampField(line))
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
// operator in terms they can act on (#262): the system-defined band/score plus a
// plain-language gloss of WHAT each flagged factor means, not the internal factor
// identifiers. For a fail-safe hold it is a plain "could not be assessed". It
// draws only on the stored, system-set fields (band, score, factor names) — never
// any message content. Nil (not assessed) renders nothing.
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
	// Band + score in operator terms, then the trust caveat (if any), then the factor
	// glosses. Two things drive the content and the order:
	//   - The factor identifiers ("secrets_request") named the rule that fired without
	//     saying what it means, so they are replaced by a fixed gloss (glossFactors); the
	//     rest of the stored summary is dropped, it only restated those identifiers.
	//   - EXCEPT the summary's truncation caveat, which is not a restatement but a
	//     statement of how far the score can be trusted (it was computed on partial
	//     content). It is kept here rather than left to the fenced-body section, because
	//     the degraded cards (fetch-failed, no readable body) return before that section,
	//     so this line is the only place it survives on those paths — exactly the cards
	//     where the operator cannot read the body to judge for themselves (#262, review).
	// The caveat goes AHEAD of the gloss clauses so that if this line is ever clamped
	// (clampField, 300 runes) the enumerable factor detail is truncated first and the
	// trust qualifier stays anchored: a shortened factor list is degraded information, a
	// dropped "scored on partial content" is misleading — the precise failure this change
	// exists to fix, which must not be re-armed by later prose growth (review).
	//
	// The caveat is driven by the stored structured flag (a.Truncated), computed once
	// at ingest, so the render no longer depends on the summary prose for records this
	// version wrote — a reword of the note cannot drop it. Records persisted before the
	// flag existed carry a nil flag; for that legacy cohort only, assessmentTruncated
	// falls back to matching the assessor's exported constant in the stored summary, so
	// the caveat still survives on old partial-content cards (#280).
	line := fmt.Sprintf("%s risk (%d)", a.Band, a.Score)
	if assessmentTruncated(a) {
		line += " — scored on partial content (message was truncated during extraction)"
	}
	if reason := glossFactors(a.Factors); reason != "" {
		line += " — " + reason
	}
	return line
}

// assessmentTruncated reports whether the score was computed on partial content.
// It reads the structured flag as authoritative when present (a record this version
// wrote), and only falls back to the summary prose for the legacy cohort whose
// records predate the flag (a.Truncated nil) — the state a plain bool could not
// represent, which is why the stored field is a pointer (#280). A non-nil false is
// therefore honoured as "not truncated" without consulting the prose, so a new
// record never depends on the summary wording.
func assessmentTruncated(a *inbound.Assessment) bool {
	if a.Truncated != nil {
		return *a.Truncated
	}
	return strings.Contains(a.Summary, assessor.TruncationNote)
}

// factorGloss maps each system-defined risk factor to one operator-facing clause
// explaining what the system thinks the message is doing. The clauses carry the
// only scope distinction that changes operator caution — content in an attachment
// versus inline — because in v1 a factor's match scope is fixed by its rule, so
// the scope rides on the factor's identity (an explicit per-match scope field
// would be a detector-contract and stored-schema change, tracked separately).
// Keyed by the string form of riskscore.Factor so the renderer needs no import of
// the scorer's constants.
var factorGloss = map[string]string{
	"instruction_to_reader": "contains instructions directed at the reader",
	"secrets_request":       "asks the reader to send or confirm a credential",
	"hidden_directives":     "contains instructions hidden from view",
	"attachment_directives": "an attachment carries instructions directed at the reader",
}

// glossFactors renders the flagged factors as a semicolon-joined list of
// plain-language clauses. A factor with no gloss (e.g. one an operator added to
// the point-table) falls back to its raw name rather than being silently dropped —
// an unexplained flag is better than a hidden one.
func glossFactors(factors []string) string {
	if len(factors) == 0 {
		return ""
	}
	clauses := make([]string, 0, len(factors))
	for _, f := range factors {
		if g, ok := factorGloss[f]; ok {
			clauses = append(clauses, g)
		} else {
			clauses = append(clauses, f)
		}
	}
	return strings.Join(clauses, "; ")
}

// fencedBody renders the stored message for the operator card: the DECODED text of
// the message, never the raw message source.
//
// Why extraction at all. Fencing string(raw) spent the entire budget on transport
// headers — Received, ARC-Seal, DKIM-Signature — and truncated before a single
// human-readable line, so the operator was asked to Expose or Drop a message whose
// content they had never actually seen. On an injection-assessed hold the body IS
// the decision, so an unreadable card is not a cosmetic problem.
//
// Why THIS extractor. mailtext is what the assessor consumes, so the operator reads
// the text the detector actually scored rather than a separately derived rendering
// that could quietly disagree with the verdict being judged. It also flattens
// text/html, so an HTML-only message stays readable here.
//
// That correspondence currently holds because both call sites use the package
// defaults, NOT because anything ties them together: the screening path takes its
// limits through an option that merely defaults to them. Today the option is
// test-only, so there is no live divergence, but if a caller ever overrides the
// screening limits this stops being the same view and the claim above weakens to
// "the same extractor, possibly different bounds".
//
// The no-text case is always stated, never silent. Falling back to raw source would
// reinstate the defect, and rendering nothing would read as "the message is empty" —
// the exact misrepresentation this surface exists to prevent.
func fencedBody(raw []byte, budget int) string {
	if budget <= 0 || len(raw) == 0 {
		return ""
	}
	c, err := mailtext.Extract(raw, mailtext.DefaultLimits())
	text := strings.TrimRight(c.Body, " \t\r\n")

	// Undecodable means text the message carries never reached the assessor, so the
	// verdict cannot vouch for it. That bears directly on the decision being made and
	// is surfaced even when readable text was recovered alongside it.
	var note string
	if err != nil || c.Undecodable {
		note = "\n\n(!) part of this message could not be decoded, so it was never scored — the assessment above cannot account for it; treat it as incomplete."
	}

	// This return bypasses the budget, which is safe on stated grounds rather than by
	// accident: the string is fixed apart from a byte count, so it is bounded at a few
	// hundred units, and the header it joins is already clamped per field. It is the
	// same shape as the marker overflow above, so the grounds are written down rather
	// than left for a later reader to re-derive — if this text ever grows, or the
	// header stops being clamped, it has to come out of the budget like everything else.
	if text == "" {
		reason := "it has no readable text part"
		if err != nil || c.Undecodable {
			reason = "its content could not be decoded"
		}
		return fmt.Sprintf("(!) no message text is shown because %s — this is NOT an empty message. "+
			"The raw source is %d bytes; dump it with `darbaan holds show <id>` (add --text for the decoded body). "+
			"Do not read the absence of text here as the message having no content.", reason, len(raw))
	}

	// Every string appended after this point has to come out of the budget, not out of
	// the framing allowance. fenceOverhead covers the fence's own markers and the
	// joining newlines with only a few units to spare, so an appended marker that is
	// not subtracted here pushes the whole card past the Telegram ceiling. That is not
	// a cosmetic overflow: the send is rejected, the hold is never marked posted, and
	// every later poll rebuilds the identical oversized card — so the message stays
	// held but the operator is never told it exists, on the surface whose entire
	// purpose is telling them. Reserve the width up front instead of widening the
	// allowance, which would only leave the next marker to rediscover this.
	const extractionCapped = "\n[extraction limit reached — the message carries more text than was scored]"
	budget -= utf16Len(note)
	if c.Truncated {
		budget -= utf16Len(extractionCapped)
	}
	if budget <= 0 {
		return strings.TrimPrefix(note, "\n\n")
	}
	if utf16Len(text) > budget {
		text = truncateUTF16(text, budget) + "\n[truncated]"
	}
	if c.Truncated {
		// Not budget truncation — extraction itself hit its caps (size, part count or
		// depth), so the message carries more text than was ever extracted, and more than
		// was ever scored. Distinct from "[truncated]", which means it did not fit here.
		text += extractionCapped
	}
	return assessor.Fence("email body", text) + note
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
