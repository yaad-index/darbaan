package telegram

import (
	"context"
	"fmt"

	"github.com/go-telegram/bot"

	"github.com/yaad-index/darbaan/internal/admin"
)

// pollReconcile lists each inbox's reconciliation latch (ADR 0026) and pushes a
// proactive alert for each inbox the safety cap has newly suspended, so the
// operator learns of a latch without polling the status surface (#149). It is the
// reconcile mirror of pollHolds: alert once per latch, and prune the dedup set
// when an inbox is no longer suspended so a re-latch after an operator release
// notifies again.
//
// Reconciliation is opt-in and off by default (ADR 0026), so the status call is
// unavailable (503) in the common config; a poll failure is logged at debug — not
// error — so it never spams every cycle when reconcile is off. A genuine serve
// outage is already surfaced loudly by poll/pollHolds.
func (c *Client) pollReconcile(ctx context.Context) {
	statuses, err := c.admin.ReconcileStatus(ctx)
	if err != nil {
		c.logger.Debug("telegram poll reconcile status failed", "err", err)
		return
	}
	c.pruneLatched(statuses)
	for _, st := range statuses {
		if !st.Suspended || c.seenLatch(st.Inbox) {
			continue
		}
		if err := c.notifyLatch(ctx, st); err != nil {
			c.logger.Warn("telegram notify reconcile latch failed", "inbox", st.Inbox, "err", err)
			continue
		}
		c.markPostedLatch(st.Inbox)
	}
}

func (c *Client) notifyLatch(ctx context.Context, st admin.ReconcileStatus) error {
	_, err := c.bot.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: c.operatorID,
		Text:   formatLatch(st),
	})
	return err
}

// formatLatch is the operator-facing latch alert. It names the inbox and the
// held-count and points at the CLI release — deliberately NOT a one-tap button,
// since releasing runs a cap-bypassed purge the operator should decide only after
// checking why the inbox latched (a legitimate source removal vs. an anomaly);
// the latch exists to force that deliberation (ADR 0026).
func formatLatch(st admin.ReconcileStatus) string {
	return fmt.Sprintf(
		"⚠️ Reconciliation held — inbox %q\n"+
			"The safety cap suspended reconciliation: %d message(s) would be retracted "+
			"(a possible source-side mass removal). Retraction is paused for this inbox "+
			"until you release it — nothing has been purged.\n"+
			"Check the source, then run:  darbaan reconcile release %s",
		st.Inbox, st.HeldCount, st.Inbox)
}

// pruneLatched drops dedup entries for inboxes that are no longer suspended, so a
// release followed by a fresh latch re-notifies (the reconcile mirror of
// prunePostedHolds).
func (c *Client) pruneLatched(statuses []admin.ReconcileStatus) {
	suspended := make(map[string]bool, len(statuses))
	for _, st := range statuses {
		if st.Suspended {
			suspended[st.Inbox] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for inbox := range c.postedLatches {
		if !suspended[inbox] {
			delete(c.postedLatches, inbox)
		}
	}
}

func (c *Client) seenLatch(inbox string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.postedLatches[inbox]
}

func (c *Client) markPostedLatch(inbox string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.postedLatches[inbox] = true
}
