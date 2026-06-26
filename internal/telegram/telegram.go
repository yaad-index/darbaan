// Package telegram is the Telegram approval client (ADR 0017): a separate,
// long-running process that bridges the operator's Telegram chat to the
// localhost-only admin API (#52). It is NOT compiled into serve; it holds only
// a bot token and an admin-API token, never the mail credentials (ADR 0002).
//
// Increment 1 connects and logs readiness only — the queue notify / approve /
// reject flow lands in later increments (#60).
package telegram

import (
	"context"
	"fmt"
	"log"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/yaad-index/darbaan/internal/admin"
)

// Client is the Telegram approval interface.
type Client struct {
	bot        *bot.Bot
	admin      *admin.Client
	operatorID int64
}

// New builds the Telegram client. The bot token is never logged; operatorID is
// the only chat/user permitted to act (everyone else is ignored); adminClient
// is the admin-API client through which verdicts are relayed. The bot is
// constructed without a network call (the connect happens in Run).
func New(token string, operatorID int64, adminClient *admin.Client) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("telegram: bot token is required (DARBAAN_TELEGRAM_TOKEN)")
	}
	if operatorID == 0 {
		return nil, fmt.Errorf("telegram: a telegram-operator-id is required (only that chat may approve/reject)")
	}
	if adminClient == nil {
		return nil, fmt.Errorf("telegram: an admin client is required")
	}
	b, err := bot.New(token, bot.WithSkipGetMe(), bot.WithDefaultHandler(ignoreUpdate))
	if err != nil {
		return nil, fmt.Errorf("telegram: init bot: %w", err)
	}
	return &Client{bot: b, admin: adminClient, operatorID: operatorID}, nil
}

// Run connects to Telegram, logs readiness, and runs the update loop until ctx
// is cancelled. Increment 1 has no queue logic — it only proves the process
// comes up as a working admin-API client.
func (c *Client) Run(ctx context.Context) error {
	me, err := c.bot.GetMe(ctx)
	if err != nil {
		return fmt.Errorf("telegram: connect: %w", err)
	}
	log.Printf("darbaan telegram: ready — bot @%s, operator %d, relaying to the admin API", me.Username, c.operatorID)
	c.bot.Start(ctx) // long-poll loop; returns when ctx is cancelled
	return nil
}

// ignoreUpdate drops incoming updates in Increment 1; notify/approve/reject
// handlers land in later increments.
func ignoreUpdate(context.Context, *bot.Bot, *models.Update) {}
