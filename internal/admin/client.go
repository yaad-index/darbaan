package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// Client is a thin HTTP client for the admin API — what the `darbaan queue`
// subcommands use instead of opening the bbolt stores directly (which a running
// serve holds exclusively).
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient builds a client for the admin server at addr (host:port).
func NewClient(addr, token string) *Client {
	return &Client{base: "http://" + addr, token: token, http: &http.Client{}}
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin: %s %s: %w (is `darbaan serve` running?)", method, path, err)
	}
	return resp, nil
}

// errorFrom reads an {"error": "..."} body and returns it for a non-2xx status.
func errorFrom(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	if e.Error == "" {
		e.Error = resp.Status
	}
	return fmt.Errorf("admin: %s", e.Error)
}

// List returns the held messages' metadata.
func (c *Client) List(ctx context.Context) ([]sluice.Meta, error) {
	resp, err := c.request(ctx, http.MethodGet, "/queue", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFrom(resp)
	}
	var metas []sluice.Meta
	if err := json.NewDecoder(resp.Body).Decode(&metas); err != nil {
		return nil, err
	}
	return metas, nil
}

// Show returns the raw RFC 822 of a held message.
func (c *Client) Show(ctx context.Context, id string) ([]byte, error) {
	resp, err := c.request(ctx, http.MethodGet, "/queue/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFrom(resp)
	}
	return io.ReadAll(resp.Body)
}

// Approve approves a held message.
func (c *Client) Approve(ctx context.Context, id string) (Outcome, error) {
	return c.action(ctx, "/queue/"+id+"/approve", nil)
}

// Reject rejects a held message with a reason.
func (c *Client) Reject(ctx context.Context, id, reason string, retryable bool) (Outcome, error) {
	body, _ := json.Marshal(map[string]any{"reason": reason, "retryable": retryable})
	return c.action(ctx, "/queue/"+id+"/reject", bytes.NewReader(body))
}

// HeldList returns the inbound messages held for a human decision (ADR 0021).
func (c *Client) HeldList(ctx context.Context) ([]inbound.Message, error) {
	resp, err := c.request(ctx, http.MethodGet, "/holds", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFrom(resp)
	}
	var held []inbound.Message
	if err := json.NewDecoder(resp.Body).Decode(&held); err != nil {
		return nil, err
	}
	return held, nil
}

// Expose approves a held message for the agent to see (ADR 0021).
func (c *Client) Expose(ctx context.Context, id string) (inbound.Message, error) {
	return c.hold(ctx, "/holds/"+id+"/expose")
}

// Drop rejects a held message — it stays hidden from the agent (ADR 0021).
func (c *Client) Drop(ctx context.Context, id string) (inbound.Message, error) {
	return c.hold(ctx, "/holds/"+id+"/drop")
}

func (c *Client) hold(ctx context.Context, path string) (inbound.Message, error) {
	resp, err := c.request(ctx, http.MethodPost, path, nil)
	if err != nil {
		return inbound.Message{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return inbound.Message{}, errorFrom(resp)
	}
	var m inbound.Message
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return inbound.Message{}, err
	}
	return m, nil
}

func (c *Client) action(ctx context.Context, path string, body io.Reader) (Outcome, error) {
	resp, err := c.request(ctx, http.MethodPost, path, body)
	if err != nil {
		return Outcome{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Outcome{}, errorFrom(resp)
	}
	var out Outcome
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Outcome{}, err
	}
	return out, nil
}

// ReconcileStatus lists each inbox's reconciliation latch (ADR 0026).
func (c *Client) ReconcileStatus(ctx context.Context) ([]ReconcileStatus, error) {
	resp, err := c.request(ctx, http.MethodGet, "/reconcile", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFrom(resp)
	}
	var st []ReconcileStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return st, nil
}

// ReleaseReconcile releases a latched inbox — confirm the large retraction and
// resume reconciliation (ADR 0026).
func (c *Client) ReleaseReconcile(ctx context.Context, inbox string) (ReconcileReleaseResult, error) {
	resp, err := c.request(ctx, http.MethodPost, "/reconcile/"+inbox+"/release", nil)
	if err != nil {
		return ReconcileReleaseResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ReconcileReleaseResult{}, errorFrom(resp)
	}
	var res ReconcileReleaseResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return ReconcileReleaseResult{}, err
	}
	return res, nil
}
