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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		// A truncated read is a transport/read fault, not an empty message; classify
		// it so the caller never mistakes a short read for "the body is empty".
		return nil, fmt.Errorf("admin: read %s: %w", id, err)
	}
	return b, nil
}

// Approve approves a held message.
func (c *Client) Approve(ctx context.Context, id string) (Outcome, error) {
	return c.action(ctx, "/queue/"+id+"/approve", nil)
}

// ApproveAs approves a held message and sends it from the given inbox's identity
// (ADR 0023 slice 5).
func (c *Client) ApproveAs(ctx context.Context, id, inbox string) (Outcome, error) {
	return c.action(ctx, "/queue/"+id+"/approve-as/"+inbox, nil)
}

// ReSend retries the upstream delivery of an approved message whose previous send
// failed (C4). Only valid for a message stranded in `approved` with a send error.
func (c *Client) ReSend(ctx context.Context, id string) (Outcome, error) {
	return c.action(ctx, "/queue/"+id+"/resend", nil)
}

// Inboxes lists the configured inbox identities for the Change-sender picker
// (ADR 0023 slice 5).
func (c *Client) Inboxes(ctx context.Context) ([]InboxIdentity, error) {
	resp, err := c.request(ctx, http.MethodGet, "/inboxes", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFrom(resp)
	}
	var out []InboxIdentity
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
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

// HeldContent returns a held message's stored raw body for the operator hold
// surface (ADR 0032 change A). Its three outcomes are kept distinct so the caller
// never conflates opposite-action states: an id that is not currently held returns
// ErrNotHeld (errors.Is-able — the server signals it as a 404); a held message
// whose body has not been fetched yet returns empty bytes and no error; a transport
// or read fault returns a classified error (never a silent empty body).
func (c *Client) HeldContent(ctx context.Context, id string) ([]byte, error) {
	resp, err := c.request(ctx, http.MethodGet, "/holds/"+id+"/content", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		// Map a 404 to the typed sentinel ONLY on positive evidence that THIS service
		// produced it — the codeNotHeld marker in the body. A bare 404 from a route-less
		// daemon (version skew) or a mis-pointed peer carries no such code; it falls
		// through to the generic error the guidance routes to the tool branch, rather
		// than silently reporting every id as already-decided. The default mux 404 body
		// does not decode to a non-empty error field, so it lands here correctly.
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Code == codeNotHeld {
			return nil, ErrNotHeld
		}
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, fmt.Errorf("admin: %s", e.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errorFrom(resp)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("admin: read %s: %w", id, err)
	}
	return b, nil
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

// SyncStatus reports each fronted account's inbound-sync health (#195).
func (c *Client) SyncStatus(ctx context.Context) ([]SyncStatus, error) {
	resp, err := c.request(ctx, http.MethodGet, "/sync-status", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFrom(resp)
	}
	var st []SyncStatus
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
