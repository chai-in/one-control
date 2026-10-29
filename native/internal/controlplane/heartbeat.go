package controlplane

import (
	"context"
	"net/http"
)

// Presence belongs to enrollment custody and remains available with all feature
// modules disabled. Inventory reports retain their separate optional outbox.
func (c *Client) Heartbeat(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.request(ctx, http.MethodPost, "/native-heartbeat", []byte(`{}`), true)
	return err
}
