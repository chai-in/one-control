package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"onecontrol/native/internal/packages"
	"time"
)

// artifactURL is called by delivery while Reconcile owns the client mutex.
// The returned capability is short lived and never persisted in the catalog.
func (c *Client) artifactURL(ctx context.Context, artifact packages.Approval) (string, error) {
	payload, _ := json.Marshal(map[string]string{"id": artifact.ID, "version": artifact.Version, "sha256": artifact.SHA256})
	raw, err := c.request(ctx, http.MethodPost, "/native-artifact-ticket", payload, true)
	if err != nil {
		return "", err
	}
	var ticket struct {
		URL       string    `json:"url"`
		SHA256    string    `json:"sha256"`
		Size      int64     `json:"size"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if json.Unmarshal(raw, &ticket) != nil || ticket.SHA256 != artifact.SHA256 || ticket.Size != artifact.Size || !time.Now().Before(ticket.ExpiresAt) || ticket.ExpiresAt.After(time.Now().Add(2*time.Minute)) {
		return "", errors.New("invalid_artifact_ticket")
	}
	return ticket.URL, nil
}

// ResolveArtifactURL is an installation-owned callback; it is used only inside
// the serialized reconciliation operation, never by a feature process.
func (c *Client) ResolveArtifactURL(ctx context.Context, artifact packages.Approval) (string, error) {
	return c.artifactURL(ctx, artifact)
}
