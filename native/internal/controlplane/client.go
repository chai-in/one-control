// Package controlplane transports configuration to the existing authority and
// lifecycle owners. Transport success alone grants no package execution rights.
package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/contracts"
	"onecontrol/native/internal/lifecycle"
	"strings"
	"sync"
	"time"
)

type Client struct {
	mu         sync.Mutex
	endpoint   string
	credential string
	http       *http.Client
	transport  *http.Transport
}

// Open receives the enrollment credential and endpoint from installation
// custody. Neither is read from a downloaded catalog or package.
func Open(origin, credential string, roots *x509.CertPool) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("invalid_control_plane_origin")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(credential)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != credential {
		return nil, errors.New("invalid_native_credential")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if roots != nil {
		transport.TLSClientConfig.RootCAs = roots.Clone()
	}
	transport.ResponseHeaderTimeout = 10 * time.Second
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{endpoint: strings.TrimSuffix(u.String(), "/") + "/v1/agent/native-configuration", credential: credential, http: client, transport: transport}, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.credential = ""
	c.transport.CloseIdleConnections()
}

type response struct {
	Policy       string            `json:"policy"`
	Catalog      string            `json:"catalog"`
	Freshness    string            `json:"freshness"`
	Attestations map[string]string `json:"attestations"`
}

func envelope(encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 6<<20 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("invalid_native_response")
	}
	return raw, nil
}

// Reconcile owns a fresh challenge through transport and lifecycle admission.
// The manager persists acceptance before downloads/activation and preserves
// uncertain host outcomes. No saved response is replayed after restart.
func (c *Client) Reconcile(ctx context.Context, manager *lifecycle.Manager) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credential == "" {
		return errors.New("control_plane_closed")
	}
	challenge, err := authority.NewChallenge()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(struct {
		Nonce string `json:"nonce"`
	}{challenge.Nonce()})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("native_request_failed")
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	result, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("native_transport_failed")
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		return &HTTPError{Status: result.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(result.Body, (32<<20)+1))
	if err != nil || len(raw) > 32<<20 {
		return errors.New("invalid_native_response")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload response
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF || len(payload.Attestations) > 512 {
		return errors.New("invalid_native_response")
	}
	accepted := lifecycle.Request{Challenge: challenge, Attestations: map[string][]byte{}}
	if accepted.Policy, err = envelope(payload.Policy); err != nil {
		return err
	}
	if accepted.Catalog, err = envelope(payload.Catalog); err != nil {
		return err
	}
	if accepted.Freshness, err = envelope(payload.Freshness); err != nil {
		return err
	}
	// Decode only to index supplied evidence. The lifecycle owner subsequently
	// verifies these exact catalog/policy bytes and every selected evidence hash.
	var policyEnvelope, catalogEnvelope contracts.Envelope
	if _, err = contracts.Decode(accepted.Policy, "Envelope", &policyEnvelope); err != nil {
		return err
	}
	if _, err = contracts.Decode(accepted.Catalog, "Envelope", &catalogEnvelope); err != nil {
		return err
	}
	policyBytes, err := base64.RawURLEncoding.Strict().DecodeString(policyEnvelope.Payload)
	if err != nil {
		return err
	}
	catalogBytes, err := base64.RawURLEncoding.Strict().DecodeString(catalogEnvelope.Payload)
	if err != nil {
		return err
	}
	var policy contracts.Policy
	var catalog contracts.ModuleCatalog
	if _, err = contracts.Decode(policyBytes, "Policy", &policy); err != nil {
		return err
	}
	if _, err = contracts.Decode(catalogBytes, "ModuleCatalog", &catalog); err != nil {
		return err
	}
	for _, entry := range catalog.Entries {
		metadata, exists := entry.Platforms[policy.Platform]
		if !exists {
			continue
		}
		key := entry.Manifest.ID + "@" + entry.Manifest.Version
		if accepted.Attestations[key], err = envelope(payload.Attestations[metadata.AttestationSha256]); err != nil {
			return err
		}
	}
	accepted.Now = time.Now().Unix()
	return manager.Reconcile(ctx, accepted)
}
