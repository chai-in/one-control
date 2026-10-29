package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"onecontrol/native/internal/contracts"
)

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("control_plane_http_%d", e.Status) }

type Enrollment struct {
	DeviceID     string          `json:"deviceId"`
	EnrollmentID string          `json:"enrollmentId"`
	Platform     string          `json:"platform"`
	Scope        contracts.Scope `json:"scope"`
}

func CredentialHash(credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(digest[:])
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, authenticate bool) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.endpoint, "/native-configuration")+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("native_request_failed")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if authenticate {
		request.Header.Set("Authorization", "Bearer "+c.credential)
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("native_transport_failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return nil, &HTTPError{response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, errors.New("invalid_native_response")
	}
	return raw, nil
}

func decodeEnrollment(raw []byte) (Enrollment, error) {
	var result Enrollment
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.DeviceID == "" || result.EnrollmentID == "" || result.Scope.Kind != "machine" || result.Scope.MachineID == "" {
		return result, errors.New("invalid_enrollment_response")
	}
	return result, nil
}

// Enroll is sent once by the installation owner after the credential and
// submission intent are durable. A lost response is resolved with Enrollment.
func (c *Client) Enroll(ctx context.Context, token string) (Enrollment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	body, _ := json.Marshal(struct {
		Token          string `json:"token"`
		CredentialHash string `json:"credentialHash"`
	}{token, CredentialHash(c.credential)})
	raw, err := c.request(ctx, http.MethodPost, "/native-enroll", body, false)
	if err != nil {
		return Enrollment{}, err
	}
	return decodeEnrollment(raw)
}

func (c *Client) Enrollment(ctx context.Context) (Enrollment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, err := c.request(ctx, http.MethodGet, "/native-enrollment", nil, true)
	if err != nil {
		return Enrollment{}, err
	}
	return decodeEnrollment(raw)
}

// Rotate receives a replacement already saved by the credential owner.
func (c *Client) Rotate(ctx context.Context, credentialHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	body, _ := json.Marshal(struct {
		CredentialHash string `json:"credentialHash"`
	}{credentialHash})
	_, err := c.request(ctx, http.MethodPost, "/native-credentials/rotate", body, true)
	return err
}
