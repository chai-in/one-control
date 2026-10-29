package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"onecontrol/native/internal/contracts"

	"onecontrol/native/internal/lifecycle"
	"onecontrol/native/internal/ownership"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type reportRecord struct {
	Enrollment   string `json:"enrollment"`
	Sequence     string `json:"sequence"`
	Payload      []byte `json:"payload"`
	Digest       string `json:"digest"`
	Acknowledged bool   `json:"acknowledged"`
}

// ReportOutbox persists one pending report before transmission. The installation
// owner supplies a protected directory; checksums detect damage, not tampering.
type ReportOutbox struct {
	mu         sync.Mutex
	path       string
	enrollment string
	owner      *ownership.Owner
	state      *reportRecord
	poisoned   bool
}

func OpenReportOutbox(ctx context.Context, path, enrollment string) (*ReportOutbox, error) {
	if !filepath.IsAbs(path) || enrollment == "" {
		return nil, errors.New("invalid_report_store")
	}
	owner, err := ownership.Acquire(ctx, path+".lock")
	if err != nil {
		return nil, err
	}
	out := &ReportOutbox{path: path, enrollment: enrollment, owner: owner}
	if err = out.load(); err != nil {
		owner.Close()
		return nil, err
	}
	return out, nil
}
func (o *ReportOutbox) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.owner == nil {
		return nil
	}
	err := o.owner.Close()
	o.owner = nil
	return err
}
func reportDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (o *ReportOutbox) load() error {
	file, err := os.Open(o.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	for {
		var size [4]byte
		_, err = io.ReadFull(file, size[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("report_store_incomplete")
		}
		n := binary.BigEndian.Uint32(size[:])
		if n == 0 || n > 32768 {
			return errors.New("report_store_invalid")
		}
		raw := make([]byte, n)
		var digest [32]byte
		if _, err = io.ReadFull(file, raw); err != nil {
			return errors.New("report_store_incomplete")
		}
		if _, err = io.ReadFull(file, digest[:]); err != nil || sha256.Sum256(raw) != digest {
			return errors.New("report_store_invalid")
		}
		var record reportRecord
		if json.Unmarshal(raw, &record) != nil || record.Enrollment != o.enrollment || reportDigest(record.Payload) != record.Digest {
			return errors.New("report_store_invalid")
		}
		sequence, err := strconv.ParseUint(record.Sequence, 10, 64)
		if err != nil || sequence == 0 {
			return errors.New("report_store_invalid")
		}
		if o.state == nil {
			if sequence != 1 || record.Acknowledged {
				return errors.New("report_store_invalid")
			}
		} else {
			previous, _ := strconv.ParseUint(o.state.Sequence, 10, 64)
			if o.state.Acknowledged {
				if previous == ^uint64(0) || sequence != previous+1 || record.Acknowledged {
					return errors.New("report_store_invalid")
				}
			} else if sequence != previous || !record.Acknowledged || record.Digest != o.state.Digest {
				return errors.New("report_store_invalid")
			}
		}
		o.state = &record
	}
}
func (o *ReportOutbox) append(record reportRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(raw)))
	frame = append(frame, raw...)
	sum := sha256.Sum256(raw)
	frame = append(frame, sum[:]...)
	file, err := os.OpenFile(o.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	n, err := file.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		o.poisoned = true
		return err
	}
	o.state = &record
	return nil
}

type reportPayload struct {
	Sequence      string          `json:"sequence"`
	PolicyDigest  string          `json:"policyDigest"`
	Kind          string          `json:"kind"`
	ModuleVersion string          `json:"moduleVersion,omitempty"`
	Report        json.RawMessage `json:"report,omitempty"`
}
type reportState struct {
	EnrollmentID string          `json:"enrollmentId"`
	Sequence     string          `json:"sequence"`
	Digest       *string         `json:"digest"`
	Response     json.RawMessage `json:"response"`
}

func (c *Client) reportRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.endpoint, "/native-configuration")+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("native_request_failed")
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("native_transport_failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("native_report_rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, errors.New("invalid_report_response")
	}
	return raw, nil
}

// Report sends metadata or a caller-provided inventory from the selected module.
// It does not collect inventory itself. A lost acknowledgment is recovered by
// comparing the server receipt before sending anything again.
func (c *Client) Report(ctx context.Context, manager *lifecycle.Manager, outbox *ReportOutbox, observed json.RawMessage) error {
	return c.report(ctx, manager, outbox, observed, "")
}

// CollectInventory invokes only the selected inventory host. The result keeps
// its collection-time policy binding through durable outbox admission.
func (c *Client) CollectInventory(ctx context.Context, manager *lifecycle.Manager, outbox *ReportOutbox) error {
	result, err := manager.Invoke(ctx, "inventory", "inventory.read", "inventory.scan", nil)
	if err != nil {
		return err
	}
	return c.report(ctx, manager, outbox, json.RawMessage(result.Payload), result.PolicyDigest)
}

func (c *Client) report(ctx context.Context, manager *lifecycle.Manager, outbox *ReportOutbox, observed json.RawMessage, observedPolicy string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if c.credential == "" || outbox.owner == nil || outbox.poisoned {
		return errors.New("report_store_unavailable")
	}
	snapshot := manager.Snapshot()
	if snapshot == nil {
		return errors.New("native_policy_unavailable")
	}
	if observedPolicy != "" && observedPolicy != snapshot.Checkpoint.PolicyDigest {
		return errors.New("observation_policy_changed")
	}
	envelopeBytes, err := base64.RawURLEncoding.DecodeString(snapshot.PolicyEnvelope)
	if err != nil {
		return err
	}
	var envelope contracts.Envelope
	if _, err = contracts.Decode(envelopeBytes, "Envelope", &envelope); err != nil {
		return err
	}
	policyBytes, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return err
	}
	var policy contracts.Policy
	if _, err = contracts.Decode(policyBytes, "Policy", &policy); err != nil {
		return err
	}
	if policy.EnrollmentID != outbox.enrollment {
		return errors.New("report_enrollment_mismatch")
	}
	stateRaw, err := c.reportRequest(ctx, http.MethodGet, "/native-report-state", nil)
	if err != nil {
		return err
	}
	var remote reportState
	if json.Unmarshal(stateRaw, &remote) != nil || remote.EnrollmentID != outbox.enrollment {
		return errors.New("invalid_report_response")
	}
	// Never silently advance a restored or deleted local counter to server state.
	previous := "0"
	if outbox.state != nil {
		previous = outbox.state.Sequence
	}
	if outbox.state != nil && !outbox.state.Acknowledged && remote.Sequence == previous && remote.Digest != nil && *remote.Digest == outbox.state.Digest {
		ack := *outbox.state
		ack.Acknowledged = true
		return outbox.append(ack)
	}
	if outbox.state != nil && !outbox.state.Acknowledged {
		number, _ := strconv.ParseUint(previous, 10, 64)
		if remote.Sequence != strconv.FormatUint(number-1, 10) {
			return errors.New("report_counter_conflict")
		}
	} else {
		if remote.Sequence != previous {
			return errors.New("report_counter_conflict")
		}
		if outbox.state != nil && (remote.Digest == nil || *remote.Digest != outbox.state.Digest) {
			return errors.New("report_counter_conflict")
		}
		number, _ := strconv.ParseUint(previous, 10, 64)
		if number == ^uint64(0) {
			return errors.New("report_counter_exhausted")
		}
		payload := reportPayload{Sequence: strconv.FormatUint(number+1, 10), PolicyDigest: snapshot.Checkpoint.PolicyDigest, Kind: "heartbeat"}
		if observed != nil {
			payload.Kind = "inventory"
			payload.ModuleVersion = policy.Enabled["inventory"]
			payload.Report = observed
			if payload.ModuleVersion == "" {
				return errors.New("inventory_not_selected")
			}
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if err = outbox.append(reportRecord{Enrollment: outbox.enrollment, Sequence: payload.Sequence, Payload: raw, Digest: reportDigest(raw)}); err != nil {
			return err
		}
	}
	pending := outbox.state
	var payload reportPayload
	if json.Unmarshal(pending.Payload, &payload) != nil {
		return errors.New("report_store_invalid")
	}
	if payload.PolicyDigest != snapshot.Checkpoint.PolicyDigest {
		return errors.New("pending_report_policy_changed")
	}
	raw, err := c.reportRequest(ctx, http.MethodPost, "/native-report", pending.Payload)
	if err != nil {
		return err
	}
	var receipt struct {
		Sequence     string `json:"sequence"`
		EnrollmentID string `json:"enrollmentId"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Sequence != pending.Sequence || receipt.EnrollmentID != outbox.enrollment {
		return errors.New("invalid_report_response")
	}
	ack := *pending
	ack.Acknowledged = true
	return outbox.append(ack)
}
