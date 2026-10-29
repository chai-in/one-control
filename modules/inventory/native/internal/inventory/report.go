package inventory

import (
	"context"
	"encoding/json"
	"time"
)

const (
	SchemaVersion               = 1
	MaximumJSONBytes            = 4096
	MaximumExactInteger  uint64 = 1<<53 - 1
	maximumHostnameBytes        = 253
)

type Status string

const (
	Available   Status = "available"
	Unavailable Status = "unavailable"
	Unsupported Status = "unsupported"
)

type Reason string

const (
	NoReason              Reason = ""
	PlatformUnsupported   Reason = "platform_unsupported"
	OutsideCollectorScope Reason = "outside_collector_scope"
	ProcedureUnavailable  Reason = "procedure_unavailable"
	QueryFailed           Reason = "query_failed"
	InvalidResult         Reason = "invalid_result"
)

type Observation[T any] struct {
	Status Status `json:"status"`
	Reason Reason `json:"reason,omitempty"`
	Value  *T     `json:"value,omitempty"`
}

type Architecture string

const (
	X86   Architecture = "x86"
	X64   Architecture = "x64"
	ARM32 Architecture = "arm32"
	ARM64 Architecture = "arm64"
	IA64  Architecture = "ia64"
)

type WindowsVersion struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
	Build uint32 `json:"build"`
}

type CPUTopology struct {
	ActiveLogicalProcessors uint32 `json:"activeLogicalProcessors"`
	ActiveProcessorGroups   uint16 `json:"activeProcessorGroups"`
}

type PhysicalMemory struct {
	TotalBytes     uint64 `json:"totalBytes"`
	AvailableBytes uint64 `json:"availableBytes"`
}

type NoValue struct{}

type Report struct {
	SchemaVersion                 uint32                      `json:"schemaVersion"`
	CollectedAt                   time.Time                   `json:"collectedAt"`
	Hostname                      Observation[string]         `json:"hostname"`
	OSVersion                     Observation[WindowsVersion] `json:"osVersion"`
	NativeArchitecture            Observation[Architecture]   `json:"nativeArchitecture"`
	ProcessArchitecture           Observation[Architecture]   `json:"processArchitecture"`
	CPU                           Observation[CPUTopology]    `json:"cpu"`
	Memory                        Observation[PhysicalMemory] `json:"memory"`
	ElapsedSinceStartMilliseconds Observation[uint64]         `json:"elapsedSinceStartMilliseconds"`
	ServerContact                 Observation[NoValue]        `json:"serverContact"`
	BootIdentity                  Observation[NoValue]        `json:"bootIdentity"`
	PowerState                    Observation[NoValue]        `json:"powerState"`
}

type ValidationCode string

const (
	CodeInvalidSchema       ValidationCode = "invalid_schema"
	CodeInvalidTimestamp    ValidationCode = "invalid_timestamp"
	CodeInvalidObservation  ValidationCode = "invalid_observation"
	CodeInvalidHostname     ValidationCode = "invalid_hostname"
	CodeInvalidVersion      ValidationCode = "invalid_version"
	CodeInvalidArchitecture ValidationCode = "invalid_architecture"
	CodeInvalidCPU          ValidationCode = "invalid_cpu"
	CodeInvalidMemory       ValidationCode = "invalid_memory"
	CodeInvalidElapsed      ValidationCode = "invalid_elapsed"
	CodeInvalidScope        ValidationCode = "invalid_scope"
	CodePayloadLimit        ValidationCode = "payload_limit"
)

type ValidationError struct{ Code ValidationCode }

func (e ValidationError) Error() string { return string(e.Code) }

func Validate(r Report) error {
	if r.SchemaVersion != SchemaVersion {
		return ValidationError{CodeInvalidSchema}
	}
	if r.CollectedAt.IsZero() || r.CollectedAt.Location() != time.UTC || r.CollectedAt.Year() < 1 || r.CollectedAt.Year() > 9999 {
		return ValidationError{CodeInvalidTimestamp}
	}
	checks := []error{
		validateObservation(r.Hostname, validHostname, CodeInvalidHostname),
		validateObservation(r.OSVersion, validVersion, CodeInvalidVersion),
		validateObservation(r.NativeArchitecture, validArchitecture, CodeInvalidArchitecture),
		validateObservation(r.ProcessArchitecture, validArchitecture, CodeInvalidArchitecture),
		validateObservation(r.CPU, validCPU, CodeInvalidCPU),
		validateObservation(r.Memory, validMemory, CodeInvalidMemory),
		validateObservation(r.ElapsedSinceStartMilliseconds, validElapsed, CodeInvalidElapsed),
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	for _, o := range []Observation[NoValue]{r.ServerContact, r.BootIdentity, r.PowerState} {
		if o.Status != Unsupported || o.Reason != OutsideCollectorScope || o.Value != nil {
			return ValidationError{CodeInvalidScope}
		}
	}
	return nil
}

func validateObservation[T any](o Observation[T], valid func(T) bool, code ValidationCode) error {
	switch o.Status {
	case Available:
		if o.Value == nil || o.Reason != NoReason {
			return ValidationError{CodeInvalidObservation}
		}
		if !valid(*o.Value) {
			return ValidationError{code}
		}
	case Unavailable:
		if o.Value != nil || (o.Reason != ProcedureUnavailable && o.Reason != QueryFailed && o.Reason != InvalidResult) {
			return ValidationError{CodeInvalidObservation}
		}
	case Unsupported:
		if o.Value != nil || o.Reason != PlatformUnsupported {
			return ValidationError{CodeInvalidObservation}
		}
	default:
		return ValidationError{CodeInvalidObservation}
	}
	return nil
}

func (r Report) MarshalJSON() ([]byte, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}
	type wireReport Report
	payload, err := json.Marshal(wireReport(r))
	if err != nil {
		return nil, ValidationError{CodeInvalidTimestamp}
	}
	if len(payload) > MaximumJSONBytes {
		return nil, ValidationError{CodePayloadLimit}
	}
	return payload, nil
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > maximumHostnameBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validVersion(v WindowsVersion) bool { return v.Major != 0 && v.Build != 0 }
func validArchitecture(a Architecture) bool {
	switch a {
	case X86, X64, ARM32, ARM64, IA64:
		return true
	}
	return false
}
func validCPU(c CPUTopology) bool {
	return c.ActiveProcessorGroups != 0 && c.ActiveLogicalProcessors >= uint32(c.ActiveProcessorGroups)
}
func validMemory(m PhysicalMemory) bool {
	return m.TotalBytes != 0 && m.TotalBytes <= MaximumExactInteger && m.AvailableBytes <= m.TotalBytes
}
func validElapsed(v uint64) bool { return v <= MaximumExactInteger }

func available[T any](v T) Observation[T] { return Observation[T]{Status: Available, Value: &v} }
func unavailable[T any](r Reason) Observation[T] {
	return Observation[T]{Status: Unavailable, Reason: r}
}
func platformUnsupported[T any]() Observation[T] {
	return Observation[T]{Status: Unsupported, Reason: PlatformUnsupported}
}

func initialReport(at time.Time) Report {
	outside := Observation[NoValue]{Status: Unsupported, Reason: OutsideCollectorScope}
	return Report{SchemaVersion: SchemaVersion, CollectedAt: at, ServerContact: outside, BootIdentity: outside, PowerState: outside}
}

// Collect reads a fixed local allowlist. Cancellation discards the entire report.
func Collect(ctx context.Context) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return collectPlatform(ctx, time.Now().UTC())
}
