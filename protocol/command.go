package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Command struct {
	ProtocolVersion   string          `json:"protocol_version"`
	CommandID         string          `json:"command_id"`
	SessionID         string          `json:"session_id,omitempty"`
	Capability        CapabilityName  `json:"capability"`
	IdempotencyKey    string          `json:"idempotency_key"`
	CancellationToken string          `json:"cancellation_token"`
	Deadline          time.Time       `json:"deadline"`
	DeliveryClass     DeliveryClass   `json:"delivery_class"`
	Payload           json.RawMessage `json:"payload"`
}

func (c Command) Validate() error {
	if err := validateProtocol(c.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("command_id", c.CommandID); err != nil {
		return err
	}
	if !validCapabilityName(c.Capability) {
		return fmt.Errorf("command capability is invalid")
	}
	if commandRequiresSession(c.Capability) && c.SessionID == "" {
		return fmt.Errorf("session_id is required for the command capability")
	}
	if c.SessionID != "" {
		if err := validateID("session_id", c.SessionID); err != nil {
			return err
		}
	}
	if err := validateTextRange("idempotency_key", c.IdempotencyKey, 16, 256); err != nil {
		return err
	}
	if err := validateTextRange("cancellation_token", c.CancellationToken, 16, 256); err != nil {
		return err
	}
	if err := validateTime("deadline", c.Deadline); err != nil {
		return err
	}
	if !validDeliveryClass(c.DeliveryClass) {
		return fmt.Errorf("command delivery class is unsupported")
	}
	if known, ok := Capability(c.Capability); ok {
		if !known.Mutating {
			return fmt.Errorf("read-only capability cannot be dispatched as a command")
		}
		if c.DeliveryClass != known.DeliveryClass {
			return fmt.Errorf("command delivery class does not match the capability")
		}
	}
	if len(c.Payload) == 0 || !json.Valid(c.Payload) {
		return fmt.Errorf("command payload is invalid")
	}
	return nil
}

func commandRequiresSession(capability CapabilityName) bool {
	value := string(capability)
	for _, prefix := range []string{"runtime.", "terminal.", "harness.", "agent.", "context.", "approval.", "artifact."} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// ValidateAgainstManifest proves that a command targets an advertised mutating
// capability with the exact delivery semantics negotiated for that provider.
func (c Command) ValidateAgainstManifest(manifest ProviderManifest) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("provider manifest is invalid")
	}
	descriptor, advertised := manifest.Capability(c.Capability)
	if !advertised {
		return NotSupported(c.Capability, manifestCapabilityNames(manifest))
	}
	if !descriptor.Mutating || descriptor.DeliveryClass != c.DeliveryClass {
		return fmt.Errorf("command does not match the advertised capability delivery contract")
	}
	return nil
}

func manifestCapabilityNames(manifest ProviderManifest) []CapabilityName {
	result := make([]CapabilityName, 0, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		result = append(result, capability.Name)
	}
	return result
}

type CommandGetResultRequest struct {
	CommandID string `json:"command_id"`
}

func (r CommandGetResultRequest) Validate() error { return validateID("command_id", r.CommandID) }

type CommandResultStatus string

const (
	CommandResultPending        CommandResultStatus = "pending"
	CommandResultSucceeded      CommandResultStatus = "succeeded"
	CommandResultFailed         CommandResultStatus = "failed"
	CommandResultOutcomeUnknown CommandResultStatus = "outcome_unknown"
)

type CommandResult struct {
	CommandID  string              `json:"command_id"`
	Status     CommandResultStatus `json:"status"`
	Result     json.RawMessage     `json:"result,omitempty"`
	Error      *Error              `json:"error,omitempty"`
	ObservedAt time.Time           `json:"observed_at"`
}

func (r CommandResult) Validate() error {
	if err := validateID("command_id", r.CommandID); err != nil {
		return err
	}
	if err := validateTime("observed_at", r.ObservedAt); err != nil {
		return err
	}
	switch r.Status {
	case CommandResultPending, CommandResultOutcomeUnknown:
		if len(r.Result) != 0 || r.Error != nil {
			return fmt.Errorf("unresolved command result cannot contain an outcome")
		}
	case CommandResultSucceeded:
		if len(r.Result) == 0 || !json.Valid(r.Result) || r.Error != nil {
			return fmt.Errorf("successful command result is invalid")
		}
		if err := rejectDuplicateKeys(r.Result); err != nil {
			return fmt.Errorf("successful command result is ambiguous")
		}
	case CommandResultFailed:
		if len(r.Result) != 0 || r.Error == nil {
			return fmt.Errorf("failed command result requires an error")
		}
		if err := r.Error.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("command result status is unsupported")
	}
	return nil
}

// CommandDigest hashes the exact persisted JSON bytes. Callers must dispatch those same bytes.
func CommandDigest(data []byte) (Digest, error) {
	if len(data) == 0 || len(data) > MaxMessageBytes || !json.Valid(data) {
		return "", protocolError(CodeInvalidArgument, "canonical command bytes are invalid")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return "", protocolError(CodeInvalidArgument, "canonical command bytes are ambiguous")
	}
	sum := sha256.Sum256(data)
	return Digest("sha256:" + hex.EncodeToString(sum[:])), nil
}
