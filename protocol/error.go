package protocol

import (
	"errors"
	"fmt"
	"time"
)

type ErrorCode string

const (
	CodeInvalidArgument   ErrorCode = "invalid_argument"
	CodeMessageTooLarge   ErrorCode = "message_too_large"
	CodeNotSupported      ErrorCode = "not_supported"
	CodeSequenceConflict  ErrorCode = "sequence_conflict"
	CodeReplay            ErrorCode = "replay"
	CodeExpired           ErrorCode = "expired"
	CodeUnauthenticated   ErrorCode = "unauthenticated"
	CodePermissionDenied  ErrorCode = "permission_denied"
	CodeConflict          ErrorCode = "conflict"
	CodeDeadlineExceeded  ErrorCode = "deadline_exceeded"
	CodeCancelled         ErrorCode = "cancelled"
	CodeResourceExhausted ErrorCode = "resource_exhausted"
	CodeUnavailable       ErrorCode = "unavailable"
	CodeOutcomeUnknown    ErrorCode = "outcome_unknown"
)

var canonicalErrorMessages = map[ErrorCode]string{
	CodeInvalidArgument:   "protocol value is invalid",
	CodeMessageTooLarge:   "protocol message exceeds its limit",
	CodeNotSupported:      "required capability is not supported",
	CodeSequenceConflict:  "event sequence conflicts with prior content",
	CodeReplay:            "one-use value was already consumed",
	CodeExpired:           "authorization or evidence has expired",
	CodeUnauthenticated:   "protocol identity or signature is not authenticated",
	CodePermissionDenied:  "operation is not authorized",
	CodeConflict:          "operation conflicts with current state",
	CodeDeadlineExceeded:  "operation deadline was exceeded",
	CodeCancelled:         "operation was cancelled",
	CodeResourceExhausted: "protocol resource limit was exhausted",
	CodeUnavailable:       "provider is unavailable",
	CodeOutcomeUnknown:    "operation outcome is unknown",
}

func (c ErrorCode) Validate() error {
	if _, supported := canonicalErrorMessages[c]; !supported {
		return fmt.Errorf("protocol error code is unsupported")
	}
	return nil
}

// Error is a structured, content-free protocol failure. Message is a closed
// canonical value so native identifiers, paths, prompts, and provider output
// cannot accidentally cross the diagnostics boundary.
type Error struct {
	Code                   ErrorCode        `json:"code"`
	Message                string           `json:"message"`
	RequiredCapability     CapabilityName   `json:"required_capability,omitempty"`
	AdvertisedCapabilities []CapabilityName `json:"advertised_capabilities,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	message, supported := canonicalErrorMessages[e.Code]
	if !supported {
		return "protocol_error"
	}
	return fmt.Sprintf("%s: %s", e.Code, message)
}

func (e Error) Validate() error {
	if err := e.Code.Validate(); err != nil {
		return err
	}
	if e.Message != canonicalErrorMessages[e.Code] {
		return fmt.Errorf("protocol error message is not canonical")
	}
	if e.Code != CodeNotSupported {
		if e.RequiredCapability != "" || len(e.AdvertisedCapabilities) != 0 {
			return fmt.Errorf("capability details are valid only for not_supported")
		}
		return nil
	}
	if !validCapabilityName(e.RequiredCapability) {
		return fmt.Errorf("required capability is invalid")
	}
	if len(e.AdvertisedCapabilities) > 256 {
		return fmt.Errorf("too many advertised capabilities")
	}
	seen := make(map[CapabilityName]struct{}, len(e.AdvertisedCapabilities))
	for _, capability := range e.AdvertisedCapabilities {
		if !validCapabilityName(capability) {
			return fmt.Errorf("advertised capability is invalid")
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("advertised capability is duplicated")
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func protocolError(code ErrorCode, _ string) error {
	message, supported := canonicalErrorMessages[code]
	if !supported {
		code = CodeInvalidArgument
		message = canonicalErrorMessages[code]
	}
	return &Error{Code: code, Message: message}
}

func IsCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.Code == code
}

func NotSupported(required CapabilityName, advertised []CapabilityName) error {
	return &Error{
		Code:                   CodeNotSupported,
		Message:                canonicalErrorMessages[CodeNotSupported],
		RequiredCapability:     required,
		AdvertisedCapabilities: append([]CapabilityName(nil), advertised...),
	}
}

type OperationStatus string

const (
	OperationAccepted       OperationStatus = "accepted"
	OperationRunning        OperationStatus = "running"
	OperationSucceeded      OperationStatus = "succeeded"
	OperationFailed         OperationStatus = "failed"
	OperationOutcomeUnknown OperationStatus = "outcome_unknown"
)

// OperationResult is a provider-local mutation result. Its identifiers and
// references are opaque and confer no canonical Mission Control authority.
type OperationResult struct {
	OperationID     NativeID        `json:"operation_id"`
	Status          OperationStatus `json:"status"`
	ObservedAt      time.Time       `json:"observed_at"`
	ResultReference string          `json:"result_reference,omitempty"`
	Error           *Error          `json:"error,omitempty"`
}

func (r OperationResult) Validate() error {
	if err := r.OperationID.Validate(); err != nil {
		return err
	}
	if err := validateTime("observed_at", r.ObservedAt); err != nil {
		return err
	}
	switch r.Status {
	case OperationAccepted, OperationRunning, OperationSucceeded, OperationOutcomeUnknown:
		if r.Error != nil {
			return fmt.Errorf("non-failed operation cannot contain an error")
		}
	case OperationFailed:
		if r.Error == nil {
			return fmt.Errorf("failed operation requires an error")
		}
		if err := r.Error.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("operation status is unsupported")
	}
	if r.ResultReference != "" {
		if err := validateOpaqueReference("result_reference", r.ResultReference); err != nil {
			return err
		}
	}
	return nil
}
