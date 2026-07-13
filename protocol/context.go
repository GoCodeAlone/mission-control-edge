package protocol

import (
	"encoding/json"
	"fmt"
	"time"
)

type ContextDeliveryMode string

const (
	ContextModeInitialPrompt        ContextDeliveryMode = "initial_prompt"
	ContextModeSystemInstructions   ContextDeliveryMode = "system_instructions"
	ContextModeMountedFile          ContextDeliveryMode = "mounted_file"
	ContextModeEnvironmentReference ContextDeliveryMode = "environment_reference"
	ContextModeMCPResource          ContextDeliveryMode = "mcp_resource"
	ContextModeACPInitialization    ContextDeliveryMode = "acp_initialization"
	ContextModeProjectInstructions  ContextDeliveryMode = "project_instructions"
	ContextModeFollowUpMessage      ContextDeliveryMode = "follow_up_message"
)

func (m ContextDeliveryMode) Validate() error {
	switch m {
	case ContextModeInitialPrompt, ContextModeSystemInstructions, ContextModeMountedFile,
		ContextModeEnvironmentReference, ContextModeMCPResource, ContextModeACPInitialization,
		ContextModeProjectInstructions, ContextModeFollowUpMessage:
		return nil
	default:
		return fmt.Errorf("context delivery mode is unsupported")
	}
}

type ContextDeliveryStatus string

const (
	ContextDeliveryAccepted ContextDeliveryStatus = "accepted"
	ContextDeliveryRejected ContextDeliveryStatus = "rejected"
	ContextDeliveryFailed   ContextDeliveryStatus = "failed"
)

func (s ContextDeliveryStatus) Validate() error {
	switch s {
	case ContextDeliveryAccepted, ContextDeliveryRejected, ContextDeliveryFailed:
		return nil
	default:
		return fmt.Errorf("context delivery status is unsupported")
	}
}

type ContextReceipt struct {
	ProtocolVersion        string                `json:"protocol_version"`
	SessionID              string                `json:"session_id"`
	ProviderID             string                `json:"provider_id"`
	NativeSessionID        NativeID              `json:"native_session_id"`
	ContextVersion         string                `json:"context_version"`
	SourceDigest           Digest                `json:"source_digest"`
	DeliveryMode           ContextDeliveryMode   `json:"delivery_mode"`
	DeliveredAt            time.Time             `json:"delivered_at"`
	Status                 ContextDeliveryStatus `json:"status"`
	NativeRuntimeMayIgnore bool                  `json:"native_runtime_may_ignore"`
}

func (r ContextReceipt) Validate() error {
	if err := validateProtocol(r.ProtocolVersion); err != nil {
		return err
	}
	for field, value := range map[string]string{"session_id": r.SessionID, "provider_id": r.ProviderID, "context_version": r.ContextVersion} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := r.SourceDigest.Validate(); err != nil {
		return err
	}
	if err := r.DeliveryMode.Validate(); err != nil {
		return err
	}
	if err := validateTime("delivered_at", r.DeliveredAt); err != nil {
		return err
	}
	return r.Status.Validate()
}

func (r ContextReceipt) Accepted() bool {
	return r.Status == ContextDeliveryAccepted
}

type ContextDeliverRequest struct {
	NativeSessionID NativeID            `json:"native_session_id"`
	ContextVersion  string              `json:"context_version"`
	SourceDigest    Digest              `json:"source_digest"`
	DeliveryMode    ContextDeliveryMode `json:"delivery_mode"`
	Content         json.RawMessage     `json:"content"`
	ContentDigest   Digest              `json:"content_digest"`
}

func (r ContextDeliverRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("context_version", r.ContextVersion); err != nil {
		return err
	}
	if err := r.SourceDigest.Validate(); err != nil {
		return err
	}
	if err := r.DeliveryMode.Validate(); err != nil {
		return err
	}
	return validateCompactJSONDigest("context content", r.Content, r.ContentDigest)
}

type ContextDeliverResult struct {
	Receipt ContextReceipt `json:"receipt"`
}

func (r ContextDeliverResult) Validate() error { return r.Receipt.Validate() }

type ContextConfirmRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
	ContextVersion  string   `json:"context_version"`
}

func (r ContextConfirmRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	return validateID("context_version", r.ContextVersion)
}

type ContextConfirmResult struct {
	Receipt ContextReceipt `json:"receipt"`
}

func (r ContextConfirmResult) Validate() error { return r.Receipt.Validate() }
