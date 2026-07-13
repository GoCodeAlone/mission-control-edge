package protocol

import (
	"encoding/json"
	"fmt"
)

// HarnessState is the provider-local semantic state of an agent harness.
type HarnessState struct {
	ProviderID      string      `json:"provider_id"`
	NativeSessionID NativeID    `json:"native_session_id"`
	Activity        StateReport `json:"activity"`
	Usage           Usage       `json:"usage"`
}

func (s HarnessState) Validate() error {
	if err := validateID("provider_id", s.ProviderID); err != nil {
		return err
	}
	if err := s.NativeSessionID.Validate(); err != nil {
		return err
	}
	return s.Activity.validate(AxisActivity)
}

type HarnessSessionRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
}

func (r HarnessSessionRequest) Validate() error { return r.NativeSessionID.Validate() }

type HarnessListRequest struct{}

func (HarnessListRequest) Validate() error { return nil }

type HarnessLaunchRequest struct {
	NativeEnvironmentID NativeID        `json:"native_environment_id"`
	NativeRuntimeID     NativeID        `json:"native_runtime_id,omitempty"`
	ContextVersion      string          `json:"context_version"`
	Configuration       json.RawMessage `json:"configuration"`
	ConfigurationDigest Digest          `json:"configuration_digest"`
}

func (r HarnessLaunchRequest) Validate() error {
	if err := r.NativeEnvironmentID.Validate(); err != nil {
		return err
	}
	if r.NativeRuntimeID != "" {
		if err := r.NativeRuntimeID.Validate(); err != nil {
			return err
		}
	}
	if err := validateID("context_version", r.ContextVersion); err != nil {
		return err
	}
	return validateCompactJSONDigest("harness configuration", r.Configuration, r.ConfigurationDigest)
}

type HarnessResumeRequest struct {
	NativeResumeReference NativeID `json:"native_resume_reference"`
	ContextVersion        string   `json:"context_version"`
}

func (r HarnessResumeRequest) Validate() error {
	if err := r.NativeResumeReference.Validate(); err != nil {
		return err
	}
	return validateID("context_version", r.ContextVersion)
}

type HarnessSessionResult struct {
	ProviderID            string       `json:"provider_id"`
	NativeSessionID       NativeID     `json:"native_session_id"`
	NativeResumeReference NativeID     `json:"native_resume_reference,omitempty"`
	State                 HarnessState `json:"state"`
}

type HarnessListResult struct {
	Sessions []HarnessSessionResult `json:"sessions"`
}

func (r HarnessListResult) Validate() error {
	if len(r.Sessions) > 4096 {
		return fmt.Errorf("too many harness sessions")
	}
	seen := make(map[NativeID]struct{}, len(r.Sessions))
	for _, session := range r.Sessions {
		if err := session.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[session.NativeSessionID]; duplicate {
			return fmt.Errorf("harness session is duplicated")
		}
		seen[session.NativeSessionID] = struct{}{}
	}
	return nil
}

func (r HarnessSessionResult) Validate() error {
	if err := validateID("provider_id", r.ProviderID); err != nil {
		return err
	}
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if r.NativeResumeReference != "" {
		if err := r.NativeResumeReference.Validate(); err != nil {
			return err
		}
	}
	if r.State.ProviderID != r.ProviderID || r.State.NativeSessionID != r.NativeSessionID {
		return fmt.Errorf("harness result identity is inconsistent")
	}
	return r.State.Validate()
}

type AgentMessageRequest struct {
	NativeSessionID NativeID        `json:"native_session_id"`
	Message         json.RawMessage `json:"message"`
	MessageDigest   Digest          `json:"message_digest"`
}

type AgentControlRequest = HarnessSessionRequest

type AgentStateResult struct {
	State HarnessState `json:"state"`
}

func (r AgentStateResult) Validate() error { return r.State.Validate() }

type AgentUsageResult struct {
	Usage Usage `json:"usage"`
}

func (r AgentMessageRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	return validateCompactJSONDigest("agent message", r.Message, r.MessageDigest)
}

type AgentTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

func (t AgentTool) Validate() error {
	if err := validateToken("agent tool name", t.Name); err != nil {
		return err
	}
	if t.Description != "" {
		if err := validateText("agent tool description", t.Description, 512); err != nil {
			return err
		}
	}
	if len(t.InputSchema) == 0 || !json.Valid(t.InputSchema) {
		return fmt.Errorf("agent tool input schema is invalid")
	}
	return nil
}

type AgentToolsResult struct {
	Tools []AgentTool `json:"tools"`
}

func (r AgentToolsResult) Validate() error {
	if len(r.Tools) > 256 {
		return fmt.Errorf("too many agent tools")
	}
	seen := make(map[string]struct{}, len(r.Tools))
	for _, tool := range r.Tools {
		if err := tool.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[tool.Name]; duplicate {
			return fmt.Errorf("agent tool is duplicated")
		}
		seen[tool.Name] = struct{}{}
	}
	return nil
}

type AgentNativeIdentityResult struct {
	NativeSessionID NativeID `json:"native_session_id"`
	NativeAgentID   NativeID `json:"native_agent_id"`
}

func (r AgentNativeIdentityResult) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	return r.NativeAgentID.Validate()
}
