package protocol

import (
	"fmt"
	"sort"
	"time"
)

type ApprovalOutcome string

const (
	ApprovalOutcomeApproved ApprovalOutcome = "approved"
	ApprovalOutcomeRejected ApprovalOutcome = "rejected"
	ApprovalOutcomeExpired  ApprovalOutcome = "expired"
)

// ApprovalProviderSelection binds one provider role to an exact executable
// artifact. Native identifiers are deliberately excluded: approval authorizes
// the selected implementation, while the command binds the native target.
type ApprovalProviderSelection struct {
	Role     ProviderRole     `json:"role"`
	Provider ArtifactIdentity `json:"provider"`
}

func (s ApprovalProviderSelection) validate(expected ProviderRole) error {
	if s.Role != expected {
		return fmt.Errorf("approval provider role does not match selection")
	}
	if err := s.Role.Validate(); err != nil {
		return err
	}
	return validateSignedArtifact("approval provider", s.Provider)
}

type ApprovalBinding struct {
	CommandDigest    Digest                     `json:"command_digest"`
	SessionID        string                     `json:"session_id"`
	SessionRevision  uint64                     `json:"session_revision"`
	WorkItemRevision uint64                     `json:"work_item_revision"`
	ResourceRevision uint64                     `json:"resource_revision"`
	ContextVersion   string                     `json:"context_version"`
	PolicyRevision   uint64                     `json:"policy_revision"`
	Environment      ApprovalProviderSelection  `json:"environment"`
	Runtime          *ApprovalProviderSelection `json:"runtime,omitempty"`
	Harness          ApprovalProviderSelection  `json:"harness"`
	GatewayID        string                     `json:"gateway_id"`
	Scopes           []string                   `json:"scopes"`
	ExpiresAt        time.Time                  `json:"expires_at"`
	Nonce            string                     `json:"nonce"`
}

func (b ApprovalBinding) Validate() error {
	if err := b.CommandDigest.Validate(); err != nil {
		return err
	}
	for field, value := range map[string]string{"session_id": b.SessionID, "context_version": b.ContextVersion, "gateway_id": b.GatewayID} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if b.SessionRevision == 0 || b.WorkItemRevision == 0 || b.ResourceRevision == 0 || b.PolicyRevision == 0 {
		return fmt.Errorf("approval revisions must be positive")
	}
	if err := b.Environment.validate(RoleExecutionEnvironment); err != nil {
		return err
	}
	if b.Runtime != nil {
		if err := b.Runtime.validate(RoleSessionRuntime); err != nil {
			return err
		}
	}
	if err := b.Harness.validate(RoleAgentHarness); err != nil {
		return err
	}
	if len(b.Scopes) == 0 {
		return fmt.Errorf("approval scopes are required")
	}
	if err := validateUniqueStrings("scopes", b.Scopes); err != nil {
		return err
	}
	for _, scope := range b.Scopes {
		if err := validateSafeASCII("approval scope", scope, 1, 128); err != nil {
			return err
		}
	}
	if err := validateTime("expires_at", b.ExpiresAt); err != nil {
		return err
	}
	return validateNonce(b.Nonce)
}

type ApprovalDecision struct {
	ProtocolVersion  string          `json:"protocol_version"`
	ApprovalID       string          `json:"approval_id"`
	Outcome          ApprovalOutcome `json:"outcome"`
	Binding          ApprovalBinding `json:"binding"`
	DecisionRevision uint64          `json:"decision_revision"`
	DecidedAt        time.Time       `json:"decided_at"`
}

func (d ApprovalDecision) Validate() error {
	if err := validateProtocol(d.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("approval_id", d.ApprovalID); err != nil {
		return err
	}
	switch d.Outcome {
	case ApprovalOutcomeApproved, ApprovalOutcomeRejected, ApprovalOutcomeExpired:
	default:
		return fmt.Errorf("approval outcome is unsupported")
	}
	if err := d.Binding.Validate(); err != nil {
		return err
	}
	if d.DecisionRevision == 0 {
		return fmt.Errorf("decision_revision must be positive")
	}
	return validateTime("decided_at", d.DecidedAt)
}

func ValidateApprovalDecision(decision ApprovalDecision, expected ApprovalBinding, nonces NonceConsumer, now time.Time) error {
	if err := decision.Validate(); err != nil {
		return protocolError(CodeInvalidArgument, err.Error())
	}
	if err := expected.Validate(); err != nil {
		return protocolError(CodeInvalidArgument, "expected approval binding is invalid")
	}
	if !equalApprovalBinding(decision.Binding, expected) {
		return protocolError(CodeConflict, "approval decision does not match the current command and revisions")
	}
	if !now.Before(expected.ExpiresAt) || decision.Outcome == ApprovalOutcomeExpired {
		return protocolError(CodeExpired, "approval decision has expired")
	}
	if decision.DecidedAt.After(now) || decision.DecidedAt.After(expected.ExpiresAt) {
		return protocolError(CodeInvalidArgument, "approval decision timestamp is invalid")
	}
	if decision.Outcome != ApprovalOutcomeApproved {
		return protocolError(CodePermissionDenied, "approval decision does not authorize the command")
	}
	if nonces == nil || !nonces.Consume(expected.Nonce) {
		return protocolError(CodeReplay, "approval nonce was already consumed")
	}
	return nil
}

func equalApprovalBinding(a, b ApprovalBinding) bool {
	return a.CommandDigest == b.CommandDigest && a.SessionID == b.SessionID && a.SessionRevision == b.SessionRevision && a.WorkItemRevision == b.WorkItemRevision && a.ResourceRevision == b.ResourceRevision && a.ContextVersion == b.ContextVersion && a.PolicyRevision == b.PolicyRevision && equalApprovalProviderSelection(a.Environment, b.Environment) && equalOptionalApprovalProviderSelection(a.Runtime, b.Runtime) && equalApprovalProviderSelection(a.Harness, b.Harness) && a.GatewayID == b.GatewayID && equalStringSets(a.Scopes, b.Scopes) && a.ExpiresAt.Equal(b.ExpiresAt) && a.Nonce == b.Nonce
}

func equalApprovalProviderSelection(a, b ApprovalProviderSelection) bool {
	return a.Role == b.Role && a.Provider == b.Provider
}

func equalOptionalApprovalProviderSelection(a, b *ApprovalProviderSelection) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return equalApprovalProviderSelection(*a, *b)
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	return equalStrings(left, right)
}

type ProviderApproval struct {
	NativeApprovalID NativeID  `json:"native_approval_id"`
	NativeSessionID  NativeID  `json:"native_session_id"`
	Type             string    `json:"type"`
	Summary          string    `json:"summary"`
	Risk             string    `json:"risk"`
	RequestedScopes  []string  `json:"requested_scopes"`
	RequestDigest    Digest    `json:"request_digest"`
	Revision         uint64    `json:"revision"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (a ProviderApproval) Validate() error {
	if err := a.NativeApprovalID.Validate(); err != nil {
		return err
	}
	if err := a.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateToken("approval type", a.Type); err != nil {
		return err
	}
	if err := validateText("approval summary", a.Summary, 512); err != nil {
		return err
	}
	switch a.Risk {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("approval risk is unsupported")
	}
	if len(a.RequestedScopes) == 0 || len(a.RequestedScopes) > 64 {
		return fmt.Errorf("approval scopes are invalid")
	}
	if err := validateUniqueStrings("requested_scopes", a.RequestedScopes); err != nil {
		return err
	}
	for _, scope := range a.RequestedScopes {
		if err := validateSafeASCII("approval scope", scope, 1, 128); err != nil {
			return err
		}
	}
	if err := a.RequestDigest.Validate(); err != nil {
		return err
	}
	if a.Revision == 0 {
		return fmt.Errorf("approval revision must be positive")
	}
	return validateTime("expires_at", a.ExpiresAt)
}

type ApprovalListRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
}

func (r ApprovalListRequest) Validate() error { return r.NativeSessionID.Validate() }

type ApprovalListResult struct {
	Approvals []ProviderApproval `json:"approvals"`
}

func (r ApprovalListResult) Validate() error {
	if len(r.Approvals) > 1024 {
		return fmt.Errorf("too many pending approvals")
	}
	seen := make(map[NativeID]struct{}, len(r.Approvals))
	for _, approval := range r.Approvals {
		if err := approval.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[approval.NativeApprovalID]; duplicate {
			return fmt.Errorf("provider approval is duplicated")
		}
		seen[approval.NativeApprovalID] = struct{}{}
	}
	return nil
}

type ApprovalActionRequest struct {
	NativeSessionID  NativeID        `json:"native_session_id"`
	NativeApprovalID NativeID        `json:"native_approval_id"`
	Outcome          ApprovalOutcome `json:"outcome"`
	ExpectedRevision uint64          `json:"expected_revision"`
	DecisionDigest   Digest          `json:"decision_digest"`
}

func (r ApprovalActionRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := r.NativeApprovalID.Validate(); err != nil {
		return err
	}
	switch r.Outcome {
	case ApprovalOutcomeApproved, ApprovalOutcomeRejected, ApprovalOutcomeExpired:
	default:
		return fmt.Errorf("approval outcome is unsupported")
	}
	if r.ExpectedRevision == 0 {
		return fmt.Errorf("expected approval revision must be positive")
	}
	return r.DecisionDigest.Validate()
}

type ApprovalActionResult struct {
	Operation OperationResult `json:"operation"`
}

func (r ApprovalActionResult) Validate() error { return r.Operation.Validate() }
