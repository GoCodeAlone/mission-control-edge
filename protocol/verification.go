package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
	"time"
)

type VerificationTier string

const (
	TierUnverified           VerificationTier = "unverified"
	TierNativeContractTested VerificationTier = "native_contract_tested"
	TierLiveVerified         VerificationTier = "live_verified"
)

type VerificationResult string

const (
	VerificationPassed VerificationResult = "passed"
	VerificationFailed VerificationResult = "failed"
)

type VerificationSubject struct {
	Provider            ArtifactIdentity `json:"provider"`
	NativeArtifact      ArtifactIdentity `json:"native_artifact"`
	Platform            Platform         `json:"platform"`
	Capabilities        []CapabilityName `json:"capabilities"`
	Cases               []string         `json:"cases"`
	SuiteVersion        string           `json:"suite_version"`
	SuiteDigest         Digest           `json:"suite_digest"`
	ConfigurationDigest Digest           `json:"configuration_digest"`
	DataModes           []DataMode       `json:"data_modes"`
}

func (s VerificationSubject) Validate() error {
	if err := validateSignedArtifact("verification provider", s.Provider); err != nil {
		return err
	}
	if err := validateSignedArtifact("verification native artifact", s.NativeArtifact); err != nil {
		return err
	}
	if err := s.Platform.Validate(); err != nil {
		return err
	}
	if len(s.Capabilities) == 0 || len(s.Cases) == 0 || len(s.DataModes) == 0 {
		return fmt.Errorf("verification subject scope is incomplete")
	}
	capabilities := make([]string, len(s.Capabilities))
	for i := range s.Capabilities {
		capabilities[i] = string(s.Capabilities[i])
		if !validCapabilityName(s.Capabilities[i]) {
			return fmt.Errorf("verification capability is invalid")
		}
	}
	if err := validateUniqueStrings("capabilities", capabilities); err != nil {
		return err
	}
	if err := validateUniqueStrings("cases", s.Cases); err != nil {
		return err
	}
	for _, testCase := range s.Cases {
		if err := validateSafeASCII("verification case", testCase, 1, 128); err != nil {
			return err
		}
	}
	if err := validateVersion("suite_version", s.SuiteVersion); err != nil {
		return err
	}
	if err := validateSafeASCII("suite_version", s.SuiteVersion, 1, 128); err != nil {
		return err
	}
	if err := s.SuiteDigest.Validate(); err != nil {
		return err
	}
	if err := s.ConfigurationDigest.Validate(); err != nil {
		return err
	}
	seenModes := map[DataMode]struct{}{}
	for _, mode := range s.DataModes {
		if err := mode.Validate(); err != nil {
			return err
		}
		if _, ok := seenModes[mode]; ok {
			return fmt.Errorf("data_modes contains a duplicate")
		}
		seenModes[mode] = struct{}{}
	}
	return nil
}

type Usage struct {
	InputTokens    uint64 `json:"input_tokens"`
	OutputTokens   uint64 `json:"output_tokens"`
	CostMicrounits uint64 `json:"cost_microunits"`
}

// LiveVerificationAuthorization is Mission-signed authority for one bounded
// native run. It is distinct from both the gateway receipt and final evidence.
type LiveVerificationAuthorization struct {
	ProtocolVersion     string              `json:"protocol_version"`
	AuthorizationID     string              `json:"authorization_id"`
	Subject             VerificationSubject `json:"subject"`
	TenantID            string              `json:"tenant_id"`
	GatewayID           string              `json:"gateway_id"`
	GatewayKeyID        string              `json:"gateway_key_id"`
	CorrelationID       string              `json:"correlation_id"`
	RunNonce            string              `json:"run_nonce"`
	BudgetReference     string              `json:"budget_reference"`
	CredentialReference string              `json:"credential_reference"`
	IssuedAt            time.Time           `json:"issued_at"`
	ExpiresAt           time.Time           `json:"expires_at"`
	TrustEpoch          uint64              `json:"trust_epoch"`
	Signature           Signature           `json:"signature"`
}

func (a LiveVerificationAuthorization) validateFields() error {
	if err := validateProtocol(a.ProtocolVersion); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"authorization_id": a.AuthorizationID,
		"tenant_id":        a.TenantID,
		"gateway_id":       a.GatewayID,
		"gateway_key_id":   a.GatewayKeyID,
		"correlation_id":   a.CorrelationID,
	} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if err := a.Subject.Validate(); err != nil {
		return err
	}
	if err := validateNonce(a.RunNonce); err != nil {
		return err
	}
	if err := validateSignedReference("budget_reference", a.BudgetReference); err != nil {
		return err
	}
	if err := validateSignedReference("credential_reference", a.CredentialReference); err != nil {
		return err
	}
	if err := validateEvidenceTimes(a.IssuedAt, a.ExpiresAt); err != nil {
		return err
	}
	if a.TrustEpoch == 0 {
		return fmt.Errorf("trust_epoch must be positive")
	}
	return nil
}

func (a LiveVerificationAuthorization) Validate() error {
	if err := a.validateFields(); err != nil {
		return err
	}
	return a.Signature.validate(PurposeLiveRunAuthorization)
}

func (a LiveVerificationAuthorization) SigningBytes() ([]byte, error) {
	if err := a.validateFields(); err != nil {
		return nil, err
	}
	if err := a.Signature.validateMetadata(PurposeLiveRunAuthorization); err != nil {
		return nil, err
	}
	a.Subject = canonicalVerificationSubject(a.Subject)
	a.Signature.Value = ""
	return signingPreimage(PurposeLiveRunAuthorization, a)
}

// LiveVerificationReceipt is the gateway-signed result of exactly one live
// authorization. Usage is a pointer so an omitted measurement cannot be
// confused with an explicitly observed zero value.
type LiveVerificationReceipt struct {
	ProtocolVersion     string              `json:"protocol_version"`
	ReceiptID           string              `json:"receipt_id"`
	AuthorizationID     string              `json:"authorization_id"`
	Subject             VerificationSubject `json:"subject"`
	TenantID            string              `json:"tenant_id"`
	GatewayID           string              `json:"gateway_id"`
	CorrelationID       string              `json:"correlation_id"`
	RunNonce            string              `json:"run_nonce"`
	BudgetReference     string              `json:"budget_reference"`
	CredentialReference string              `json:"credential_reference"`
	Result              VerificationResult  `json:"result"`
	Usage               *Usage              `json:"usage"`
	AuditEventID        string              `json:"audit_event_id"`
	IssuedAt            time.Time           `json:"issued_at"`
	Signature           Signature           `json:"signature"`
}

func (r LiveVerificationReceipt) validateFields() error {
	if err := validateProtocol(r.ProtocolVersion); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"receipt_id":       r.ReceiptID,
		"authorization_id": r.AuthorizationID,
		"tenant_id":        r.TenantID,
		"gateway_id":       r.GatewayID,
		"correlation_id":   r.CorrelationID,
		"audit_event_id":   r.AuditEventID,
	} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if err := validateNonce(r.RunNonce); err != nil {
		return err
	}
	if err := validateSignedReference("budget_reference", r.BudgetReference); err != nil {
		return err
	}
	if err := validateSignedReference("credential_reference", r.CredentialReference); err != nil {
		return err
	}
	if r.Result != VerificationPassed && r.Result != VerificationFailed {
		return fmt.Errorf("verification result is unsupported")
	}
	if r.Usage == nil {
		return fmt.Errorf("live verification usage is required")
	}
	return validateTime("issued_at", r.IssuedAt)
}

func (r LiveVerificationReceipt) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if err := r.Signature.validate(PurposeLiveRunReceipt); err != nil {
		return err
	}
	if r.Signature.Issuer != r.GatewayID {
		return fmt.Errorf("live verification receipt signer does not match gateway")
	}
	return nil
}

func (r LiveVerificationReceipt) SigningBytes() ([]byte, error) {
	if err := r.validateFields(); err != nil {
		return nil, err
	}
	if err := r.Signature.validateMetadata(PurposeLiveRunReceipt); err != nil {
		return nil, err
	}
	r.Subject = canonicalVerificationSubject(r.Subject)
	r.Signature.Value = ""
	return signingPreimage(PurposeLiveRunReceipt, r)
}

type VerificationEvidence struct {
	ProtocolVersion   string                         `json:"protocol_version"`
	EvidenceID        string                         `json:"evidence_id"`
	Tier              VerificationTier               `json:"tier"`
	Subject           VerificationSubject            `json:"subject"`
	Result            VerificationResult             `json:"result"`
	Reference         string                         `json:"reference"`
	IssuedAt          time.Time                      `json:"issued_at"`
	ExpiresAt         time.Time                      `json:"expires_at"`
	TrustEpoch        uint64                         `json:"trust_epoch"`
	LiveAuthorization *LiveVerificationAuthorization `json:"live_authorization,omitempty"`
	LiveReceipt       *LiveVerificationReceipt       `json:"live_receipt,omitempty"`
	Signature         Signature                      `json:"signature"`
}

func (e VerificationEvidence) validateFields() (string, error) {
	if err := validateProtocol(e.ProtocolVersion); err != nil {
		return "", err
	}
	if err := validateID("evidence_id", e.EvidenceID); err != nil {
		return "", err
	}
	if e.Tier != TierNativeContractTested && e.Tier != TierLiveVerified {
		return "", fmt.Errorf("verification evidence tier is not issuable")
	}
	if err := e.Subject.Validate(); err != nil {
		return "", err
	}
	if e.Result != VerificationPassed && e.Result != VerificationFailed {
		return "", fmt.Errorf("verification result is unsupported")
	}
	if err := validateSignedReference("evidence reference", e.Reference); err != nil {
		return "", err
	}
	if err := validateEvidenceTimes(e.IssuedAt, e.ExpiresAt); err != nil {
		return "", err
	}
	if e.TrustEpoch == 0 {
		return "", fmt.Errorf("trust_epoch must be positive")
	}
	purpose := PurposeContractVerification
	if e.Tier == TierLiveVerified {
		purpose = PurposeLiveVerification
		if e.LiveAuthorization == nil || e.LiveReceipt == nil {
			return "", fmt.Errorf("live authorization and receipt are required")
		}
		if err := e.LiveAuthorization.Validate(); err != nil {
			return "", err
		}
		if err := e.LiveReceipt.Validate(); err != nil {
			return "", err
		}
		if !liveComponentsMatch(e, *e.LiveAuthorization, *e.LiveReceipt) {
			return "", fmt.Errorf("live verification components do not match")
		}
		if e.LiveReceipt.IssuedAt.Before(e.LiveAuthorization.IssuedAt) || !e.LiveReceipt.IssuedAt.Before(e.LiveAuthorization.ExpiresAt) || e.IssuedAt.Before(e.LiveReceipt.IssuedAt) {
			return "", fmt.Errorf("live verification timestamps are inconsistent")
		}
	} else if e.LiveAuthorization != nil || e.LiveReceipt != nil {
		return "", fmt.Errorf("native contract evidence cannot contain live records")
	}
	return purpose, nil
}

func (e VerificationEvidence) Validate() error {
	purpose, err := e.validateFields()
	if err != nil {
		return err
	}
	return e.Signature.validate(purpose)
}

func (e VerificationEvidence) SigningBytes() ([]byte, error) {
	purpose, err := e.validateFields()
	if err != nil {
		return nil, err
	}
	if err := e.Signature.validateMetadata(purpose); err != nil {
		return nil, err
	}
	e = canonicalVerificationEvidence(e)
	e.Signature.Value = ""
	return signingPreimage(purpose, e)
}

// VerificationExpectation is the caller-owned exact scope for projection.
// Supplying no live fields permits native-contract projection only. Supplying
// any live field requires the complete live scope.
type VerificationExpectation struct {
	Subject             VerificationSubject `json:"subject"`
	TenantID            string              `json:"tenant_id,omitempty"`
	GatewayID           string              `json:"gateway_id,omitempty"`
	GatewayKeyID        string              `json:"gateway_key_id,omitempty"`
	CorrelationID       string              `json:"correlation_id,omitempty"`
	AuthorizationID     string              `json:"authorization_id,omitempty"`
	RunNonce            string              `json:"run_nonce,omitempty"`
	BudgetReference     string              `json:"budget_reference,omitempty"`
	CredentialReference string              `json:"credential_reference,omitempty"`
}

func (e VerificationExpectation) Validate() error {
	if err := e.Subject.Validate(); err != nil {
		return err
	}
	if !e.hasLiveScope() {
		return nil
	}
	for field, value := range map[string]string{
		"tenant_id":        e.TenantID,
		"gateway_id":       e.GatewayID,
		"gateway_key_id":   e.GatewayKeyID,
		"correlation_id":   e.CorrelationID,
		"authorization_id": e.AuthorizationID,
	} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if err := validateNonce(e.RunNonce); err != nil {
		return err
	}
	if err := validateSignedReference("budget_reference", e.BudgetReference); err != nil {
		return err
	}
	return validateSignedReference("credential_reference", e.CredentialReference)
}

func (e VerificationExpectation) hasLiveScope() bool {
	return e.TenantID != "" || e.GatewayID != "" || e.GatewayKeyID != "" || e.CorrelationID != "" || e.AuthorizationID != "" || e.RunNonce != "" || e.BudgetReference != "" || e.CredentialReference != ""
}

// VerificationReplayGuard atomically admits a live run nonce. Accept must be
// idempotent for the same nonce/evidence pair and reject the nonce when it is
// already bound to a different evidence ID.
type VerificationReplayGuard interface {
	Accept(runNonce, evidenceID string) bool
}

type VerificationPolicy struct {
	Trust                 SignatureTrust
	CurrentTrustEpoch     uint64
	RevokedEvidenceIDs    []string
	SupersededEvidenceIDs []string
}

type VerificationProjection struct {
	Tier       VerificationTier `json:"tier"`
	EvidenceID string           `json:"evidence_id,omitempty"`
}

func EvaluateVerification(evidence []VerificationEvidence, expected VerificationExpectation, policy VerificationPolicy, replay VerificationReplayGuard, now time.Time) VerificationProjection {
	projection := VerificationProjection{Tier: TierUnverified}
	if expected.Validate() != nil || policy.Trust == nil || policy.CurrentTrustEpoch == 0 {
		return projection
	}
	for _, candidate := range evidence {
		if !verificationApplies(candidate, expected, policy, replay, now) {
			continue
		}
		if candidate.Tier == TierLiveVerified || projection.Tier == TierUnverified {
			projection = VerificationProjection{Tier: candidate.Tier, EvidenceID: candidate.EvidenceID}
		}
	}
	return projection
}

func verificationApplies(e VerificationEvidence, expected VerificationExpectation, policy VerificationPolicy, replay VerificationReplayGuard, now time.Time) bool {
	if e.Validate() != nil || e.Result != VerificationPassed || e.TrustEpoch != policy.CurrentTrustEpoch || now.Before(e.IssuedAt) || !now.Before(e.ExpiresAt) || !equalVerificationSubject(e.Subject, expected.Subject) {
		return false
	}
	if containsString(policy.RevokedEvidenceIDs, e.EvidenceID) || containsString(policy.SupersededEvidenceIDs, e.EvidenceID) {
		return false
	}
	payload, err := e.SigningBytes()
	if err != nil || !verifyTrustedSignature(e.Signature, signaturePurposeForTier(e.Tier), policy.Trust, payload) {
		return false
	}
	if e.Tier != TierLiveVerified {
		return true
	}
	if !expected.hasLiveScope() || replay == nil || e.LiveAuthorization == nil || e.LiveReceipt == nil {
		return false
	}
	authorization := *e.LiveAuthorization
	receipt := *e.LiveReceipt
	if !liveAuthorizationMatchesExpectation(authorization, expected) || !liveReceiptMatchesAuthorization(receipt, authorization) {
		return false
	}
	if now.Before(authorization.IssuedAt) || !now.Before(authorization.ExpiresAt) || now.Before(receipt.IssuedAt) {
		return false
	}
	authorizationBytes, err := authorization.SigningBytes()
	if err != nil || !verifyTrustedSignature(authorization.Signature, PurposeLiveRunAuthorization, policy.Trust, authorizationBytes) {
		return false
	}
	if receipt.Signature.Issuer != receipt.GatewayID {
		return false
	}
	receiptBytes, err := receipt.SigningBytes()
	if err != nil || !verifyTrustedSignature(receipt.Signature, PurposeLiveRunReceipt, policy.Trust, receiptBytes) {
		return false
	}
	return replay.Accept(receipt.RunNonce, e.EvidenceID)
}

func verifyTrustedSignature(signature Signature, expectedPurpose string, trust SignatureTrust, payload []byte) bool {
	if trust == nil || signature.validate(expectedPurpose) != nil {
		return false
	}
	key, ok := trust.PublicKey(signature.Issuer, signature.KeyID, expectedPurpose)
	if !ok {
		return false
	}
	value, err := base64.RawURLEncoding.DecodeString(signature.Value)
	return err == nil && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, payload, value)
}

func signaturePurposeForTier(tier VerificationTier) string {
	if tier == TierLiveVerified {
		return PurposeLiveVerification
	}
	return PurposeContractVerification
}

func canonicalVerificationEvidence(e VerificationEvidence) VerificationEvidence {
	e.Subject = canonicalVerificationSubject(e.Subject)
	if e.LiveAuthorization != nil {
		value := *e.LiveAuthorization
		value.Subject = canonicalVerificationSubject(value.Subject)
		e.LiveAuthorization = &value
	}
	if e.LiveReceipt != nil {
		value := *e.LiveReceipt
		value.Subject = canonicalVerificationSubject(value.Subject)
		e.LiveReceipt = &value
	}
	return e
}

func canonicalVerificationSubject(subject VerificationSubject) VerificationSubject {
	subject.Capabilities = append([]CapabilityName(nil), subject.Capabilities...)
	sort.Slice(subject.Capabilities, func(i, j int) bool { return subject.Capabilities[i] < subject.Capabilities[j] })
	subject.Cases = sortedStrings(subject.Cases)
	subject.DataModes = append([]DataMode(nil), subject.DataModes...)
	sort.Slice(subject.DataModes, func(i, j int) bool { return subject.DataModes[i] < subject.DataModes[j] })
	return subject
}

func equalVerificationSubject(a, b VerificationSubject) bool {
	a = canonicalVerificationSubject(a)
	b = canonicalVerificationSubject(b)
	if a.Provider != b.Provider || a.NativeArtifact != b.NativeArtifact || a.Platform != b.Platform || a.SuiteVersion != b.SuiteVersion || a.SuiteDigest != b.SuiteDigest || a.ConfigurationDigest != b.ConfigurationDigest || len(a.Capabilities) != len(b.Capabilities) || len(a.DataModes) != len(b.DataModes) {
		return false
	}
	for i := range a.Capabilities {
		if a.Capabilities[i] != b.Capabilities[i] {
			return false
		}
	}
	for i := range a.DataModes {
		if a.DataModes[i] != b.DataModes[i] {
			return false
		}
	}
	return equalStrings(a.Cases, b.Cases)
}

func liveComponentsMatch(e VerificationEvidence, authorization LiveVerificationAuthorization, receipt LiveVerificationReceipt) bool {
	return e.TrustEpoch == authorization.TrustEpoch && e.Result == receipt.Result && equalVerificationSubject(e.Subject, authorization.Subject) && liveReceiptMatchesAuthorization(receipt, authorization)
}

func liveAuthorizationMatchesExpectation(authorization LiveVerificationAuthorization, expected VerificationExpectation) bool {
	return equalVerificationSubject(authorization.Subject, expected.Subject) && authorization.TenantID == expected.TenantID && authorization.GatewayID == expected.GatewayID && authorization.GatewayKeyID == expected.GatewayKeyID && authorization.CorrelationID == expected.CorrelationID && authorization.AuthorizationID == expected.AuthorizationID && authorization.RunNonce == expected.RunNonce && authorization.BudgetReference == expected.BudgetReference && authorization.CredentialReference == expected.CredentialReference
}

func liveReceiptMatchesAuthorization(receipt LiveVerificationReceipt, authorization LiveVerificationAuthorization) bool {
	return receipt.AuthorizationID == authorization.AuthorizationID && equalVerificationSubject(receipt.Subject, authorization.Subject) && receipt.TenantID == authorization.TenantID && receipt.GatewayID == authorization.GatewayID && receipt.Signature.KeyID == authorization.GatewayKeyID && receipt.CorrelationID == authorization.CorrelationID && receipt.RunNonce == authorization.RunNonce && receipt.BudgetReference == authorization.BudgetReference && receipt.CredentialReference == authorization.CredentialReference
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validateSignedReference(field, value string) error {
	if err := validateOpaqueReference(field, value); err != nil {
		return err
	}
	return validateSafeASCII(field, value, 3, 1024)
}

func validateOpaqueReference(field, value string) error {
	if len(value) == 0 || len(value) > 1024 {
		return fmt.Errorf("%s is invalid", field)
	}
	for i, r := range value {
		if r == '\x00' || r == '\r' || r == '\n' {
			return fmt.Errorf("%s is invalid", field)
		}
		if r == ':' && i > 0 {
			return nil
		}
	}
	return fmt.Errorf("%s must be an opaque typed reference", field)
}
