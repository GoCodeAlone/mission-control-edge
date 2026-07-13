package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

type DataMode string

const (
	DataModeFull                DataMode = "full"
	DataModeEphemeralTranscript DataMode = "ephemeral-transcript"
	DataModeMetadataOnly        DataMode = "metadata-only"
	DataModeLocalControl        DataMode = "local-control"
)

func (m DataMode) Validate() error {
	switch m {
	case DataModeFull, DataModeEphemeralTranscript, DataModeMetadataOnly, DataModeLocalControl:
		return nil
	default:
		return fmt.Errorf("data mode is unsupported")
	}
}

type Sensitivity string

const (
	SensitivityPublic       Sensitivity = "public"
	SensitivityMetadata     Sensitivity = "metadata"
	SensitivityInternal     Sensitivity = "internal"
	SensitivityConfidential Sensitivity = "confidential"
	SensitivityRestricted   Sensitivity = "restricted"
)

func (s Sensitivity) Validate() error {
	switch s {
	case SensitivityPublic, SensitivityMetadata, SensitivityInternal, SensitivityConfidential, SensitivityRestricted:
		return nil
	default:
		return fmt.Errorf("sensitivity is unsupported")
	}
}

const (
	SignatureEd25519            = "ed25519"
	PurposeIsolationEvidence    = "isolation-evidence"
	PurposeCustodyEvidence      = "custody-evidence"
	PurposeContractVerification = "contract-verification"
	PurposeLiveRunAuthorization = "live-run-authorization"
	PurposeLiveRunReceipt       = "live-run-receipt"
	PurposeLiveVerification     = "live-verification"
	// PurposeLiveGatewayProof is retained as a protocol name for older peers.
	// New live verification uses PurposeLiveRunReceipt.
	PurposeLiveGatewayProof = "live-gateway-proof"
)

const signingDomainPrefix = ProtocolVersion + "\x00"

type Signature struct {
	Algorithm string `json:"algorithm"`
	Purpose   string `json:"purpose"`
	Issuer    string `json:"issuer"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

func (s Signature) validate(expectedPurpose string) error {
	if err := s.validateMetadata(expectedPurpose); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s.Value)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return fmt.Errorf("signature value is invalid")
	}
	return nil
}

func (s Signature) validateMetadata(expectedPurpose string) error {
	if s.Algorithm != SignatureEd25519 || s.Purpose != expectedPurpose {
		return fmt.Errorf("signature algorithm or purpose is invalid")
	}
	if err := validateID("signature issuer", s.Issuer); err != nil {
		return err
	}
	if err := validateID("signature key_id", s.KeyID); err != nil {
		return err
	}
	return nil
}

type SignatureTrust interface {
	PublicKey(issuer, keyID, purpose string) (ed25519.PublicKey, bool)
}

type NonceConsumer interface{ Consume(nonce string) bool }

type CustodyBinding struct {
	SessionID           string           `json:"session_id"`
	PolicyRevision      uint64           `json:"policy_revision"`
	GatewayID           string           `json:"gateway_id"`
	GatewayKeyID        string           `json:"gateway_key_id"`
	Provider            ArtifactIdentity `json:"provider"`
	NativeEnvironmentID NativeID         `json:"native_environment_id"`
	ConfigurationDigest Digest           `json:"configuration_digest"`
	ImageDigest         Digest           `json:"image_digest"`
	Controls            []string         `json:"controls"`
	DataMode            DataMode         `json:"data_mode"`
}

func (b CustodyBinding) Validate() error {
	for field, value := range map[string]string{"session_id": b.SessionID, "gateway_id": b.GatewayID, "gateway_key_id": b.GatewayKeyID} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if b.PolicyRevision == 0 {
		return fmt.Errorf("policy_revision must be positive")
	}
	if err := validateSignedArtifact("custody provider", b.Provider); err != nil {
		return err
	}
	if err := b.NativeEnvironmentID.Validate(); err != nil {
		return err
	}
	if err := validateSafeASCII("native_environment_id", string(b.NativeEnvironmentID), 1, 1024); err != nil {
		return err
	}
	if err := b.ConfigurationDigest.Validate(); err != nil {
		return err
	}
	if err := b.ImageDigest.Validate(); err != nil {
		return err
	}
	if len(b.Controls) == 0 {
		return fmt.Errorf("custody controls are required")
	}
	if err := validateUniqueStrings("controls", b.Controls); err != nil {
		return err
	}
	for _, control := range b.Controls {
		if err := validateSafeASCII("custody control", control, 1, 128); err != nil {
			return err
		}
	}
	return b.DataMode.Validate()
}

type ContentCustodyEvidence struct {
	ProtocolVersion string         `json:"protocol_version"`
	EvidenceID      string         `json:"evidence_id"`
	Nonce           string         `json:"nonce"`
	CustodyBinding  CustodyBinding `json:"binding"`
	IssuedAt        time.Time      `json:"issued_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Signature       Signature      `json:"signature,omitzero"`
}

func (e ContentCustodyEvidence) validateFields() error {
	if err := validateProtocol(e.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("evidence_id", e.EvidenceID); err != nil {
		return err
	}
	if err := validateNonce(e.Nonce); err != nil {
		return err
	}
	if err := e.CustodyBinding.Validate(); err != nil {
		return err
	}
	if err := validateEvidenceTimes(e.IssuedAt, e.ExpiresAt); err != nil {
		return err
	}
	return nil
}

func (e ContentCustodyEvidence) Validate() error {
	if err := e.validateFields(); err != nil {
		return err
	}
	return e.Signature.validate(PurposeCustodyEvidence)
}

func (e ContentCustodyEvidence) SigningBytes() ([]byte, error) {
	if err := e.validateFields(); err != nil {
		return nil, err
	}
	if err := e.Signature.validateMetadata(PurposeCustodyEvidence); err != nil {
		return nil, err
	}
	e.CustodyBinding.Controls = sortedStrings(e.CustodyBinding.Controls)
	e.Signature.Value = ""
	return signingPreimage(PurposeCustodyEvidence, e)
}

func VerifyCustody(e ContentCustodyEvidence, expected CustodyBinding, trust SignatureTrust, nonces NonceConsumer, now time.Time) error {
	if err := e.Validate(); err != nil {
		return protocolError(CodeInvalidArgument, err.Error())
	}
	if err := expected.Validate(); err != nil {
		return protocolError(CodeInvalidArgument, "expected custody binding is invalid")
	}
	if !equalCustodyBinding(e.CustodyBinding, expected) {
		return protocolError(CodeConflict, "custody evidence binding does not match authorization")
	}
	bytes, err := e.SigningBytes()
	if err != nil {
		return protocolError(CodeInvalidArgument, "custody evidence cannot be encoded")
	}
	if err := verifyEvidenceSignature(e.Signature, e.CustodyBinding.GatewayID, e.CustodyBinding.GatewayKeyID, trust, bytes, now, e.IssuedAt, e.ExpiresAt); err != nil {
		return err
	}
	if nonces == nil || !nonces.Consume(e.Nonce) {
		return protocolError(CodeReplay, "evidence nonce was already consumed")
	}
	return nil
}

func equalCustodyBinding(a, b CustodyBinding) bool {
	return a.SessionID == b.SessionID && a.PolicyRevision == b.PolicyRevision && a.GatewayID == b.GatewayID && a.GatewayKeyID == b.GatewayKeyID && a.Provider == b.Provider && a.NativeEnvironmentID == b.NativeEnvironmentID && a.ConfigurationDigest == b.ConfigurationDigest && a.ImageDigest == b.ImageDigest && a.DataMode == b.DataMode && equalStringSets(a.Controls, b.Controls)
}

func validateNonce(value string) error {
	if len(value) < 22 || len(value) > 256 {
		return fmt.Errorf("nonce is invalid")
	}
	for _, char := range []byte(value) {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			continue
		}
		return fmt.Errorf("nonce is invalid")
	}
	return nil
}

func validateEvidenceTimes(issuedAt, expiresAt time.Time) error {
	if err := validateTime("issued_at", issuedAt); err != nil {
		return err
	}
	if err := validateTime("expires_at", expiresAt); err != nil {
		return err
	}
	if !expiresAt.After(issuedAt) {
		return fmt.Errorf("evidence expiry must follow issue time")
	}
	return nil
}

func verifyEvidenceSignature(signature Signature, expectedIssuer, expectedKeyID string, trust SignatureTrust, payload []byte, now, issuedAt, expiresAt time.Time) error {
	if now.Before(issuedAt) {
		return protocolError(CodeUnauthenticated, "evidence is not yet valid")
	}
	if !now.Before(expiresAt) {
		return protocolError(CodeExpired, "evidence has expired")
	}
	if signature.Issuer != expectedIssuer || signature.KeyID != expectedKeyID || trust == nil {
		return protocolError(CodeUnauthenticated, "evidence signer is not authoritative")
	}
	key, ok := trust.PublicKey(signature.Issuer, signature.KeyID, signature.Purpose)
	if !ok {
		return protocolError(CodeUnauthenticated, "evidence signer is not trusted")
	}
	value, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || !ed25519.Verify(key, payload, value) {
		return protocolError(CodeUnauthenticated, "evidence signature is invalid")
	}
	return nil
}

func signingPreimage(purpose string, document any) ([]byte, error) {
	if err := validateSafeASCII("signature purpose", purpose, 1, 128); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	capacity, err := checkedAllocationSize(len(signingDomainPrefix), len(purpose), 1, len(payload))
	if err != nil {
		return nil, fmt.Errorf("signing preimage: %w", err)
	}
	result := make([]byte, 0, capacity)
	result = append(result, signingDomainPrefix...)
	result = append(result, purpose...)
	result = append(result, 0)
	result = append(result, payload...)
	return result, nil
}

func checkedAllocationSize(parts ...int) (int, error) {
	maxInt := int(^uint(0) >> 1)
	total := 0
	for _, size := range parts {
		if size < 0 || size > maxInt-total {
			return 0, fmt.Errorf("allocation size exceeds platform limit")
		}
		total += size
	}
	return total, nil
}

func validateSignedArtifact(field string, artifact ArtifactIdentity) error {
	if err := artifact.Validate(); err != nil {
		return err
	}
	if err := validateSafeASCII(field+" id", artifact.ID, 1, 128); err != nil {
		return err
	}
	if err := validateSafeASCII(field+" version", artifact.Version, 1, 128); err != nil {
		return err
	}
	return validateSafeASCII(field+" digest", string(artifact.Digest), 71, 71)
}

func validateSafeASCII(field, value string, minimum, maximum int) error {
	if len(value) < minimum || len(value) > maximum {
		return fmt.Errorf("%s is invalid", field)
	}
	for _, char := range []byte(value) {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '.', '_', '-', ':', '/', '@', '+', '=', '~':
			continue
		default:
			return fmt.Errorf("%s is invalid", field)
		}
	}
	return nil
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
