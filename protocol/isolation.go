package protocol

import (
	"fmt"
	"time"
)

type IsolationBinding struct {
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

func (b IsolationBinding) Validate() error {
	for field, value := range map[string]string{"session_id": b.SessionID, "gateway_id": b.GatewayID, "gateway_key_id": b.GatewayKeyID} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if b.PolicyRevision == 0 {
		return fmt.Errorf("policy_revision must be positive")
	}
	if err := validateSignedArtifact("isolation provider", b.Provider); err != nil {
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
		return fmt.Errorf("isolation controls are required")
	}
	if err := validateUniqueStrings("controls", b.Controls); err != nil {
		return err
	}
	for _, control := range b.Controls {
		if err := validateSafeASCII("isolation control", control, 1, 128); err != nil {
			return err
		}
	}
	return b.DataMode.Validate()
}

type IsolationEvidence struct {
	ProtocolVersion  string           `json:"protocol_version"`
	EvidenceID       string           `json:"evidence_id"`
	Nonce            string           `json:"nonce"`
	IsolationBinding IsolationBinding `json:"binding"`
	IssuedAt         time.Time        `json:"issued_at"`
	ExpiresAt        time.Time        `json:"expires_at"`
	Signature        Signature        `json:"signature,omitzero"`
}

func (e IsolationEvidence) validateFields() error {
	if err := validateProtocol(e.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("evidence_id", e.EvidenceID); err != nil {
		return err
	}
	if err := validateNonce(e.Nonce); err != nil {
		return err
	}
	if err := e.IsolationBinding.Validate(); err != nil {
		return err
	}
	if err := validateEvidenceTimes(e.IssuedAt, e.ExpiresAt); err != nil {
		return err
	}
	return nil
}

func (e IsolationEvidence) Validate() error {
	if err := e.validateFields(); err != nil {
		return err
	}
	return e.Signature.validate(PurposeIsolationEvidence)
}

func (e IsolationEvidence) SigningBytes() ([]byte, error) {
	if err := e.validateFields(); err != nil {
		return nil, err
	}
	if err := e.Signature.validateMetadata(PurposeIsolationEvidence); err != nil {
		return nil, err
	}
	e.IsolationBinding.Controls = sortedStrings(e.IsolationBinding.Controls)
	e.Signature.Value = ""
	return signingPreimage(PurposeIsolationEvidence, e)
}

func VerifyIsolation(e IsolationEvidence, expected IsolationBinding, trust SignatureTrust, nonces NonceConsumer, now time.Time) error {
	if err := e.Validate(); err != nil {
		return protocolError(CodeInvalidArgument, err.Error())
	}
	if err := expected.Validate(); err != nil {
		return protocolError(CodeInvalidArgument, "expected isolation binding is invalid")
	}
	if !equalIsolationBinding(e.IsolationBinding, expected) {
		return protocolError(CodeConflict, "isolation evidence binding does not match authorization")
	}
	bytes, err := e.SigningBytes()
	if err != nil {
		return protocolError(CodeInvalidArgument, "isolation evidence cannot be encoded")
	}
	if err := verifyEvidenceSignature(e.Signature, e.IsolationBinding.GatewayID, e.IsolationBinding.GatewayKeyID, trust, bytes, now, e.IssuedAt, e.ExpiresAt); err != nil {
		return err
	}
	if nonces == nil || !nonces.Consume(e.Nonce) {
		return protocolError(CodeReplay, "evidence nonce was already consumed")
	}
	return nil
}

func equalIsolationBinding(a, b IsolationBinding) bool {
	return a.SessionID == b.SessionID && a.PolicyRevision == b.PolicyRevision && a.GatewayID == b.GatewayID && a.GatewayKeyID == b.GatewayKeyID && a.Provider == b.Provider && a.NativeEnvironmentID == b.NativeEnvironmentID && a.ConfigurationDigest == b.ConfigurationDigest && a.ImageDigest == b.ImageDigest && a.DataMode == b.DataMode && equalStringSets(a.Controls, b.Controls)
}
