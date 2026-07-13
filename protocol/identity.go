package protocol

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

type NativeID string

const MaxNativeIDBytes = 1024

func (id NativeID) Validate() error {
	value := string(id)
	if value == "" {
		return fmt.Errorf("native_id is required")
	}
	if len(value) > MaxNativeIDBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("native_id is invalid")
	}
	return nil
}

type Digest string

func (d Digest) Validate() error {
	value := string(d)
	if !strings.HasPrefix(value, "sha256:") {
		return fmt.Errorf("digest must use sha256")
	}
	hexPart := strings.TrimPrefix(value, "sha256:")
	if len(hexPart) != 64 || strings.ToLower(hexPart) != hexPart {
		return fmt.Errorf("digest must contain 64 lowercase hexadecimal characters")
	}
	_, err := hex.DecodeString(hexPart)
	if err != nil {
		return fmt.Errorf("digest is invalid")
	}
	return nil
}

type ArtifactIdentity struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  Digest `json:"digest"`
}

func (a ArtifactIdentity) Validate() error {
	if err := validateID("artifact.id", a.ID); err != nil {
		return err
	}
	if err := validateVersion("artifact.version", a.Version); err != nil {
		return err
	}
	return a.Digest.Validate()
}

type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

func (p Platform) Validate() error {
	if err := validateToken("platform.os", p.OS); err != nil {
		return err
	}
	return validateToken("platform.architecture", p.Architecture)
}

// ProviderBinding binds one logical session role to an opaque native identity.
type ProviderBinding struct {
	ProviderID            string   `json:"provider_id"`
	ProviderVersion       string   `json:"provider_version"`
	NativeID              NativeID `json:"native_id"`
	NativeResumeReference NativeID `json:"native_resume_reference,omitempty"`
	ArtifactDigest        Digest   `json:"artifact_digest"`
}

func (b ProviderBinding) Validate() error {
	if err := validateID("provider_id", b.ProviderID); err != nil {
		return err
	}
	if err := validateVersion("provider_version", b.ProviderVersion); err != nil {
		return err
	}
	if err := b.NativeID.Validate(); err != nil {
		return err
	}
	if b.NativeResumeReference != "" {
		if err := b.NativeResumeReference.Validate(); err != nil {
			return err
		}
	}
	return b.ArtifactDigest.Validate()
}
