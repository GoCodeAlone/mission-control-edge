package protocol

import (
	"encoding/json"
	"fmt"
)

// Environment describes a provider-local execution environment without canonical tenant scope.
type Environment struct {
	ProviderID          string          `json:"provider_id"`
	NativeEnvironmentID NativeID        `json:"native_environment_id"`
	Platform            Platform        `json:"platform"`
	Health              StateReport     `json:"health"`
	Configuration       json.RawMessage `json:"configuration,omitempty"`
}

func (e Environment) Validate() error {
	if err := validateID("provider_id", e.ProviderID); err != nil {
		return err
	}
	if err := e.NativeEnvironmentID.Validate(); err != nil {
		return err
	}
	if err := e.Platform.Validate(); err != nil {
		return err
	}
	if err := e.Health.validate(AxisHealth); err != nil {
		return err
	}
	if len(e.Configuration) != 0 && !json.Valid(e.Configuration) {
		return fmt.Errorf("environment configuration is invalid")
	}
	return nil
}

type EnvironmentInspectRequest struct {
	NativeEnvironmentID NativeID `json:"native_environment_id"`
}

func (r EnvironmentInspectRequest) Validate() error { return r.NativeEnvironmentID.Validate() }

type EnvironmentProvisionRequest struct {
	Configuration       json.RawMessage `json:"configuration"`
	ConfigurationDigest Digest          `json:"configuration_digest"`
	ImageDigest         Digest          `json:"image_digest,omitempty"`
}

func (r EnvironmentProvisionRequest) Validate() error {
	if err := validateCompactJSONDigest("environment configuration", r.Configuration, r.ConfigurationDigest); err != nil {
		return err
	}
	if r.ImageDigest != "" {
		return r.ImageDigest.Validate()
	}
	return nil
}

type EnvironmentMountRequest struct {
	NativeEnvironmentID NativeID `json:"native_environment_id"`
	MountID             string   `json:"mount_id"`
	ResourceReference   string   `json:"resource_reference"`
	ReadOnly            bool     `json:"read_only"`
}

func (r EnvironmentMountRequest) Validate() error {
	if err := r.NativeEnvironmentID.Validate(); err != nil {
		return err
	}
	if err := validateID("mount_id", r.MountID); err != nil {
		return err
	}
	return validateOpaqueReference("resource_reference", r.ResourceReference)
}

type EnvironmentHealthRequest = EnvironmentInspectRequest
type EnvironmentShutdownRequest = EnvironmentInspectRequest

type EnvironmentResult struct {
	Environment Environment `json:"environment"`
}

func (r EnvironmentResult) Validate() error { return r.Environment.Validate() }
