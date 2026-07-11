package protocol

import (
	"encoding/json"
	"fmt"
)

type ProviderManifest struct {
	ProtocolVersion     string                     `json:"protocol_version"`
	ID                  string                     `json:"id"`
	Roles               []ProviderRole             `json:"roles"`
	Name                string                     `json:"name"`
	Version             string                     `json:"version"`
	Executable          string                     `json:"executable"`
	Platforms           []Platform                 `json:"platforms"`
	Capabilities        []CapabilityDescriptor     `json:"capabilities"`
	InteractionModes    []string                   `json:"interaction_modes"`
	Permissions         []string                   `json:"permissions"`
	ConfigurationSchema string                     `json:"configuration_schema"`
	Extensions          map[string]json.RawMessage `json:"extensions"`
}

func (m ProviderManifest) Validate() error {
	if err := validateProtocol(m.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("id", m.ID); err != nil {
		return err
	}
	if len(m.Roles) == 0 || len(m.Roles) > 4 {
		return fmt.Errorf("provider roles are required")
	}
	roles := make(map[ProviderRole]struct{}, len(m.Roles))
	for _, role := range m.Roles {
		if err := role.validateConcern(); err != nil {
			return err
		}
		if _, duplicate := roles[role]; duplicate {
			return fmt.Errorf("provider role is duplicated")
		}
		roles[role] = struct{}{}
	}
	if err := validateText("name", m.Name, 256); err != nil {
		return err
	}
	if err := validateVersion("version", m.Version); err != nil {
		return err
	}
	if err := validateExecutable(m.Executable); err != nil {
		return err
	}
	if len(m.Platforms) == 0 || len(m.Platforms) > 32 {
		return fmt.Errorf("platforms are required")
	}
	seenPlatforms := make(map[Platform]struct{}, len(m.Platforms))
	for _, platform := range m.Platforms {
		if err := platform.Validate(); err != nil {
			return err
		}
		if _, duplicate := seenPlatforms[platform]; duplicate {
			return fmt.Errorf("platform is duplicated")
		}
		seenPlatforms[platform] = struct{}{}
	}
	if len(m.Capabilities) == 0 || len(m.Capabilities) > 256 {
		return fmt.Errorf("capabilities are required")
	}
	seen := make(map[CapabilityName]struct{}, len(m.Capabilities))
	for _, capability := range m.Capabilities {
		if err := capability.Validate(); err != nil {
			return err
		}
		if capability.Role != RoleProvider {
			if _, supported := roles[capability.Role]; !supported {
				return fmt.Errorf("capability role is not one of the provider roles")
			}
		}
		if known, ok := Capability(capability.Name); ok && !equalCapabilityDefinition(capability, known) {
			return fmt.Errorf("known capability metadata does not match the protocol definition")
		}
		if _, duplicate := seen[capability.Name]; duplicate {
			return fmt.Errorf("capability is duplicated")
		}
		seen[capability.Name] = struct{}{}
	}
	if len(m.InteractionModes) == 0 || len(m.InteractionModes) > 32 {
		return fmt.Errorf("interaction modes are required")
	}
	if err := validateTokenSet("interaction_modes", m.InteractionModes, 32); err != nil {
		return err
	}
	if len(m.Permissions) > 64 {
		return fmt.Errorf("too many permissions")
	}
	if err := validateTokenSet("permissions", m.Permissions, 64); err != nil {
		return err
	}
	if err := validateLocalSchemaRef(m.ConfigurationSchema); err != nil {
		return err
	}
	if err := rejectReservedExtensions(m.Extensions); err != nil {
		return err
	}
	return validateExtensions(m.Extensions)
}

func (m ProviderManifest) Supports(name CapabilityName) bool {
	for _, capability := range m.Capabilities {
		if capability.Name == name {
			return true
		}
	}
	return false
}

func (m ProviderManifest) Capability(name CapabilityName) (CapabilityDescriptor, bool) {
	for _, capability := range m.Capabilities {
		if capability.Name == name {
			return capability, true
		}
	}
	return CapabilityDescriptor{}, false
}

func validateTokenSet(field string, values []string, maximum int) error {
	if len(values) > maximum {
		return fmt.Errorf("%s contains too many values", field)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateToken(field, value); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("%s contains a duplicate", field)
		}
		seen[value] = struct{}{}
	}
	return nil
}

type ProviderInitializeRequest struct {
	SupportedProtocolVersions []string         `json:"supported_protocol_versions"`
	GatewayVersion            string           `json:"gateway_version"`
	Platform                  Platform         `json:"platform"`
	RequiredCapabilities      []CapabilityName `json:"required_capabilities"`
	MaximumMessageBytes       uint64           `json:"maximum_message_bytes"`
	MaximumChunkBytes         uint64           `json:"maximum_chunk_bytes"`
	ReplaySupported           bool             `json:"replay_supported"`
	AuthenticationModes       []string         `json:"authentication_modes"`
	ExperimentalFeatures      []string         `json:"experimental_features"`
}

func (r ProviderInitializeRequest) Validate() error {
	if len(r.SupportedProtocolVersions) == 0 || len(r.SupportedProtocolVersions) > 8 {
		return fmt.Errorf("supported protocol versions are invalid")
	}
	if err := validateUniqueStrings("supported_protocol_versions", r.SupportedProtocolVersions); err != nil {
		return err
	}
	for _, version := range r.SupportedProtocolVersions {
		if err := validateVersion("supported protocol version", version); err != nil {
			return err
		}
	}
	if err := validateVersion("gateway_version", r.GatewayVersion); err != nil {
		return err
	}
	if err := r.Platform.Validate(); err != nil {
		return err
	}
	if len(r.RequiredCapabilities) > 256 {
		return fmt.Errorf("too many required capabilities")
	}
	seen := make(map[CapabilityName]struct{}, len(r.RequiredCapabilities))
	for _, capability := range r.RequiredCapabilities {
		if !validCapabilityName(capability) {
			return fmt.Errorf("required capability is invalid")
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("required capability is duplicated")
		}
		seen[capability] = struct{}{}
	}
	if r.MaximumMessageBytes == 0 || r.MaximumMessageBytes > MaxMessageBytes {
		return fmt.Errorf("maximum message size is invalid")
	}
	if r.MaximumChunkBytes == 0 || r.MaximumChunkBytes > MaxTerminalChunkBytes {
		return fmt.Errorf("maximum chunk size is invalid")
	}
	if r.MaximumChunkBytes > r.MaximumMessageBytes {
		return fmt.Errorf("maximum chunk size exceeds the message size")
	}
	if len(r.AuthenticationModes) == 0 {
		return fmt.Errorf("authentication modes are required")
	}
	if err := validateTokenSet("authentication_modes", r.AuthenticationModes, 16); err != nil {
		return err
	}
	return validateTokenSet("experimental_features", r.ExperimentalFeatures, 64)
}

type ProviderInitializeResult struct {
	ProtocolVersion      string           `json:"protocol_version"`
	Manifest             ProviderManifest `json:"manifest"`
	NativeRuntimeVersion string           `json:"native_runtime_version,omitempty"`
	MaximumMessageBytes  uint64           `json:"maximum_message_bytes"`
	MaximumChunkBytes    uint64           `json:"maximum_chunk_bytes"`
	ReplaySupported      bool             `json:"replay_supported"`
	AuthenticationMode   string           `json:"authentication_mode"`
	ExperimentalFeatures []string         `json:"experimental_features"`
}

func (r ProviderInitializeResult) Validate() error {
	if err := validateProtocol(r.ProtocolVersion); err != nil {
		return err
	}
	if err := r.Manifest.Validate(); err != nil {
		return err
	}
	if r.NativeRuntimeVersion != "" {
		if err := validateVersion("native_runtime_version", r.NativeRuntimeVersion); err != nil {
			return err
		}
	}
	if r.MaximumMessageBytes == 0 || r.MaximumMessageBytes > MaxMessageBytes {
		return fmt.Errorf("maximum message size is invalid")
	}
	if r.MaximumChunkBytes == 0 || r.MaximumChunkBytes > MaxTerminalChunkBytes {
		return fmt.Errorf("maximum chunk size is invalid")
	}
	if r.MaximumChunkBytes > r.MaximumMessageBytes {
		return fmt.Errorf("maximum chunk size exceeds the message size")
	}
	if err := validateToken("authentication_mode", r.AuthenticationMode); err != nil {
		return err
	}
	return validateTokenSet("experimental_features", r.ExperimentalFeatures, 64)
}

// ValidateProviderNegotiation proves that an individually valid provider
// response is a compatible selection from the gateway's initialization offer.
func ValidateProviderNegotiation(request ProviderInitializeRequest, result ProviderInitializeResult) error {
	if err := request.Validate(); err != nil {
		return fmt.Errorf("provider initialization request is invalid: %w", err)
	}
	if err := result.Validate(); err != nil {
		return fmt.Errorf("provider initialization result is invalid: %w", err)
	}
	if !containsString(request.SupportedProtocolVersions, result.ProtocolVersion) {
		return fmt.Errorf("provider selected an unsupported protocol version")
	}
	platformSupported := false
	for _, platform := range result.Manifest.Platforms {
		if platform == request.Platform {
			platformSupported = true
			break
		}
	}
	if !platformSupported {
		return fmt.Errorf("provider does not support the gateway platform")
	}
	for _, capability := range request.RequiredCapabilities {
		if !result.Manifest.Supports(capability) {
			return fmt.Errorf("provider does not support a required capability")
		}
	}
	if result.MaximumMessageBytes > request.MaximumMessageBytes || result.MaximumChunkBytes > request.MaximumChunkBytes {
		return fmt.Errorf("provider selected a limit above the gateway offer")
	}
	if result.ReplaySupported && !request.ReplaySupported {
		return fmt.Errorf("provider selected unsupported replay behavior")
	}
	if !containsString(request.AuthenticationModes, result.AuthenticationMode) {
		return fmt.Errorf("provider selected an unsupported authentication mode")
	}
	for _, feature := range result.ExperimentalFeatures {
		if !containsString(request.ExperimentalFeatures, feature) {
			return fmt.Errorf("provider selected an unoffered experimental feature")
		}
	}
	return nil
}

type ProviderHealthRequest struct{}

func (ProviderHealthRequest) Validate() error { return nil }

type ProviderHealthResult struct {
	ProviderID string      `json:"provider_id"`
	Health     StateReport `json:"health"`
}

func (r ProviderHealthResult) Validate() error {
	if err := validateID("provider_id", r.ProviderID); err != nil {
		return err
	}
	return r.Health.validate(AxisHealth)
}

type ProviderCapabilitiesRequest struct{}

func (ProviderCapabilitiesRequest) Validate() error { return nil }

type ProviderCapabilitiesResult struct {
	ProviderID   string                 `json:"provider_id"`
	Roles        []ProviderRole         `json:"roles"`
	Capabilities []CapabilityDescriptor `json:"capabilities"`
}

func (r ProviderCapabilitiesResult) Validate() error {
	if err := validateID("provider_id", r.ProviderID); err != nil {
		return err
	}
	if len(r.Roles) == 0 || len(r.Roles) > 4 {
		return fmt.Errorf("provider roles are required")
	}
	roles := make(map[ProviderRole]struct{}, len(r.Roles))
	for _, role := range r.Roles {
		if err := role.validateConcern(); err != nil {
			return err
		}
		if _, duplicate := roles[role]; duplicate {
			return fmt.Errorf("provider role is duplicated")
		}
		roles[role] = struct{}{}
	}
	if len(r.Capabilities) == 0 || len(r.Capabilities) > 256 {
		return fmt.Errorf("provider capabilities are required")
	}
	seen := make(map[CapabilityName]struct{}, len(r.Capabilities))
	for _, capability := range r.Capabilities {
		if err := capability.Validate(); err != nil {
			return err
		}
		if capability.Role != RoleProvider {
			if _, supported := roles[capability.Role]; !supported {
				return fmt.Errorf("capability role is not one of the provider roles")
			}
		}
		if known, ok := Capability(capability.Name); ok && !equalCapabilityDefinition(capability, known) {
			return fmt.Errorf("known capability metadata does not match the protocol definition")
		}
		if _, duplicate := seen[capability.Name]; duplicate {
			return fmt.Errorf("capability is duplicated")
		}
		seen[capability.Name] = struct{}{}
	}
	return nil
}

type ProviderShutdownRequest struct{}

func (ProviderShutdownRequest) Validate() error { return nil }
