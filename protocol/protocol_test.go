package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

var fixtureNow = time.Date(2026, 7, 11, 12, 30, 0, 0, time.UTC)

type signingVectorsFixture struct {
	SchemaVersion   int                         `json:"schema_version"`
	ProtocolVersion string                      `json:"protocol_version"`
	Encoding        string                      `json:"encoding"`
	Keys            map[string]signingVectorKey `json:"keys"`
	Vectors         []signingVector             `json:"vectors"`
}

type signingVectorKey struct {
	SeedBase64URL      string `json:"seed_base64url"`
	PublicKeyBase64URL string `json:"public_key_base64url"`
}

type signingVector struct {
	Name               string          `json:"name"`
	Purpose            string          `json:"purpose"`
	Key                string          `json:"key"`
	Document           json.RawMessage `json:"document"`
	PreimageBase64URL  string          `json:"preimage_base64url"`
	SignatureBase64URL string          `json:"signature_base64url"`
}

func TestValidFixturesRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file string
		new  func() any
	}{
		{name: "harness manifest", file: "provider-manifest-harness.json", new: func() any { return new(protocol.ProviderManifest) }},
		{name: "runtime manifest", file: "provider-manifest-runtime.json", new: func() any { return new(protocol.ProviderManifest) }},
		{name: "environment manifest", file: "provider-manifest-environment.json", new: func() any { return new(protocol.ProviderManifest) }},
		{name: "orchestration manifest", file: "provider-manifest-orchestration.json", new: func() any { return new(protocol.ProviderManifest) }},
		{name: "multi-role manifest", file: "provider-manifest-composed.json", new: func() any { return new(protocol.ProviderManifest) }},
		{name: "composed terminal session", file: "session-terminal.json", new: func() any { return new(protocol.Session) }},
		{name: "non-terminal session", file: "session-document.json", new: func() any { return new(protocol.Session) }},
		{name: "provider event", file: "provider-event.json", new: func() any { return new(protocol.ProviderEvent) }},
		{name: "provider artifact event", file: "provider-artifact-event.json", new: func() any { return new(protocol.ProviderEvent) }},
		{name: "canonical event", file: "canonical-event.json", new: func() any { return new(protocol.CanonicalEvent) }},
		{name: "command", file: "command.json", new: func() any { return new(protocol.Command) }},
		{name: "context receipt", file: "context-receipt.json", new: func() any { return new(protocol.ContextReceipt) }},
		{name: "failed context receipt", file: "context-receipt-failed.json", new: func() any { return new(protocol.ContextReceipt) }},
		{name: "approved decision", file: "approval-decision-approved.json", new: func() any { return new(protocol.ApprovalDecision) }},
		{name: "rejected decision", file: "approval-decision-rejected.json", new: func() any { return new(protocol.ApprovalDecision) }},
		{name: "local artifact", file: "artifact-local.json", new: func() any { return new(protocol.Artifact) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := readFixture(t, "valid", tt.file)
			value := tt.new()
			if err := protocol.Decode(data, value); err != nil {
				t.Fatalf("Decode(%s): %v", tt.file, err)
			}
			roundTrip, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("Marshal(%s): %v", tt.file, err)
			}
			if got, want := decodeJSONValue(t, roundTrip), decodeJSONValue(t, data); !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip lost or changed fixture fields for %s\ninput: %s\noutput: %s", tt.file, data, roundTrip)
			}
			clone := tt.new()
			if err := protocol.Decode(roundTrip, clone); err != nil {
				t.Fatalf("Decode(round trip %s): %v", tt.file, err)
			}
			cloneJSON, err := json.Marshal(clone)
			if err != nil {
				t.Fatalf("Marshal(round trip %s): %v", tt.file, err)
			}
			if !bytes.Equal(roundTrip, cloneJSON) {
				t.Fatalf("round trip JSON mismatch for %s\nfirst: %s\nclone: %s", tt.file, roundTrip, cloneJSON)
			}
		})
	}
}

func TestInvalidFixturesFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		file string
		new  func() any
		code protocol.ErrorCode
	}{
		{file: "manifest-provider-scope.json", new: func() any { return new(protocol.ProviderManifest) }, code: protocol.CodePermissionDenied},
		{file: "manifest-self-verification.json", new: func() any { return new(protocol.ProviderManifest) }, code: protocol.CodePermissionDenied},
		{file: "manifest-extension-traversal.json", new: func() any { return new(protocol.ProviderManifest) }, code: protocol.CodeInvalidArgument},
		{file: "manifest-unknown-role.json", new: func() any { return new(protocol.ProviderManifest) }, code: protocol.CodeInvalidArgument},
		{file: "manifest-mutating-without-delivery.json", new: func() any { return new(protocol.ProviderManifest) }, code: protocol.CodeInvalidArgument},
		{file: "event-provider-scope.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodePermissionDenied},
		{file: "event-self-verification.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodePermissionDenied},
		{file: "event-zero-id.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodeInvalidArgument},
		{file: "event-duplicate-key.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodeInvalidArgument},
		{file: "event-nested-duplicate-key.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodeInvalidArgument},
		{file: "event-payload-authority.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodePermissionDenied},
		{file: "event-extension-authority.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodePermissionDenied},
		{file: "event-artifact-approved-smuggling.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodePermissionDenied},
		{file: "event-artifact-hosted-smuggling.json", new: func() any { return new(protocol.ProviderEvent) }, code: protocol.CodeInvalidArgument},
		{file: "session-unknown-state.json", new: func() any { return new(protocol.Session) }, code: protocol.CodeInvalidArgument},
		{file: "command-missing-idempotency.json", new: func() any { return new(protocol.Command) }, code: protocol.CodeInvalidArgument},
		{file: "command-unknown-field.json", new: func() any { return new(protocol.Command) }, code: protocol.CodeInvalidArgument},
		{file: "artifact-raw-local-path.json", new: func() any { return new(protocol.Artifact) }, code: protocol.CodeInvalidArgument},
		{file: "artifact-unknown-locality.json", new: func() any { return new(protocol.Artifact) }, code: protocol.CodeInvalidArgument},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			if err := protocol.Decode(readFixture(t, "invalid", tt.file), tt.new()); !protocol.IsCode(err, tt.code) {
				t.Fatalf("Decode(%s) error = %v, want %s", tt.file, err, tt.code)
			}
		})
	}
}

func TestDecodeRejectsOversizedMessages(t *testing.T) {
	t.Parallel()

	data := bytes.Repeat([]byte{'x'}, protocol.MaxMessageBytes+1)
	var event protocol.ProviderEvent
	if err := protocol.Decode(data, &event); !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		t.Fatalf("Decode oversized error = %v, want %s", err, protocol.CodeMessageTooLarge)
	}
}

func TestNativeIDRemainsOpaque(t *testing.T) {
	t.Parallel()

	accepted := []protocol.NativeID{
		"../../native/value",
		"opaque://provider/session?x=a%2Fb",
		"workspace:tab:pane:agent",
	}
	for _, id := range accepted {
		if err := id.Validate(); err != nil {
			t.Errorf("NativeID(%q).Validate(): %v", id, err)
		}
	}
	for _, id := range []protocol.NativeID{"", "contains\x00nul", "line\nbreak"} {
		if err := id.Validate(); err == nil {
			t.Errorf("NativeID(%q).Validate() succeeded", id)
		}
	}
}

func TestCapabilityCatalogIsProviderNeutral(t *testing.T) {
	t.Parallel()

	catalog := protocol.KnownCapabilities()
	want := requiredCapabilityMatrix()
	if len(catalog) != len(want) {
		t.Errorf("KnownCapabilities() returned %d entries, want exact v1alpha1 catalog of %d", len(catalog), len(want))
	}
	seen := map[protocol.CapabilityName]protocol.CapabilityDescriptor{}
	for _, capability := range catalog {
		if err := capability.Validate(); err != nil {
			t.Errorf("capability %q invalid: %v", capability.Name, err)
		}
		if _, duplicate := seen[capability.Name]; duplicate {
			t.Errorf("duplicate capability %q", capability.Name)
		}
		seen[capability.Name] = capability
		lower := strings.ToLower(string(capability.Name))
		for _, vendor := range []string{"ratchet", "herdr", "codex", "claude", "tmux"} {
			if strings.Contains(lower, vendor) {
				t.Errorf("capability %q leaks provider %q", capability.Name, vendor)
			}
		}
	}
	for name, expected := range want {
		got, ok := seen[name]
		if !ok {
			t.Errorf("catalog missing %q", name)
			continue
		}
		if got.Role != expected.Role || got.Mutating != expected.Mutating || got.DeliveryClass != expected.DeliveryClass {
			t.Errorf("capability %q semantics = role %q mutating=%t delivery=%q, want role %q mutating=%t delivery=%q", name, got.Role, got.Mutating, got.DeliveryClass, expected.Role, expected.Mutating, expected.DeliveryClass)
		}
	}
}

func TestProviderManifestAdvertisesOnlyItsRole(t *testing.T) {
	t.Parallel()

	manifest := decodeFixture[protocol.ProviderManifest](t, "valid", "provider-manifest-runtime.json")
	if !reflect.DeepEqual(manifest.Roles, []protocol.ProviderRole{protocol.RoleSessionRuntime}) {
		t.Fatalf("runtime manifest roles = %v", manifest.Roles)
	}
	manifest.Capabilities = append(manifest.Capabilities, protocol.CapabilityDescriptor{
		Name: "harness.launch", Role: protocol.RoleAgentHarness, Mutating: true, DeliveryClass: protocol.DeliveryAtMostOnce,
	})
	if err := manifest.Validate(); err == nil {
		t.Fatal("runtime manifest accepted harness capability")
	}

	manifest = decodeFixture[protocol.ProviderManifest](t, "valid", "provider-manifest-runtime.json")
	manifest.Extensions["example.dev/authority"] = json.RawMessage(`{"nested":{"tenant_id":"tenant-forged"}}`)
	if err := manifest.Validate(); err == nil {
		t.Fatal("direct manifest validation accepted nested canonical authority")
	}
}

func TestProviderManifestConfigurationSchemaIsLocal(t *testing.T) {
	t.Parallel()

	base := decodeFixture[protocol.ProviderManifest](t, "valid", "provider-manifest-runtime.json")
	manifestSchema := readSchema(t, "provider-manifest.v1alpha1.schema.json")
	for _, reference := range []string{"schema.json", "schemas/provider-v1.json"} {
		candidate := base
		candidate.ConfigurationSchema = reference
		if err := candidate.Validate(); err != nil {
			t.Errorf("local configuration schema %q rejected: %v", reference, err)
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRawSchema(manifestSchema, manifestSchema, data); err != nil {
			t.Errorf("manifest schema rejected local configuration schema %q: %v", reference, err)
		}
	}
	for _, reference := range []string{"https://example.invalid/schema.json", "/absolute/schema.json", "../schema.json", "schemas/foo..json", `schemas\\provider.json`} {
		candidate := base
		candidate.ConfigurationSchema = reference
		if err := candidate.Validate(); err == nil {
			t.Errorf("non-local configuration schema %q accepted", reference)
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRawSchema(manifestSchema, manifestSchema, data); err == nil {
			t.Errorf("manifest schema accepted non-local configuration schema %q", reference)
		}
	}
}

func TestGeneratedSchemasMatchGoTextSemantics(t *testing.T) {
	t.Parallel()

	manifest := decodeFixture[protocol.ProviderManifest](t, "valid", "provider-manifest-runtime.json")
	manifestSchema := readSchema(t, "provider-manifest.v1alpha1.schema.json")
	for _, executable := range []string{"my provider", "..."} {
		candidate := manifest
		candidate.Executable = executable
		if err := candidate.Validate(); err != nil {
			t.Fatalf("Go rejected executable %q: %v", executable, err)
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRawSchema(manifestSchema, manifestSchema, data); err != nil {
			t.Errorf("generated schema rejected Go-valid executable %q: %v", executable, err)
		}
	}
	for _, executable := range []string{".", "..", "bin/provider", `bin\provider`, "provider\nname"} {
		candidate := manifest
		candidate.Executable = executable
		if err := candidate.Validate(); err == nil {
			t.Fatalf("Go accepted invalid executable %q", executable)
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRawSchema(manifestSchema, manifestSchema, data); err == nil {
			t.Errorf("generated schema accepted invalid executable %q", executable)
		}
	}

	session := decodeFixture[protocol.Session](t, "valid", "session-terminal.json")
	session.Lifecycle.Source = "human operator"
	if err := session.Validate(); err != nil {
		t.Fatalf("Go rejected state source containing spaces: %v", err)
	}
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	sessionSchema := readSchema(t, "session.v1alpha1.schema.json")
	if err := validateRawSchema(sessionSchema, sessionSchema, data); err != nil {
		t.Fatalf("generated schema rejected Go-valid state source: %v", err)
	}

	session.Lifecycle.Source = "human\noperator"
	if err := session.Validate(); err == nil {
		t.Fatal("Go accepted a state source containing a newline")
	}
	data, err = json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(sessionSchema, sessionSchema, data); err == nil {
		t.Fatal("generated schema accepted a state source containing a newline")
	}
}

func TestProviderInitializationNegotiatesPlatformAndLimits(t *testing.T) {
	t.Parallel()

	request := protocol.ProviderInitializeRequest{
		SupportedProtocolVersions: []string{protocol.ProtocolVersion},
		GatewayVersion:            "v0.1.0",
		Platform:                  protocol.Platform{OS: "linux", Architecture: "arm64"},
		RequiredCapabilities:      []protocol.CapabilityName{"provider.health"},
		MaximumMessageBytes:       protocol.MaxMessageBytes / 2,
		MaximumChunkBytes:         protocol.MaxTerminalChunkBytes / 2,
		ReplaySupported:           true,
		AuthenticationModes:       []string{"local-socket"},
		ExperimentalFeatures:      []string{},
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid provider initialization request rejected: %v", err)
	}
	request.Platform = protocol.Platform{}
	if err := request.Validate(); err == nil {
		t.Fatal("provider initialization accepted a missing gateway platform")
	}
	request.Platform = protocol.Platform{OS: "linux", Architecture: "arm64"}
	request.MaximumMessageBytes = 1024
	request.MaximumChunkBytes = 2048
	if err := request.Validate(); err == nil {
		t.Fatal("provider initialization accepted a chunk limit larger than its message limit")
	}
}

func TestProviderInitializationNegotiationIsCompatible(t *testing.T) {
	t.Parallel()

	manifest := decodeFixture[protocol.ProviderManifest](t, "valid", "provider-manifest-runtime.json")
	request := protocol.ProviderInitializeRequest{
		SupportedProtocolVersions: []string{protocol.ProtocolVersion},
		GatewayVersion:            "v0.1.0",
		Platform:                  protocol.Platform{OS: "darwin", Architecture: "arm64"},
		RequiredCapabilities:      []protocol.CapabilityName{"provider.initialize", "runtime.create_session"},
		MaximumMessageBytes:       protocol.MaxMessageBytes / 2,
		MaximumChunkBytes:         protocol.MaxTerminalChunkBytes / 2,
		ReplaySupported:           true,
		AuthenticationModes:       []string{"local-socket", "stdio"},
		ExperimentalFeatures:      []string{"event-batching"},
	}
	result := protocol.ProviderInitializeResult{
		ProtocolVersion:      protocol.ProtocolVersion,
		Manifest:             manifest,
		NativeRuntimeVersion: "v1.0.0",
		MaximumMessageBytes:  request.MaximumMessageBytes,
		MaximumChunkBytes:    request.MaximumChunkBytes,
		ReplaySupported:      true,
		AuthenticationMode:   "local-socket",
		ExperimentalFeatures: []string{"event-batching"},
	}
	if err := protocol.ValidateProviderNegotiation(request, result); err != nil {
		t.Fatalf("compatible provider negotiation rejected: %v", err)
	}

	mutations := map[string]func(*protocol.ProviderInitializeResult){
		"protocol": func(value *protocol.ProviderInitializeResult) { value.ProtocolVersion = "mission-control.provider.v2" },
		"platform": func(value *protocol.ProviderInitializeResult) {
			value.Manifest.Platforms = []protocol.Platform{{OS: "linux", Architecture: "amd64"}}
		},
		"capability": func(value *protocol.ProviderInitializeResult) {
			value.Manifest.Capabilities = value.Manifest.Capabilities[:1]
		},
		"message limit": func(value *protocol.ProviderInitializeResult) {
			value.MaximumMessageBytes = request.MaximumMessageBytes + 1
		},
		"chunk limit": func(value *protocol.ProviderInitializeResult) {
			value.MaximumChunkBytes = request.MaximumChunkBytes + 1
		},
		"replay":    func(value *protocol.ProviderInitializeResult) { value.ReplaySupported = true },
		"auth mode": func(value *protocol.ProviderInitializeResult) { value.AuthenticationMode = "mtls" },
		"feature": func(value *protocol.ProviderInitializeResult) {
			value.ExperimentalFeatures = []string{"undeclared-feature"}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidateRequest := request
			candidate := result
			candidate.Manifest.Platforms = append([]protocol.Platform(nil), result.Manifest.Platforms...)
			candidate.Manifest.Capabilities = append([]protocol.CapabilityDescriptor(nil), result.Manifest.Capabilities...)
			if name == "replay" {
				candidateRequest.ReplaySupported = false
			}
			mutate(&candidate)
			if err := protocol.ValidateProviderNegotiation(candidateRequest, candidate); err == nil {
				t.Fatal("incompatible provider negotiation accepted")
			}
		})
	}
}

func TestKnownCapabilitySemanticsCannotBeDowngraded(t *testing.T) {
	t.Parallel()

	base := decodeFixture[protocol.ProviderManifest](t, "valid", "provider-manifest-runtime.json")
	index := -1
	for i := range base.Capabilities {
		if base.Capabilities[i].Name == "runtime.create_session" {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("runtime fixture lacks runtime.create_session")
	}
	mutations := map[string]func(*protocol.CapabilityDescriptor){
		"read-only downgrade": func(value *protocol.CapabilityDescriptor) {
			value.Mutating = false
			value.DeliveryClass = ""
		},
		"delivery-class change": func(value *protocol.CapabilityDescriptor) {
			value.DeliveryClass = protocol.DeliveryAtMostOnce
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Roles = append([]protocol.ProviderRole(nil), base.Roles...)
			candidate.Capabilities = append([]protocol.CapabilityDescriptor(nil), base.Capabilities...)
			mutate(&candidate.Capabilities[index])
			if err := candidate.Validate(); err == nil {
				t.Fatal("known capability semantics were changed by a manifest")
			}
		})
	}
}

func TestStateAxesRemainIndependent(t *testing.T) {
	t.Parallel()

	session := decodeFixture[protocol.Session](t, "valid", "session-terminal.json")
	if session.Lifecycle.State != protocol.LifecycleRunning {
		t.Fatalf("lifecycle = %q", session.Lifecycle.State)
	}
	if session.Activity.State != protocol.ActivityWaitingForApproval {
		t.Fatalf("activity = %q", session.Activity.State)
	}
	if session.Health.State != protocol.HealthDegraded {
		t.Fatalf("health = %q", session.Health.State)
	}
	for axis, report := range map[string]protocol.StateReport{
		"lifecycle": session.Lifecycle,
		"activity":  session.Activity,
		"health":    session.Health,
	} {
		if report.Source == "" || report.ObservedAt.IsZero() || report.Sequence == 0 || report.Confidence <= 0 || report.Authority == "" {
			t.Errorf("%s report lacks provenance: %#v", axis, report)
		}
	}
}

func TestSequenceTrackerDistinguishesReplayGapAndConflict(t *testing.T) {
	t.Parallel()

	tracker := protocol.NewSequenceTracker()
	first := protocol.EventCursor{ProviderID: "provider-a", Role: protocol.RoleAgentHarness, StreamID: "shared-stream-id", EventID: "evt-1", Sequence: 1, Digest: digest("one")}
	if got, err := tracker.Observe(first); err != nil || got != protocol.SequenceAccepted {
		t.Fatalf("first Observe() = %q, %v", got, err)
	}
	if got, err := tracker.Observe(first); err != nil || got != protocol.SequenceDuplicate {
		t.Fatalf("duplicate Observe() = %q, %v", got, err)
	}
	collision := first
	collision.EventID = "evt-forged"
	if _, err := tracker.Observe(collision); !protocol.IsCode(err, protocol.CodeSequenceConflict) {
		t.Fatalf("collision error = %v", err)
	}
	if _, err := tracker.Observe(protocol.EventCursor{ProviderID: "provider-a", Role: protocol.RoleAgentHarness, StreamID: "shared-stream-id", EventID: first.EventID, Sequence: 2, Digest: digest("different-sequence")}); !protocol.IsCode(err, protocol.CodeSequenceConflict) {
		t.Fatalf("event ID rebound to a new sequence error = %v", err)
	}
	if got, err := tracker.Observe(protocol.EventCursor{ProviderID: "provider-a", Role: protocol.RoleAgentHarness, StreamID: "shared-stream-id", EventID: "evt-3", Sequence: 3, Digest: digest("three")}); err != nil || got != protocol.SequenceGap {
		t.Fatalf("gap Observe() = %q, %v", got, err)
	}
	if got, err := tracker.Observe(protocol.EventCursor{ProviderID: "provider-b", Role: protocol.RoleAgentHarness, StreamID: "shared-stream-id", EventID: "evt-b-1", Sequence: 1, Digest: digest("other")}); err != nil || got != protocol.SequenceAccepted {
		t.Fatalf("same stream ID on another provider Observe() = %q, %v", got, err)
	}
	if got, err := tracker.Observe(protocol.EventCursor{ProviderID: "provider-a", Role: protocol.RoleSessionRuntime, StreamID: "shared-stream-id", EventID: "evt-runtime-1", Sequence: 1, Digest: digest("runtime")}); err != nil || got != protocol.SequenceAccepted {
		t.Fatalf("same provider/stream ID under another role Observe() = %q, %v", got, err)
	}
}

func TestSequenceTrackerScopesEventIDsToProviderRoleAndStream(t *testing.T) {
	t.Parallel()

	tracker := protocol.NewSequenceTracker()
	base := protocol.EventCursor{ProviderID: "provider-a", Role: protocol.RoleAgentHarness, StreamID: "stream-a", EventID: "provider-local-event-1", Sequence: 1, Digest: digest("base")}
	if got, err := tracker.Observe(base); err != nil || got != protocol.SequenceAccepted {
		t.Fatalf("base Observe() = %q, %v", got, err)
	}
	independent := []protocol.EventCursor{
		{ProviderID: "provider-b", Role: base.Role, StreamID: base.StreamID, EventID: base.EventID, Sequence: 1, Digest: digest("other-provider")},
		{ProviderID: base.ProviderID, Role: protocol.RoleSessionRuntime, StreamID: base.StreamID, EventID: base.EventID, Sequence: 1, Digest: digest("other-role")},
		{ProviderID: base.ProviderID, Role: base.Role, StreamID: "stream-b", EventID: base.EventID, Sequence: 1, Digest: digest("other-stream")},
	}
	for _, cursor := range independent {
		if got, err := tracker.Observe(cursor); err != nil || got != protocol.SequenceAccepted {
			t.Errorf("independent namespace %#v Observe() = %q, %v", cursor, got, err)
		}
	}
}

func TestCanonicalEventSessionScopeIsConditional(t *testing.T) {
	t.Parallel()

	providerEvent := protocol.ProviderEvent{
		ProtocolVersion: protocol.ProtocolVersion,
		EventID:         "provider-health-1",
		ProviderID:      "provider-a",
		Role:            protocol.RoleProvider,
		StreamID:        "provider-stream",
		Type:            "adapter.degraded",
		Sequence:        1,
		ObservedAt:      fixtureNow,
		Payload:         json.RawMessage(`{}`),
		Extensions:      map[string]json.RawMessage{},
	}
	canonical := protocol.CanonicalEvent{
		ProtocolVersion: protocol.ProtocolVersion,
		TenantID:        "tenant-1",
		GatewayID:       "gateway-1",
		CorrelationID:   "correlation-1",
		Sensitivity:     protocol.SensitivityMetadata,
		Authority:       "gateway-assigned",
		ProviderEvent:   providerEvent,
	}
	if err := canonical.Validate(); err != nil {
		t.Fatalf("provider-level canonical event without session rejected: %v", err)
	}

	sessionEvent := providerEvent
	sessionEvent.EventID = "session-event-1"
	sessionEvent.Role = protocol.RoleAgentHarness
	sessionEvent.StreamID = "session-stream"
	sessionEvent.NativeSessionID = "native-session-1"
	sessionEvent.Type = "session.completed"
	canonical.ProviderEvent = sessionEvent
	if err := canonical.Validate(); err == nil {
		t.Fatal("session-scoped canonical event without canonical session accepted")
	}
}

func TestArtifactEventsBindTypedProviderIdentity(t *testing.T) {
	t.Parallel()

	event := decodeFixture[protocol.ProviderEvent](t, "valid", "provider-artifact-event.json")
	var report protocol.ProviderArtifactReport
	if err := json.Unmarshal(event.Payload, &report); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*protocol.ProviderArtifactReport){
		"provider":       func(value *protocol.ProviderArtifactReport) { value.ProviderID = "provider-other" },
		"role":           func(value *protocol.ProviderArtifactReport) { value.Role = protocol.RoleSessionRuntime },
		"stream":         func(value *protocol.ProviderArtifactReport) { value.StreamID = "stream-other" },
		"native session": func(value *protocol.ProviderArtifactReport) { value.NativeSessionID = "native-session-other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidateReport := report
			mutate(&candidateReport)
			payload, err := json.Marshal(candidateReport)
			if err != nil {
				t.Fatal(err)
			}
			candidate := event
			candidate.Payload = payload
			if err := candidate.Validate(); err == nil {
				t.Fatal("artifact event with mismatched provider identity accepted")
			}
		})
	}
}

func TestProviderEventTypesCannotSynthesizeAuthority(t *testing.T) {
	t.Parallel()

	base := decodeFixture[protocol.ProviderEvent](t, "valid", "provider-event.json")
	eventSchema := readSchema(t, "event.v1alpha1.schema.json")
	base.NativeSessionID = ""
	base.Role = protocol.RoleProvider
	base.StreamID = "provider-stream"
	base.Payload = json.RawMessage(`{}`)
	for _, eventType := range []string{"artifact.approved", "artifact.finalized", "approval.approved", "approval.rejected", "verification.live_verified"} {
		candidate := base
		candidate.Type = eventType
		if err := candidate.Validate(); err == nil {
			t.Errorf("provider authority-bearing event type %q accepted", eventType)
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRawSchema(eventSchema, eventSchema, data); err == nil {
			t.Errorf("event schema accepted provider authority-bearing type %q", eventType)
		}
	}

	extension := base
	extension.Type = "example.dev/custom_event"
	if err := extension.Validate(); err != nil {
		t.Fatalf("namespaced provider extension event rejected: %v", err)
	}
	data, err := json.Marshal(extension)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(eventSchema, eventSchema, data); err != nil {
		t.Fatalf("event schema rejected namespaced provider extension event: %v", err)
	}
}

func TestEventSubscriptionAcceptsNamespacedProviderEvents(t *testing.T) {
	t.Parallel()

	request := protocol.EventsSubscribeRequest{
		Cursors: []protocol.EventSubscriptionCursor{{
			Role:          protocol.RoleProvider,
			StreamID:      "provider-stream",
			AfterSequence: 4,
		}},
		EventTypes: []string{"adapter.degraded", "example.dev/custom_event"},
		WindowSize: 128,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("namespaced event subscription rejected: %v", err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	openRPC := readSchema(t, "openrpc.v1alpha1.json")
	if err := validateRawSchema(openRPC, openRPCMethodSchema(t, openRPC, "events.subscribe", "request"), data); err != nil {
		t.Fatalf("OpenRPC event subscription schema rejected namespaced event: %v", err)
	}
}

func TestCommandDigestBindsExactBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want protocol.Digest
	}{
		{
			name: "compact",
			data: []byte(`{"method":"runtime.create_session","params":{"a":1,"b":2}}`),
			want: "sha256:46e75faf81003f325fb4e605ce019b9157b68b50e5a1d6fad190ef638580eb63",
		},
		{
			name: "different key order",
			data: []byte(`{"params":{"b":2,"a":1},"method":"runtime.create_session"}`),
			want: "sha256:8f8ed49f9d9aa9dd0a9ce63ade086bc8225ed9826a4a36ea1e9309972914c72d",
		},
		{
			name: "different whitespace",
			data: []byte(`{ "method": "runtime.create_session", "params": {"a": 1, "b": 2} }`),
			want: "sha256:92d8c0f8d960200fd9fbebe9e005f0c0e565a9f147b14eb27f09a0e8e17770b3",
		},
	}
	seen := map[protocol.Digest]bool{}
	for _, tt := range tests {
		got, err := protocol.CommandDigest(tt.data)
		if err != nil {
			t.Fatalf("CommandDigest(%s): %v", tt.name, err)
		}
		if got != tt.want {
			t.Errorf("CommandDigest(%s) = %q, want exact-byte golden %q", tt.name, got, tt.want)
		}
		if seen[got] {
			t.Errorf("CommandDigest(%s) reused %q for different bytes", tt.name, got)
		}
		seen[got] = true
	}
	if _, err := protocol.CommandDigest([]byte(`{"broken":`)); err == nil {
		t.Fatal("CommandDigest accepted invalid JSON")
	}
}

func TestCommandSessionScopeFollowsCapability(t *testing.T) {
	t.Parallel()

	base := protocol.Command{
		ProtocolVersion:   protocol.ProtocolVersion,
		CommandID:         "command-scope-1",
		Capability:        "provider.shutdown",
		IdempotencyKey:    "idempotency-key-0001",
		CancellationToken: "cancellation-key-0001",
		Deadline:          fixtureNow.Add(time.Minute),
		DeliveryClass:     protocol.DeliveryProviderIdempotent,
		Payload:           json.RawMessage(`{}`),
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("provider-scoped command without session rejected: %v", err)
	}
	commandSchema := readSchema(t, "command.v1alpha1.schema.json")
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(commandSchema, commandSchema, data); err != nil {
		t.Fatalf("command schema rejected provider-scoped command without session: %v", err)
	}
	base.Capability = "runtime.stop_session"
	if err := base.Validate(); err == nil {
		t.Fatal("session-scoped runtime command accepted without canonical session")
	}
	data, err = json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(commandSchema, commandSchema, data); err == nil {
		t.Fatal("command schema accepted session-scoped runtime command without canonical session")
	}
	base.SessionID = "session_1"
	if err := base.Validate(); err != nil {
		t.Fatalf("session-scoped runtime command rejected with canonical session: %v", err)
	}
}

func TestEmbeddedJSONDigestsBindCompactBytes(t *testing.T) {
	t.Parallel()

	configuration := json.RawMessage("{\n  \"mode\": \"safe\",\n  \"limits\": {\"cpu\": 2}\n}")
	var compact bytes.Buffer
	if err := json.Compact(&compact, configuration); err != nil {
		t.Fatal(err)
	}
	want := digestBytes(compact.Bytes())
	wrong := digest("different-embedded-json")
	tests := []struct {
		name     string
		validate func(protocol.Digest) error
	}{
		{name: "environment provision", validate: func(value protocol.Digest) error {
			return (protocol.EnvironmentProvisionRequest{Configuration: configuration, ConfigurationDigest: value}).Validate()
		}},
		{name: "runtime create", validate: func(value protocol.Digest) error {
			return (protocol.RuntimeCreateSessionRequest{NativeEnvironmentID: "native-environment-1", Configuration: configuration, ConfigurationDigest: value}).Validate()
		}},
		{name: "harness launch", validate: func(value protocol.Digest) error {
			return (protocol.HarnessLaunchRequest{NativeEnvironmentID: "native-environment-1", ContextVersion: "context-v1", Configuration: configuration, ConfigurationDigest: value}).Validate()
		}},
		{name: "agent message", validate: func(value protocol.Digest) error {
			return (protocol.AgentMessageRequest{NativeSessionID: "native-session-1", Message: configuration, MessageDigest: value}).Validate()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.validate(want); err != nil {
				t.Fatalf("compact JSON digest rejected: %v", err)
			}
			if err := tt.validate(wrong); err == nil {
				t.Fatal("mismatched embedded JSON digest accepted")
			}
		})
	}
}

func TestStructuredNotSupportedError(t *testing.T) {
	t.Parallel()

	err := protocol.NotSupported("runtime.fork", []protocol.CapabilityName{"runtime.create_session", "runtime.stop_session"})
	if !protocol.IsCode(err, protocol.CodeNotSupported) {
		t.Fatalf("NotSupported code = %v", err)
	}
	var protocolErr *protocol.Error
	if !errors.As(err, &protocolErr) {
		t.Fatalf("NotSupported type = %T", err)
	}
	if protocolErr.RequiredCapability != "runtime.fork" || len(protocolErr.AdvertisedCapabilities) != 2 {
		t.Fatalf("NotSupported details = %#v", protocolErr)
	}
	if strings.Contains(protocolErr.Error(), "native") {
		t.Fatalf("error leaked untrusted detail: %q", protocolErr.Error())
	}
}

func TestApprovalDecisionBindsCommandAndRevisions(t *testing.T) {
	t.Parallel()

	binding := approvalBinding()
	decision := protocol.ApprovalDecision{
		ProtocolVersion:  protocol.ProtocolVersion,
		ApprovalID:       "approval-1",
		Outcome:          protocol.ApprovalOutcomeApproved,
		Binding:          binding,
		DecisionRevision: 3,
		DecidedAt:        fixtureNow.Add(-time.Minute),
	}
	replay := newNonceSet()
	if err := protocol.ValidateApprovalDecision(decision, binding, replay, fixtureNow); err != nil {
		t.Fatalf("ValidateApprovalDecision(valid): %v", err)
	}
	if err := protocol.ValidateApprovalDecision(decision, binding, replay, fixtureNow); !protocol.IsCode(err, protocol.CodeReplay) {
		t.Fatalf("replayed decision error = %v", err)
	}

	mutations := map[string]func(*protocol.ApprovalDecision){
		"command digest":   func(value *protocol.ApprovalDecision) { value.Binding.CommandDigest = digest("other") },
		"session revision": func(value *protocol.ApprovalDecision) { value.Binding.SessionRevision++ },
		"policy revision":  func(value *protocol.ApprovalDecision) { value.Binding.PolicyRevision++ },
		"context version":  func(value *protocol.ApprovalDecision) { value.Binding.ContextVersion = "context-v2" },
		"environment": func(value *protocol.ApprovalDecision) {
			value.Binding.Environment.Provider.Digest = digest("other-environment")
		},
		"runtime": func(value *protocol.ApprovalDecision) {
			value.Binding.Runtime.Provider.Digest = digest("other-runtime")
		},
		"harness": func(value *protocol.ApprovalDecision) {
			value.Binding.Harness.Provider.Digest = digest("other-harness")
		},
		"nonce": func(value *protocol.ApprovalDecision) { value.Binding.Nonce = "different-nonce" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := decision
			candidate.Binding = cloneApprovalBinding(binding)
			mutate(&candidate)
			if err := protocol.ValidateApprovalDecision(candidate, binding, newNonceSet(), fixtureNow); err == nil {
				t.Fatal("mismatched approval decision accepted")
			}
		})
	}

	rejected := decision
	rejected.ApprovalID = "approval-rejected"
	rejected.Outcome = protocol.ApprovalOutcomeRejected
	rejected.Binding = cloneApprovalBinding(binding)
	rejected.Binding.Nonce = "approval-rejected-0123456789"
	if err := rejected.Validate(); err != nil {
		t.Fatalf("rejected decision is not a valid record: %v", err)
	}
	if err := protocol.ValidateApprovalDecision(rejected, rejected.Binding, newNonceSet(), fixtureNow); !protocol.IsCode(err, protocol.CodePermissionDenied) {
		t.Fatalf("rejected decision authorization error = %v, want %s", err, protocol.CodePermissionDenied)
	}

	expired := decision
	expired.Outcome = protocol.ApprovalOutcomeExpired
	if err := protocol.ValidateApprovalDecision(expired, binding, newNonceSet(), fixtureNow); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("explicitly expired decision error = %v, want %s", err, protocol.CodeExpired)
	}
	if err := protocol.ValidateApprovalDecision(decision, binding, newNonceSet(), binding.ExpiresAt); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("decision at exact expiry error = %v, want %s", err, protocol.CodeExpired)
	}
}

func TestIsolationAndCustodyEvidenceRequireGatewayAuthority(t *testing.T) {
	publicKey, privateKey := deterministicKey(1)
	providerPublic, providerPrivate := deterministicKey(4)
	trust := keyTrust{keys: map[string]ed25519.PublicKey{
		trustKey("gateway_customer_7", "gateway-evidence-key", protocol.PurposeIsolationEvidence): publicKey,
		trustKey("gateway_customer_7", "gateway-evidence-key", protocol.PurposeCustodyEvidence):   publicKey,
		trustKey("sandbox-provider", "provider-key", protocol.PurposeIsolationEvidence):           providerPublic,
	}}

	isolation, isolationBinding := signedIsolation(t, privateKey)
	if err := protocol.VerifyIsolation(isolation, isolationBinding, trust, newNonceSet(), fixtureNow); err != nil {
		t.Fatalf("VerifyIsolation(valid): %v", err)
	}
	custody, custodyBinding := signedCustody(t, privateKey)
	if err := protocol.VerifyCustody(custody, custodyBinding, trust, newNonceSet(), fixtureNow); err != nil {
		t.Fatalf("VerifyCustody(valid): %v", err)
	}

	t.Run("provider self assertion", func(t *testing.T) {
		candidate := isolation
		candidate.Signature = signatureMetadata(protocol.PurposeIsolationEvidence, "sandbox-provider", "provider-key")
		payload, err := candidate.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		candidate.Signature = signature(providerPrivate, protocol.PurposeIsolationEvidence, "sandbox-provider", "provider-key", payload)
		if err := protocol.VerifyIsolation(candidate, isolationBinding, trust, newNonceSet(), fixtureNow); err == nil {
			t.Fatal("provider-issued isolation evidence accepted")
		}
	})
	t.Run("forged signature", func(t *testing.T) {
		candidate := isolation
		candidate.Signature.Value = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7f}, ed25519.SignatureSize))
		if err := protocol.VerifyIsolation(candidate, isolationBinding, trust, newNonceSet(), fixtureNow); err == nil {
			t.Fatal("forged isolation evidence accepted")
		}
	})
	t.Run("stale", func(t *testing.T) {
		if err := protocol.VerifyIsolation(isolation, isolationBinding, trust, newNonceSet(), isolation.ExpiresAt); !protocol.IsCode(err, protocol.CodeExpired) {
			t.Fatalf("stale isolation error = %v", err)
		}
	})
	for name, mutate := range map[string]func(*protocol.IsolationBinding){
		"session":       func(value *protocol.IsolationBinding) { value.SessionID = "session-other" },
		"policy":        func(value *protocol.IsolationBinding) { value.PolicyRevision++ },
		"gateway":       func(value *protocol.IsolationBinding) { value.GatewayID = "gateway_other" },
		"gateway key":   func(value *protocol.IsolationBinding) { value.GatewayKeyID = "gateway-key-other" },
		"provider":      func(value *protocol.IsolationBinding) { value.Provider.Digest = digest("provider-other") },
		"environment":   func(value *protocol.IsolationBinding) { value.NativeEnvironmentID = "native-environment-other" },
		"configuration": func(value *protocol.IsolationBinding) { value.ConfigurationDigest = digest("configuration-other") },
		"image":         func(value *protocol.IsolationBinding) { value.ImageDigest = digest("image-other") },
		"controls":      func(value *protocol.IsolationBinding) { value.Controls = []string{"different-control"} },
		"data mode":     func(value *protocol.IsolationBinding) { value.DataMode = protocol.DataModeFull },
	} {
		t.Run("isolation binding "+name, func(t *testing.T) {
			expected := isolationBinding
			expected.Controls = append([]string(nil), isolationBinding.Controls...)
			mutate(&expected)
			if err := protocol.VerifyIsolation(isolation, expected, trust, newNonceSet(), fixtureNow); !protocol.IsCode(err, protocol.CodeConflict) {
				t.Fatalf("binding mismatch error = %v, want %s", err, protocol.CodeConflict)
			}
		})
	}
	for name, mutate := range map[string]func(*protocol.CustodyBinding){
		"policy":        func(value *protocol.CustodyBinding) { value.PolicyRevision++ },
		"provider":      func(value *protocol.CustodyBinding) { value.Provider.Digest = digest("provider-other") },
		"environment":   func(value *protocol.CustodyBinding) { value.NativeEnvironmentID = "native-environment-other" },
		"configuration": func(value *protocol.CustodyBinding) { value.ConfigurationDigest = digest("configuration-other") },
		"image":         func(value *protocol.CustodyBinding) { value.ImageDigest = digest("image-other") },
		"controls":      func(value *protocol.CustodyBinding) { value.Controls = []string{"different-control"} },
		"data mode":     func(value *protocol.CustodyBinding) { value.DataMode = protocol.DataModeFull },
	} {
		t.Run("custody binding "+name, func(t *testing.T) {
			expected := custodyBinding
			expected.Controls = append([]string(nil), custodyBinding.Controls...)
			mutate(&expected)
			if err := protocol.VerifyCustody(custody, expected, trust, newNonceSet(), fixtureNow); !protocol.IsCode(err, protocol.CodeConflict) {
				t.Fatalf("binding mismatch error = %v, want %s", err, protocol.CodeConflict)
			}
		})
	}
	t.Run("custody exact expiry", func(t *testing.T) {
		if err := protocol.VerifyCustody(custody, custodyBinding, trust, newNonceSet(), custody.ExpiresAt); !protocol.IsCode(err, protocol.CodeExpired) {
			t.Fatalf("stale custody error = %v, want %s", err, protocol.CodeExpired)
		}
	})
	t.Run("nonce replay", func(t *testing.T) {
		replay := newNonceSet()
		if err := protocol.VerifyCustody(custody, custodyBinding, trust, replay, fixtureNow); err != nil {
			t.Fatal(err)
		}
		if err := protocol.VerifyCustody(custody, custodyBinding, trust, replay, fixtureNow); !protocol.IsCode(err, protocol.CodeReplay) {
			t.Fatalf("custody replay error = %v", err)
		}
	})
}

func TestSigningPreimagesAreDomainSeparatedCanonicalAndImmutable(t *testing.T) {
	_, gatewayPrivate := deterministicKey(10)
	_, missionPrivate := deterministicKey(11)
	isolation, _ := signedIsolation(t, gatewayPrivate)
	custody, _ := signedCustody(t, gatewayPrivate)
	subject := verificationSubject()
	subject.Capabilities = []protocol.CapabilityName{"provider.initialize", "harness.launch"}
	subject.Cases = []string{"launch", "initialize"}
	subject.DataModes = []protocol.DataMode{protocol.DataModeMetadataOnly, protocol.DataModeFull}
	native := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierNativeContractTested, subject)
	live := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierLiveVerified, subject)

	preimages := []struct {
		name      string
		purpose   string
		signature protocol.Signature
		bytes     func() ([]byte, error)
	}{
		{name: "isolation", purpose: protocol.PurposeIsolationEvidence, signature: isolation.Signature, bytes: isolation.SigningBytes},
		{name: "custody", purpose: protocol.PurposeCustodyEvidence, signature: custody.Signature, bytes: custody.SigningBytes},
		{name: "native verification", purpose: protocol.PurposeContractVerification, signature: native.Signature, bytes: native.SigningBytes},
		{name: "live authorization", purpose: protocol.PurposeLiveRunAuthorization, signature: live.LiveAuthorization.Signature, bytes: live.LiveAuthorization.SigningBytes},
		{name: "live receipt", purpose: protocol.PurposeLiveRunReceipt, signature: live.LiveReceipt.Signature, bytes: live.LiveReceipt.SigningBytes},
		{name: "live verification", purpose: protocol.PurposeLiveVerification, signature: live.Signature, bytes: live.SigningBytes},
	}
	for _, tt := range preimages {
		t.Run(tt.name+" domain and signature metadata", func(t *testing.T) {
			preimage, err := tt.bytes()
			if err != nil {
				t.Fatal(err)
			}
			assertSigningPreimage(t, preimage, tt.purpose, tt.signature)
		})
	}

	t.Run("isolation control order", func(t *testing.T) {
		original := isolation
		original.IsolationBinding.Controls = append([]string(nil), isolation.IsolationBinding.Controls...)
		first, err := isolation.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(isolation, original) {
			t.Fatal("SigningBytes mutated isolation evidence")
		}
		reordered := isolation
		reordered.IsolationBinding.Controls = []string{"non-root", "network:none", "read-only-root"}
		reorderedBefore := reordered
		reorderedBefore.IsolationBinding.Controls = append([]string(nil), reordered.IsolationBinding.Controls...)
		second, err := reordered.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(reordered, reorderedBefore) {
			t.Fatal("SigningBytes mutated reordered isolation evidence")
		}
		if !bytes.Equal(first, second) {
			t.Fatal("isolation control order changed signing preimage")
		}
	})

	t.Run("custody control order", func(t *testing.T) {
		original := custody
		original.CustodyBinding.Controls = append([]string(nil), custody.CustodyBinding.Controls...)
		first, err := custody.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(custody, original) {
			t.Fatal("SigningBytes mutated custody evidence")
		}
		reordered := custody
		reordered.CustodyBinding.Controls = []string{"zero-on-release", "no-swap", "no-dump"}
		reorderedBefore := reordered
		reorderedBefore.CustodyBinding.Controls = append([]string(nil), reordered.CustodyBinding.Controls...)
		second, err := reordered.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(reordered, reorderedBefore) {
			t.Fatal("SigningBytes mutated reordered custody evidence")
		}
		if !bytes.Equal(first, second) {
			t.Fatal("custody control order changed signing preimage")
		}
	})

	t.Run("verification subject set order", func(t *testing.T) {
		original := cloneVerificationEvidence(native)
		first, err := native.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(native, original) {
			t.Fatal("SigningBytes mutated verification evidence")
		}
		reordered := cloneVerificationEvidence(native)
		reordered.Subject.Capabilities = []protocol.CapabilityName{"harness.launch", "provider.initialize"}
		reordered.Subject.Cases = []string{"initialize", "launch"}
		reordered.Subject.DataModes = []protocol.DataMode{protocol.DataModeFull, protocol.DataModeMetadataOnly}
		reorderedBefore := cloneVerificationEvidence(reordered)
		second, err := reordered.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(reordered, reorderedBefore) {
			t.Fatal("SigningBytes mutated reordered verification evidence")
		}
		if !bytes.Equal(first, second) {
			t.Fatal("verification subject set order changed signing preimage")
		}
	})
}

func TestSharedExactSigningVectors(t *testing.T) {
	t.Parallel()

	data := readFixture(t, "valid", "signing-vectors.json")
	if _, err := decodeStrictJSON(data); err != nil {
		t.Fatalf("signing vector fixture is ambiguous: %v", err)
	}
	var fixture signingVectorsFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != 1 || fixture.ProtocolVersion != protocol.ProtocolVersion || fixture.Encoding != "base64url-no-padding" {
		t.Fatalf("signing vector metadata = %#v", fixture)
	}
	wantPurposes := map[string]string{
		"isolation_evidence":           protocol.PurposeIsolationEvidence,
		"custody_evidence":             protocol.PurposeCustodyEvidence,
		"native_contract_verification": protocol.PurposeContractVerification,
		"live_run_authorization":       protocol.PurposeLiveRunAuthorization,
		"live_run_receipt":             protocol.PurposeLiveRunReceipt,
		"live_verification":            protocol.PurposeLiveVerification,
	}
	if len(fixture.Vectors) != len(wantPurposes) {
		t.Fatalf("signing vector count = %d, want %d", len(fixture.Vectors), len(wantPurposes))
	}
	seen := map[string]bool{}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			wantPurpose, known := wantPurposes[vector.Name]
			if !known || seen[vector.Name] {
				t.Fatalf("unknown or duplicate signing vector %q", vector.Name)
			}
			seen[vector.Name] = true
			if vector.Purpose != wantPurpose {
				t.Fatalf("purpose = %q, want %q", vector.Purpose, wantPurpose)
			}
			preimage, documentSignature := signingVectorPreimage(t, vector)
			wantPreimage, err := base64.RawURLEncoding.DecodeString(vector.PreimageBase64URL)
			if err != nil || !bytes.Equal(preimage, wantPreimage) {
				t.Fatalf("preimage bytes differ from shared vector: decode error=%v", err)
			}
			if documentSignature.Purpose != vector.Purpose || documentSignature.Value != vector.SignatureBase64URL {
				t.Fatalf("document signature metadata/value differ from vector: %#v", documentSignature)
			}

			key, ok := fixture.Keys[vector.Key]
			if !ok {
				t.Fatalf("key %q is absent", vector.Key)
			}
			seed, err := base64.RawURLEncoding.DecodeString(key.SeedBase64URL)
			if err != nil || len(seed) != ed25519.SeedSize {
				t.Fatalf("test seed is invalid: length=%d error=%v", len(seed), err)
			}
			publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKeyBase64URL)
			if err != nil || len(publicKey) != ed25519.PublicKeySize {
				t.Fatalf("test public key is invalid: length=%d error=%v", len(publicKey), err)
			}
			privateKey := ed25519.NewKeyFromSeed(seed)
			if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
				t.Fatal("deterministic seed does not derive the fixture public key")
			}
			wantSignature, err := base64.RawURLEncoding.DecodeString(vector.SignatureBase64URL)
			if err != nil || len(wantSignature) != ed25519.SignatureSize {
				t.Fatalf("fixture signature is invalid: length=%d error=%v", len(wantSignature), err)
			}
			if got := ed25519.Sign(privateKey, preimage); !bytes.Equal(got, wantSignature) {
				t.Fatal("deterministic signature differs from shared vector")
			}
			if !ed25519.Verify(publicKey, preimage, wantSignature) {
				t.Fatal("shared signature does not verify")
			}
		})
	}
}

func TestSigningNonceLengthAndAlphabetBoundary(t *testing.T) {
	_, privateKey := deterministicKey(12)
	evidence, _ := signedIsolation(t, privateKey)

	tooShort := evidence
	tooShort.Nonce = "AbCdEfGhIjKlMnOpQrSt_"
	if _, err := tooShort.SigningBytes(); err == nil {
		t.Fatal("21-character nonce accepted")
	}
	minimum := evidence
	minimum.Nonce = "AbCdEfGhIjKlMnOpQrSt_-"
	if _, err := minimum.SigningBytes(); err != nil {
		t.Fatalf("22-character base64url nonce rejected: %v", err)
	}
}

func TestVerificationEvidenceProjectsHighestValidExactTier(t *testing.T) {
	missionPublic, missionPrivate := deterministicKey(2)
	gatewayPublic, gatewayPrivate := deterministicKey(3)
	_, untrustedPrivate := deterministicKey(5)
	trust := keyTrust{keys: map[string]ed25519.PublicKey{
		trustKey("mission-verification", "contract-key", protocol.PurposeContractVerification):            missionPublic,
		trustKey("mission-verification", "live-key", protocol.PurposeLiveVerification):                    missionPublic,
		trustKey("mission-live-authorization", "authorization-key", protocol.PurposeLiveRunAuthorization): missionPublic,
		trustKey("gateway_customer_7", "gateway-evidence-key", protocol.PurposeLiveRunReceipt):            gatewayPublic,
	}}
	subject := verificationSubject()
	native := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierNativeContractTested, subject)
	live := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierLiveVerified, subject)
	policy := protocol.VerificationPolicy{Trust: trust, CurrentTrustEpoch: 7}
	expected := liveVerificationExpectation(subject)

	projection := protocol.EvaluateVerification([]protocol.VerificationEvidence{native, live}, expected, policy, newVerificationReplaySet(), fixtureNow)
	if projection.Tier != protocol.TierLiveVerified || projection.EvidenceID != live.EvidenceID {
		t.Fatalf("projection = %#v, want live evidence", projection)
	}

	tests := map[string]func(*protocol.VerificationEvidence, *protocol.VerificationPolicy){
		"failed": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Result = protocol.VerificationFailed
			value.LiveReceipt.Result = protocol.VerificationFailed
		},
		"exact expiry": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.ExpiresAt = fixtureNow
		},
		"authorization exact expiry": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.LiveAuthorization.ExpiresAt = fixtureNow
		},
		"revoked": func(value *protocol.VerificationEvidence, policy *protocol.VerificationPolicy) {
			policy.RevokedEvidenceIDs = []string{value.EvidenceID}
		},
		"superseded": func(value *protocol.VerificationEvidence, policy *protocol.VerificationPolicy) {
			policy.SupersededEvidenceIDs = []string{value.EvidenceID}
		},
		"artifact mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.Provider.Digest = digest("other-provider")
		},
		"native artifact mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.NativeArtifact.Digest = digest("other-native")
		},
		"platform mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.Platform.Architecture = "arm64"
		},
		"capability mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.Capabilities = []protocol.CapabilityName{"provider.initialize"}
		},
		"case mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.Cases = []string{"initialize"}
		},
		"suite version mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.SuiteVersion = "v0.2.0"
		},
		"suite mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.SuiteDigest = digest("other-suite")
		},
		"configuration mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.ConfigurationDigest = digest("other-config")
		},
		"data mode mismatch": func(value *protocol.VerificationEvidence, _ *protocol.VerificationPolicy) {
			value.Subject.DataModes = []protocol.DataMode{protocol.DataModeFull}
		},
	}
	for name, mutate := range tests {
		t.Run(name+" falls back", func(t *testing.T) {
			candidate := cloneVerificationEvidence(live)
			candidatePolicy := policy
			mutate(&candidate, &candidatePolicy)
			if !equalSubject(candidate.Subject, live.Subject) {
				candidate.LiveAuthorization.Subject = cloneVerificationSubject(candidate.Subject)
				candidate.LiveReceipt.Subject = cloneVerificationSubject(candidate.Subject)
			}
			resignLiveEvidence(t, &candidate, missionPrivate, gatewayPrivate)
			got := protocol.EvaluateVerification([]protocol.VerificationEvidence{native, candidate}, expected, candidatePolicy, newVerificationReplaySet(), fixtureNow)
			if got.Tier != protocol.TierNativeContractTested || got.EvidenceID != native.EvidenceID {
				t.Fatalf("projection = %#v, want native-contract fallback", got)
			}
		})
	}

	for name, mutate := range map[string]func(*protocol.VerificationExpectation){
		"tenant":        func(value *protocol.VerificationExpectation) { value.TenantID = "tenant_other" },
		"gateway":       func(value *protocol.VerificationExpectation) { value.GatewayID = "gateway_other" },
		"gateway key":   func(value *protocol.VerificationExpectation) { value.GatewayKeyID = "gateway-key-other" },
		"correlation":   func(value *protocol.VerificationExpectation) { value.CorrelationID = "correlation_other" },
		"authorization": func(value *protocol.VerificationExpectation) { value.AuthorizationID = "authorization_other" },
		"run nonce":     func(value *protocol.VerificationExpectation) { value.RunNonce = "different-live-run-nonce" },
		"budget":        func(value *protocol.VerificationExpectation) { value.BudgetReference = "budget://tenant/other" },
		"credential": func(value *protocol.VerificationExpectation) {
			value.CredentialReference = "credential://gateway/other"
		},
	} {
		t.Run("live scope "+name, func(t *testing.T) {
			mismatch := expected
			mutate(&mismatch)
			got := protocol.EvaluateVerification([]protocol.VerificationEvidence{native, live}, mismatch, policy, newVerificationReplaySet(), fixtureNow)
			if got.Tier != protocol.TierNativeContractTested || got.EvidenceID != native.EvidenceID {
				t.Fatalf("projection = %#v, want native-contract fallback", got)
			}
		})
	}

	t.Run("provider issued final evidence", func(t *testing.T) {
		candidate := cloneVerificationEvidence(live)
		candidate.Signature = signatureMetadata(protocol.PurposeLiveVerification, "untrusted-provider", "provider-key")
		payload, err := candidate.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		candidate.Signature = signature(untrustedPrivate, protocol.PurposeLiveVerification, "untrusted-provider", "provider-key", payload)
		providerTrust := keyTrust{keys: cloneTrustKeys(trust.keys)}
		delete(providerTrust.keys, trustKey("untrusted-provider", "provider-key", protocol.PurposeLiveVerification))
		candidatePolicy := policy
		candidatePolicy.Trust = providerTrust
		got := protocol.EvaluateVerification([]protocol.VerificationEvidence{candidate}, expected, candidatePolicy, newVerificationReplaySet(), fixtureNow)
		if got.Tier != protocol.TierUnverified {
			t.Fatalf("provider-issued evidence projected %q", got.Tier)
		}
	})

	t.Run("wrong purpose final evidence", func(t *testing.T) {
		candidate := cloneVerificationEvidence(live)
		candidate.Signature.Purpose = protocol.PurposeContractVerification
		got := protocol.EvaluateVerification([]protocol.VerificationEvidence{candidate}, expected, policy, newVerificationReplaySet(), fixtureNow)
		if got.Tier != protocol.TierUnverified {
			t.Fatalf("wrong-purpose evidence projected %q", got.Tier)
		}
	})

	t.Run("forged Mission evidence", func(t *testing.T) {
		candidate := cloneVerificationEvidence(live)
		candidate.Signature.Value = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, ed25519.SignatureSize))
		got := protocol.EvaluateVerification([]protocol.VerificationEvidence{candidate}, expected, policy, newVerificationReplaySet(), fixtureNow)
		if got.Tier != protocol.TierUnverified {
			t.Fatalf("forged Mission evidence projected %q", got.Tier)
		}
	})

	t.Run("missing gateway receipt signature", func(t *testing.T) {
		candidate := cloneVerificationEvidence(live)
		candidate.LiveReceipt.Signature = protocol.Signature{}
		if err := candidate.Validate(); err == nil {
			t.Fatal("live evidence without a gateway receipt signature validated")
		}
	})

	t.Run("forged live authorization", func(t *testing.T) {
		candidate := cloneVerificationEvidence(live)
		candidate.LiveAuthorization.Signature.Value = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, ed25519.SignatureSize))
		resignFinalEvidence(t, &candidate, missionPrivate)
		got := protocol.EvaluateVerification([]protocol.VerificationEvidence{candidate}, expected, policy, newVerificationReplaySet(), fixtureNow)
		if got.Tier != protocol.TierUnverified {
			t.Fatalf("forged live authorization projected %q", got.Tier)
		}
	})

	t.Run("forged gateway receipt", func(t *testing.T) {
		candidate := cloneVerificationEvidence(live)
		candidate.LiveReceipt.Signature.Value = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, ed25519.SignatureSize))
		resignFinalEvidence(t, &candidate, missionPrivate)
		got := protocol.EvaluateVerification([]protocol.VerificationEvidence{candidate}, expected, policy, newVerificationReplaySet(), fixtureNow)
		if got.Tier != protocol.TierUnverified {
			t.Fatalf("forged gateway receipt projected %q", got.Tier)
		}
	})

	t.Run("receipt tamper binds usage and audit", func(t *testing.T) {
		for name, mutate := range map[string]func(*protocol.LiveVerificationReceipt){
			"usage": func(value *protocol.LiveVerificationReceipt) { value.Usage.OutputTokens++ },
			"audit": func(value *protocol.LiveVerificationReceipt) { value.AuditEventID = "audit-event-other" },
		} {
			t.Run(name, func(t *testing.T) {
				candidate := cloneVerificationEvidence(live)
				mutate(candidate.LiveReceipt)
				resignFinalEvidence(t, &candidate, missionPrivate)
				got := protocol.EvaluateVerification([]protocol.VerificationEvidence{candidate}, expected, policy, newVerificationReplaySet(), fixtureNow)
				if got.Tier != protocol.TierUnverified {
					t.Fatalf("tampered receipt projected %q", got.Tier)
				}
			})
		}
	})

	t.Run("receipt signer key must match authorized gateway key", func(t *testing.T) {
		alternatePublic, alternatePrivate := deterministicKey(13)
		candidateTrust := keyTrust{keys: cloneTrustKeys(trust.keys)}
		candidateTrust.keys[trustKey("gateway_customer_7", "gateway-rotated-key", protocol.PurposeLiveRunReceipt)] = alternatePublic
		candidate := cloneVerificationEvidence(live)
		candidate.LiveReceipt.Signature = signatureMetadata(protocol.PurposeLiveRunReceipt, candidate.LiveReceipt.GatewayID, "gateway-rotated-key")
		payload, err := candidate.LiveReceipt.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		candidate.LiveReceipt.Signature = signature(alternatePrivate, protocol.PurposeLiveRunReceipt, candidate.LiveReceipt.GatewayID, "gateway-rotated-key", payload)
		if err := candidate.LiveReceipt.Validate(); err != nil {
			t.Fatalf("independently valid rotated-key receipt rejected: %v", err)
		}
		if err := candidate.Validate(); err == nil {
			t.Fatal("final evidence accepted a receipt signer key that differs from its authorization")
		}
		if _, ok := candidateTrust.PublicKey(candidate.LiveReceipt.GatewayID, "gateway-rotated-key", protocol.PurposeLiveRunReceipt); !ok {
			t.Fatal("test setup did not trust rotated gateway receipt key")
		}
	})

	t.Run("live nonce replay", func(t *testing.T) {
		replay := newVerificationReplaySet()
		first := protocol.EvaluateVerification([]protocol.VerificationEvidence{live}, expected, policy, replay, fixtureNow)
		if first.Tier != protocol.TierLiveVerified {
			t.Fatalf("first live projection = %#v", first)
		}
		if duplicate := protocol.EvaluateVerification([]protocol.VerificationEvidence{live}, expected, policy, replay, fixtureNow); duplicate.Tier != protocol.TierLiveVerified {
			t.Fatalf("idempotent same-evidence replay = %#v", duplicate)
		}
		secondEvidence := cloneVerificationEvidence(live)
		secondEvidence.EvidenceID = "verification-live-replay"
		resignFinalEvidence(t, &secondEvidence, missionPrivate)
		if replayed := protocol.EvaluateVerification([]protocol.VerificationEvidence{secondEvidence}, expected, policy, replay, fixtureNow); replayed.Tier != protocol.TierUnverified {
			t.Fatalf("nonce rebound to different evidence projected %#v", replayed)
		}
	})

	unverifiedRecord := native
	unverifiedRecord.Tier = protocol.TierUnverified
	if err := unverifiedRecord.Validate(); err == nil {
		t.Fatal("provider-issued unverified evidence record accepted")
	}
}

func TestGeneratedProtocolDocumentsAreStableAndComplete(t *testing.T) {
	t.Parallel()

	files := []string{
		"provider-manifest.v1alpha1.schema.json",
		"session.v1alpha1.schema.json",
		"event.v1alpha1.schema.json",
		"command.v1alpha1.schema.json",
		"openrpc.v1alpha1.json",
	}
	for _, name := range files {
		// Names come only from the fixed generated-document table above.
		data, err := os.ReadFile(filepath.Join("..", "schema", name)) //nolint:gosec
		if err != nil {
			t.Errorf("read generated %s: %v", name, err)
			continue
		}
		if !json.Valid(data) {
			t.Errorf("generated %s is not JSON", name)
		}
		value, err := decodeStrictJSON(data)
		if err != nil {
			t.Errorf("decode generated %s: %v", name, err)
		} else {
			assertSchemaKeywordsWellFormed(t, value, name)
		}
		if bytes.Contains(data, []byte("/Users/")) || bytes.Contains(data, []byte("generated_at")) {
			t.Errorf("generated %s contains machine/time-specific data", name)
		}
		if !bytes.HasSuffix(data, []byte("\n")) {
			t.Errorf("generated %s lacks final newline", name)
		}
	}

	openRPCData, err := os.ReadFile(filepath.Join("..", "schema", "openrpc.v1alpha1.json"))
	if err != nil {
		return
	}
	var openRPC struct {
		Version string `json:"openrpc"`
		Methods []struct {
			Name string `json:"name"`
		} `json:"methods"`
	}
	if err := json.Unmarshal(openRPCData, &openRPC); err != nil {
		t.Fatal(err)
	}
	if openRPC.Version != "1.4.1" {
		t.Fatalf("OpenRPC version = %q", openRPC.Version)
	}
	wantMethods := make([]string, 0, len(protocol.KnownCapabilities()))
	for _, capability := range protocol.KnownCapabilities() {
		wantMethods = append(wantMethods, string(capability.Name))
	}
	sort.Strings(wantMethods)
	gotMethods := make([]string, 0, len(openRPC.Methods))
	for _, method := range openRPC.Methods {
		gotMethods = append(gotMethods, method.Name)
	}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("OpenRPC methods drifted\ngot:  %v\nwant: %v", gotMethods, wantMethods)
	}
}

func assertSchemaKeywordsWellFormed(t *testing.T, value any, path string) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if required, exists := typed["required"]; exists {
			if required == nil {
				t.Errorf("%s required value must not be null", path)
			}
		}
		for key, child := range typed {
			assertSchemaKeywordsWellFormed(t, child, path+"."+key)
		}
	case []any:
		for index, child := range typed {
			assertSchemaKeywordsWellFormed(t, child, fmt.Sprintf("%s[%d]", path, index))
		}
	}
}

func TestOpenRPCRepresentativeMethodsMatchGoContracts(t *testing.T) {
	t.Parallel()

	root := readSchema(t, "openrpc.v1alpha1.json")
	session := decodeFixture[protocol.Session](t, "valid", "session-terminal.json")
	configuration := json.RawMessage(`{"mode":"safe"}`)
	configurationDigest := digestBytes(configuration)
	runtimeSession := protocol.RuntimeSession{
		ProviderID:      "runtime-provider",
		NativeSessionID: "native-session-1",
		Lifecycle:       session.Lifecycle,
		Health:          session.Health,
		Extensions:      map[string]json.RawMessage{},
	}
	harnessState := protocol.HarnessState{
		ProviderID:      "harness-provider",
		NativeSessionID: "native-session-1",
		Activity:        session.Activity,
		Usage:           protocol.Usage{InputTokens: 10, OutputTokens: 4, CostMicrounits: 200},
	}
	manifest := decodeFixture[protocol.ProviderManifest](t, "valid", "provider-manifest-runtime.json")
	tests := []struct {
		method  string
		request any
		result  any
	}{
		{
			method: "provider.initialize",
			request: protocol.ProviderInitializeRequest{
				SupportedProtocolVersions: []string{protocol.ProtocolVersion},
				GatewayVersion:            "v0.1.0",
				Platform:                  protocol.Platform{OS: "darwin", Architecture: "arm64"},
				RequiredCapabilities:      []protocol.CapabilityName{"provider.initialize"},
				MaximumMessageBytes:       protocol.MaxMessageBytes,
				MaximumChunkBytes:         protocol.MaxTerminalChunkBytes,
				ReplaySupported:           true,
				AuthenticationModes:       []string{"local-socket"},
				ExperimentalFeatures:      []string{},
			},
			result: protocol.ProviderInitializeResult{
				ProtocolVersion:      protocol.ProtocolVersion,
				Manifest:             manifest,
				NativeRuntimeVersion: "v1.0.0",
				MaximumMessageBytes:  protocol.MaxMessageBytes,
				MaximumChunkBytes:    protocol.MaxTerminalChunkBytes,
				ReplaySupported:      true,
				AuthenticationMode:   "local-socket",
				ExperimentalFeatures: []string{},
			},
		},
		{
			method: "runtime.create_session",
			request: protocol.RuntimeCreateSessionRequest{
				NativeEnvironmentID: "native-environment-1",
				Name:                "worker",
				Configuration:       configuration,
				ConfigurationDigest: configurationDigest,
			},
			result: protocol.RuntimeSessionResult{Session: runtimeSession},
		},
		{
			method:  "runtime.get_session",
			request: protocol.RuntimeSessionRequest{NativeSessionID: "native-session-1"},
			result:  protocol.RuntimeSessionResult{Session: runtimeSession},
		},
		{
			method:  "terminal.send_keys",
			request: protocol.TerminalKeysRequest{NativeSessionID: "native-session-1", StreamID: "terminal-stream", Keys: []string{"CTRL_C"}},
			result:  protocol.TerminalAck{NativeSessionID: "native-session-1", StreamID: "terminal-stream", Sequence: 1, Offset: 2},
		},
		{
			method: "agent.send_message",
			request: protocol.AgentMessageRequest{
				NativeSessionID: "native-session-1",
				Message:         configuration,
				MessageDigest:   configurationDigest,
			},
			result: protocol.AgentStateResult{State: harnessState},
		},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			for label, value := range map[string]any{"request": tt.request, "result": tt.result} {
				if validatable, ok := value.(interface{ Validate() error }); ok {
					if err := validatable.Validate(); err != nil {
						t.Fatalf("Go %s fixture is invalid: %v", label, err)
					}
				}
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				schema := openRPCMethodSchema(t, root, tt.method, label)
				if err := validateRawSchema(root, schema, data); err != nil {
					t.Fatalf("OpenRPC %s schema rejects valid Go %s: %v\n%s", tt.method, label, err, data)
				}
			}
		})
	}

	invalidTerminal := protocol.TerminalInputRequest{
		NativeSessionID: "native-session-1",
		StreamID:        "terminal-stream",
		Encoding:        protocol.TerminalEncodingBase64,
		Data:            "not base64",
	}
	if err := invalidTerminal.Validate(); err == nil {
		t.Fatal("Go terminal input accepted invalid base64")
	}
	data, err := json.Marshal(invalidTerminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(root, openRPCMethodSchema(t, root, "terminal.send_input", "request"), data); err == nil {
		t.Fatal("OpenRPC terminal input schema accepted invalid base64")
	}

	artifactEvent := decodeFixture[protocol.ProviderEvent](t, "valid", "provider-artifact-event.json")
	var report protocol.ProviderArtifactReport
	if err := json.Unmarshal(artifactEvent.Payload, &report); err != nil {
		t.Fatal(err)
	}
	report.Extensions["example.dev/authority"] = json.RawMessage(`{"nested":{"review_state":"approved"}}`)
	register := protocol.ArtifactRegisterRequest{Artifact: report}
	if err := register.Validate(); err == nil {
		t.Fatal("Go artifact register accepted nested provider review authority")
	}
	data, err = json.Marshal(register)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(root, openRPCMethodSchema(t, root, "artifact.register", "request"), data); err == nil {
		t.Fatal("OpenRPC artifact register schema accepted nested provider review authority")
	}
	list := protocol.ArtifactListResult{Artifacts: []protocol.ProviderArtifactReport{report}}
	if err := list.Validate(); err == nil {
		t.Fatal("Go artifact list accepted nested provider review authority")
	}
	data, err = json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(root, openRPCMethodSchema(t, root, "artifact.list", "result"), data); err == nil {
		t.Fatal("OpenRPC artifact list schema accepted nested provider review authority")
	}
}

func TestGeneratedSchemasAcceptAndRejectFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class      string
		file       string
		schema     string
		definition string
		valid      bool
	}{
		{class: "valid", file: "provider-manifest-harness.json", schema: "provider-manifest.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "provider-manifest-runtime.json", schema: "provider-manifest.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "provider-manifest-environment.json", schema: "provider-manifest.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "provider-manifest-orchestration.json", schema: "provider-manifest.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "provider-manifest-composed.json", schema: "provider-manifest.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "session-terminal.json", schema: "session.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "session-document.json", schema: "session.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "provider-event.json", schema: "event.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "provider-artifact-event.json", schema: "event.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "canonical-event.json", schema: "event.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "command.json", schema: "command.v1alpha1.schema.json", valid: true},
		{class: "valid", file: "context-receipt.json", schema: "session.v1alpha1.schema.json", definition: "context_receipt", valid: true},
		{class: "valid", file: "context-receipt-failed.json", schema: "session.v1alpha1.schema.json", definition: "context_receipt", valid: true},
		{class: "valid", file: "approval-decision-approved.json", schema: "event.v1alpha1.schema.json", definition: "approval_decision", valid: true},
		{class: "valid", file: "approval-decision-rejected.json", schema: "event.v1alpha1.schema.json", definition: "approval_decision", valid: true},
		{class: "valid", file: "artifact-local.json", schema: "session.v1alpha1.schema.json", definition: "artifact", valid: true},
		{class: "invalid", file: "manifest-provider-scope.json", schema: "provider-manifest.v1alpha1.schema.json"},
		{class: "invalid", file: "manifest-self-verification.json", schema: "provider-manifest.v1alpha1.schema.json"},
		{class: "invalid", file: "manifest-extension-traversal.json", schema: "provider-manifest.v1alpha1.schema.json"},
		{class: "invalid", file: "manifest-unknown-role.json", schema: "provider-manifest.v1alpha1.schema.json"},
		{class: "invalid", file: "manifest-mutating-without-delivery.json", schema: "provider-manifest.v1alpha1.schema.json"},
		{class: "invalid", file: "event-provider-scope.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-self-verification.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-zero-id.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-duplicate-key.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-nested-duplicate-key.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-payload-authority.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-extension-authority.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-artifact-approved-smuggling.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "event-artifact-hosted-smuggling.json", schema: "event.v1alpha1.schema.json"},
		{class: "invalid", file: "session-unknown-state.json", schema: "session.v1alpha1.schema.json"},
		{class: "invalid", file: "command-missing-idempotency.json", schema: "command.v1alpha1.schema.json"},
		{class: "invalid", file: "command-unknown-field.json", schema: "command.v1alpha1.schema.json"},
		{class: "invalid", file: "artifact-raw-local-path.json", schema: "session.v1alpha1.schema.json", definition: "artifact"},
		{class: "invalid", file: "artifact-unknown-locality.json", schema: "session.v1alpha1.schema.json", definition: "artifact"},
	}
	for _, tt := range tests {
		t.Run(tt.class+"/"+tt.file, func(t *testing.T) {
			root := readSchema(t, tt.schema)
			node := root
			if tt.definition != "" {
				node = schemaDefinition(t, root, tt.definition)
			}
			err := validateRawSchema(root, node, readFixture(t, tt.class, tt.file))
			if tt.valid && err != nil {
				t.Fatalf("valid fixture rejected by %s: %v", tt.schema, err)
			}
			if !tt.valid && err == nil {
				t.Fatalf("invalid fixture accepted by %s", tt.schema)
			}
		})
	}
}

func TestGeneratedSchemasMatchSignedGoValues(t *testing.T) {
	_, privateKey := deterministicKey(7)
	isolation, _ := signedIsolation(t, privateKey)
	custody, _ := signedCustody(t, privateKey)
	_, missionPrivate := deterministicKey(8)
	_, gatewayPrivate := deterministicKey(9)
	native := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierNativeContractTested, verificationSubject())
	live := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierLiveVerified, verificationSubject())

	tests := []struct {
		name       string
		schema     string
		definition string
		value      any
	}{
		{name: "isolation evidence", schema: "command.v1alpha1.schema.json", definition: "isolation_evidence", value: isolation},
		{name: "custody evidence", schema: "command.v1alpha1.schema.json", definition: "custody_evidence", value: custody},
		{name: "native verification", schema: "event.v1alpha1.schema.json", definition: "verification", value: native},
		{name: "live verification", schema: "event.v1alpha1.schema.json", definition: "verification", value: live},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			root := readSchema(t, tt.schema)
			if err := validateRawSchema(root, schemaDefinition(t, root, tt.definition), data); err != nil {
				t.Fatalf("generated schema does not describe marshaled Go value: %v\n%s", err, data)
			}
		})
	}
}

func TestGeneratedSecuritySchemasMatchGoConditionals(t *testing.T) {
	t.Parallel()

	_, gatewayPrivate := deterministicKey(14)
	_, missionPrivate := deterministicKey(15)
	isolation, _ := signedIsolation(t, gatewayPrivate)
	custody, _ := signedCustody(t, gatewayPrivate)
	native := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierNativeContractTested, verificationSubject())
	live := signedVerification(t, missionPrivate, gatewayPrivate, protocol.TierLiveVerified, verificationSubject())
	commandSchema := readSchema(t, "command.v1alpha1.schema.json")
	eventSchema := readSchema(t, "event.v1alpha1.schema.json")
	verificationSchema := schemaDefinition(t, eventSchema, "verification")
	authorizationSchema := schemaObject(schemaPath(t, verificationSchema, "properties", "live_authorization"))
	receiptSchema := schemaObject(schemaPath(t, verificationSchema, "properties", "live_receipt"))

	isolationBadNonce := isolation
	isolationBadNonce.Nonce = "AbCdEfGhIjKlMnOpQrSt+/"
	isolationWrongPurpose := isolation
	isolationWrongPurpose.Signature.Purpose = protocol.PurposeCustodyEvidence
	custodyWrongPurpose := custody
	custodyWrongPurpose.Signature.Purpose = protocol.PurposeIsolationEvidence
	authorizationBadNonce := *live.LiveAuthorization
	authorizationBadNonce.RunNonce = "AbCdEfGhIjKlMnOpQrSt+/"
	authorizationWrongPurpose := *live.LiveAuthorization
	authorizationWrongPurpose.Signature.Purpose = protocol.PurposeLiveRunReceipt
	receiptWrongPurpose := *live.LiveReceipt
	receiptWrongPurpose.Signature.Purpose = protocol.PurposeLiveRunAuthorization
	receiptBadSignature := *live.LiveReceipt
	receiptBadSignature.Signature.Value = "not-an-ed25519-signature"
	nativeWithLiveRecords := native
	nativeWithLiveRecords.LiveAuthorization = live.LiveAuthorization
	nativeWithLiveRecords.LiveReceipt = live.LiveReceipt
	liveWithoutRecords := live
	liveWithoutRecords.LiveAuthorization = nil
	liveWithoutRecords.LiveReceipt = nil
	unverifiedEvidence := native
	unverifiedEvidence.Tier = protocol.TierUnverified
	nativeWrongPurpose := native
	nativeWrongPurpose.Signature.Purpose = protocol.PurposeLiveVerification

	tests := []struct {
		name   string
		root   map[string]any
		schema map[string]any
		value  any
	}{
		{name: "isolation nonce alphabet", root: commandSchema, schema: schemaDefinition(t, commandSchema, "isolation_evidence"), value: isolationBadNonce},
		{name: "isolation signature purpose", root: commandSchema, schema: schemaDefinition(t, commandSchema, "isolation_evidence"), value: isolationWrongPurpose},
		{name: "custody signature purpose", root: commandSchema, schema: schemaDefinition(t, commandSchema, "custody_evidence"), value: custodyWrongPurpose},
		{name: "live authorization nonce alphabet", root: eventSchema, schema: authorizationSchema, value: authorizationBadNonce},
		{name: "live authorization purpose", root: eventSchema, schema: authorizationSchema, value: authorizationWrongPurpose},
		{name: "live receipt purpose", root: eventSchema, schema: receiptSchema, value: receiptWrongPurpose},
		{name: "live receipt signature encoding", root: eventSchema, schema: receiptSchema, value: receiptBadSignature},
		{name: "native tier with live records", root: eventSchema, schema: verificationSchema, value: nativeWithLiveRecords},
		{name: "live tier without records", root: eventSchema, schema: verificationSchema, value: liveWithoutRecords},
		{name: "unverified tier issuance", root: eventSchema, schema: verificationSchema, value: unverifiedEvidence},
		{name: "native tier signature purpose", root: eventSchema, schema: verificationSchema, value: nativeWrongPurpose},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validatable := tt.value.(interface{ Validate() error })
			if err := validatable.Validate(); err == nil {
				t.Fatal("test setup is Go-valid; want a contract-invalid value")
			}
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawSchema(tt.root, tt.schema, data); err == nil {
				t.Fatalf("generated schema accepted a value rejected by Go: %s", data)
			}
		})
	}

	artifactSchema := readSchema(t, "session.v1alpha1.schema.json")
	artifactDefinition := schemaDefinition(t, artifactSchema, "artifact")
	hosted := decodeFixture[protocol.Artifact](t, "valid", "artifact-local.json")
	hosted.Locality = protocol.ArtifactHosted
	hosted.Locator = "artifact://mission-control/artifact_1"
	if err := hosted.Validate(); err != nil {
		t.Fatalf("Go-valid hosted artifact rejected: %v", err)
	}
	hostedJSON, err := json.Marshal(hosted)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(artifactSchema, artifactDefinition, hostedJSON); err != nil {
		t.Fatalf("generated schema rejects Go-valid hosted artifact: %v", err)
	}
	localityMismatch := hosted
	localityMismatch.Locator = "local-resource://gateway_customer_7/artifact_1"
	if err := localityMismatch.Validate(); err == nil {
		t.Fatal("test setup locality mismatch is Go-valid")
	}
	mismatchJSON, err := json.Marshal(localityMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawSchema(artifactSchema, artifactDefinition, mismatchJSON); err == nil {
		t.Fatalf("artifact schema accepted a hosted/local-resource locality mismatch: %s", mismatchJSON)
	}
}

func TestGeneratedSchemaEnumsAndBoundsMatchProtocol(t *testing.T) {
	manifest := readSchema(t, "provider-manifest.v1alpha1.schema.json")
	assertSchemaEnum(t, schemaPath(t, manifest, "properties", "roles", "items", "enum"), []string{
		string(protocol.RoleAgentHarness), string(protocol.RoleSessionRuntime), string(protocol.RoleExecutionEnvironment), string(protocol.RoleOrchestration),
	})
	assertSchemaNumber(t, schemaPath(t, manifest, "properties", "roles", "minItems"), 1)
	assertSchemaNumber(t, schemaPath(t, manifest, "properties", "roles", "maxItems"), 4)

	session := readSchema(t, "session.v1alpha1.schema.json")
	assertSchemaEnum(t, schemaPath(t, session, "properties", "lifecycle", "properties", "state", "enum"), []string{
		"provisioning", "starting", "running", "stopped", "terminated", "archived", "disconnected", "unknown",
	})
	assertSchemaEnum(t, schemaPath(t, session, "$defs", "artifact", "properties", "classification", "enum"), []string{
		string(protocol.SensitivityPublic), string(protocol.SensitivityMetadata), string(protocol.SensitivityInternal), string(protocol.SensitivityConfidential), string(protocol.SensitivityRestricted),
	})
	assertSchemaNumber(t, schemaPath(t, session, "$defs", "provider_binding", "properties", "native_id", "maxLength"), 1024)

	event := readSchema(t, "event.v1alpha1.schema.json")
	assertSchemaEnum(t, schemaPath(t, event, "$defs", "provider_event", "properties", "role", "enum"), []string{
		string(protocol.RoleProvider), string(protocol.RoleAgentHarness), string(protocol.RoleSessionRuntime), string(protocol.RoleExecutionEnvironment), string(protocol.RoleOrchestration),
	})
	assertSchemaNumber(t, schemaPath(t, event, "$defs", "provider_event", "properties", "native_session_id", "maxLength"), 1024)

	command := readSchema(t, "command.v1alpha1.schema.json")
	if additional, ok := command["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("command schema additionalProperties = %#v, want false for closed authority document", command["additionalProperties"])
	}
	for _, definition := range []string{"isolation_evidence", "custody_evidence"} {
		properties := schemaPath(t, command, "$defs", definition, "properties").(map[string]any)
		if _, ok := properties["binding"]; !ok {
			t.Errorf("%s schema does not expose Go wire field binding", definition)
		}
		if _, stale := properties[strings.TrimSuffix(definition, "_evidence")+"_binding"]; stale {
			t.Errorf("%s schema exposes a non-Go binding field", definition)
		}
	}
}

func readFixture(t *testing.T, class, name string) []byte {
	t.Helper()
	// Callers pass only fixed fixture names declared in this test file.
	data, err := os.ReadFile(filepath.Join("testdata", class, name)) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeJSONValue(t *testing.T, data []byte) any {
	t.Helper()
	value, err := decodeStrictJSON(data)
	if err != nil {
		t.Fatalf("decode semantic JSON: %v", err)
	}
	return value
}

func requiredCapabilityMatrix() map[protocol.CapabilityName]protocol.CapabilityDescriptor {
	read := func(name protocol.CapabilityName, role protocol.ProviderRole) protocol.CapabilityDescriptor {
		return protocol.CapabilityDescriptor{Name: name, Role: role}
	}
	mutate := func(name protocol.CapabilityName, role protocol.ProviderRole, delivery protocol.DeliveryClass) protocol.CapabilityDescriptor {
		return protocol.CapabilityDescriptor{Name: name, Role: role, Mutating: true, DeliveryClass: delivery}
	}
	return map[protocol.CapabilityName]protocol.CapabilityDescriptor{
		"provider.initialize":         read("provider.initialize", protocol.RoleProvider),
		"provider.health":             read("provider.health", protocol.RoleProvider),
		"provider.capabilities":       read("provider.capabilities", protocol.RoleProvider),
		"provider.shutdown":           mutate("provider.shutdown", protocol.RoleProvider, protocol.DeliveryProviderIdempotent),
		"environment.inspect":         read("environment.inspect", protocol.RoleExecutionEnvironment),
		"environment.provision":       mutate("environment.provision", protocol.RoleExecutionEnvironment, protocol.DeliveryStateReconciled),
		"environment.mount":           mutate("environment.mount", protocol.RoleExecutionEnvironment, protocol.DeliveryStateReconciled),
		"environment.health":          read("environment.health", protocol.RoleExecutionEnvironment),
		"environment.shutdown":        mutate("environment.shutdown", protocol.RoleExecutionEnvironment, protocol.DeliveryProviderIdempotent),
		"runtime.list_sessions":       read("runtime.list_sessions", protocol.RoleSessionRuntime),
		"runtime.get_session":         read("runtime.get_session", protocol.RoleSessionRuntime),
		"runtime.create_session":      mutate("runtime.create_session", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.stop_session":        mutate("runtime.stop_session", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"runtime.terminate_session":   mutate("runtime.terminate_session", protocol.RoleSessionRuntime, protocol.DeliveryAtMostOnce),
		"runtime.attach":              mutate("runtime.attach", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.detach":              mutate("runtime.detach", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"runtime.snapshot":            read("runtime.snapshot", protocol.RoleSessionRuntime),
		"runtime.resume":              mutate("runtime.resume", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.clone":               mutate("runtime.clone", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.fork":                mutate("runtime.fork", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.migrate":             mutate("runtime.migrate", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.export":              mutate("runtime.export", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"runtime.import":              mutate("runtime.import", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.archive":             mutate("runtime.archive", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"runtime.checkpoint":          mutate("runtime.checkpoint", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"runtime.restore":             mutate("runtime.restore", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"runtime.adopt":               mutate("runtime.adopt", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"terminal.read":               read("terminal.read", protocol.RoleSessionRuntime),
		"terminal.subscribe":          read("terminal.subscribe", protocol.RoleSessionRuntime),
		"terminal.send_input":         mutate("terminal.send_input", protocol.RoleSessionRuntime, protocol.DeliveryAtMostOnce),
		"terminal.send_keys":          mutate("terminal.send_keys", protocol.RoleSessionRuntime, protocol.DeliveryAtMostOnce),
		"terminal.resize":             mutate("terminal.resize", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"terminal.attach":             mutate("terminal.attach", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"terminal.detach":             mutate("terminal.detach", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"workspace.list":              read("workspace.list", protocol.RoleSessionRuntime),
		"workspace.get":               read("workspace.get", protocol.RoleSessionRuntime),
		"workspace.create":            mutate("workspace.create", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"workspace.close":             mutate("workspace.close", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"topology.get":                read("topology.get", protocol.RoleSessionRuntime),
		"topology.subscribe":          read("topology.subscribe", protocol.RoleSessionRuntime),
		"pane.list":                   read("pane.list", protocol.RoleSessionRuntime),
		"pane.get":                    read("pane.get", protocol.RoleSessionRuntime),
		"pane.create":                 mutate("pane.create", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"pane.split":                  mutate("pane.split", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"pane.focus":                  mutate("pane.focus", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"pane.resize":                 mutate("pane.resize", protocol.RoleSessionRuntime, protocol.DeliveryStateReconciled),
		"pane.close":                  mutate("pane.close", protocol.RoleSessionRuntime, protocol.DeliveryProviderIdempotent),
		"harness.list":                read("harness.list", protocol.RoleAgentHarness),
		"harness.inspect":             read("harness.inspect", protocol.RoleAgentHarness),
		"harness.launch":              mutate("harness.launch", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"harness.resume":              mutate("harness.resume", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"harness.stop":                mutate("harness.stop", protocol.RoleAgentHarness, protocol.DeliveryProviderIdempotent),
		"agent.send_message":          mutate("agent.send_message", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"agent.interrupt":             mutate("agent.interrupt", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"agent.cancel":                mutate("agent.cancel", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"agent.get_state":             read("agent.get_state", protocol.RoleAgentHarness),
		"agent.get_usage":             read("agent.get_usage", protocol.RoleAgentHarness),
		"agent.get_pending_approvals": read("agent.get_pending_approvals", protocol.RoleAgentHarness),
		"agent.get_tools":             read("agent.get_tools", protocol.RoleAgentHarness),
		"agent.get_native_identity":   read("agent.get_native_identity", protocol.RoleAgentHarness),
		"context.deliver":             mutate("context.deliver", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"context.confirm":             read("context.confirm", protocol.RoleAgentHarness),
		"approval.list":               read("approval.list", protocol.RoleAgentHarness),
		"approval.approve":            mutate("approval.approve", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"approval.reject":             mutate("approval.reject", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"approval.expire":             mutate("approval.expire", protocol.RoleAgentHarness, protocol.DeliveryAtMostOnce),
		"artifact.list":               read("artifact.list", protocol.RoleAgentHarness),
		"artifact.register":           mutate("artifact.register", protocol.RoleAgentHarness, protocol.DeliveryProviderIdempotent),
		"events.subscribe":            read("events.subscribe", protocol.RoleProvider),
		"events.unsubscribe":          mutate("events.unsubscribe", protocol.RoleProvider, protocol.DeliveryProviderIdempotent),
		"command.get_result":          read("command.get_result", protocol.RoleProvider),
	}
}

func decodeFixture[T any](t *testing.T, class, name string) T {
	t.Helper()
	var value T
	if err := protocol.Decode(readFixture(t, class, name), &value); err != nil {
		t.Fatalf("Decode(%s): %v", name, err)
	}
	return value
}

func digest(value string) protocol.Digest {
	return digestBytes([]byte(value))
}

func digestBytes(value []byte) protocol.Digest {
	sum := sha256.Sum256(value)
	return protocol.Digest("sha256:" + hex.EncodeToString(sum[:]))
}

type nonceSet struct {
	seen map[string]bool
}

type verificationReplaySet struct {
	mu   sync.Mutex
	seen map[string]string
}

func newVerificationReplaySet() *verificationReplaySet {
	return &verificationReplaySet{seen: map[string]string{}}
}

func (set *verificationReplaySet) Accept(runNonce, evidenceID string) bool {
	set.mu.Lock()
	defer set.mu.Unlock()
	prior, exists := set.seen[runNonce]
	if !exists {
		set.seen[runNonce] = evidenceID
		return true
	}
	return prior == evidenceID
}

func newNonceSet() *nonceSet {
	return &nonceSet{seen: map[string]bool{}}
}

func (set *nonceSet) Consume(nonce string) bool {
	if set.seen[nonce] {
		return false
	}
	set.seen[nonce] = true
	return true
}

type keyTrust struct {
	keys map[string]ed25519.PublicKey
}

func (trust keyTrust) PublicKey(issuer, keyID, purpose string) (ed25519.PublicKey, bool) {
	key, ok := trust.keys[trustKey(issuer, keyID, purpose)]
	return key, ok
}

func trustKey(issuer, keyID, purpose string) string {
	return issuer + "\x00" + keyID + "\x00" + purpose
}

func deterministicKey(marker byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{marker}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func signature(privateKey ed25519.PrivateKey, purpose, issuer, keyID string, payload []byte) protocol.Signature {
	return protocol.Signature{
		Algorithm: protocol.SignatureEd25519,
		Purpose:   purpose,
		Issuer:    issuer,
		KeyID:     keyID,
		Value:     base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
}

func signatureMetadata(purpose, issuer, keyID string) protocol.Signature {
	return protocol.Signature{
		Algorithm: protocol.SignatureEd25519,
		Purpose:   purpose,
		Issuer:    issuer,
		KeyID:     keyID,
	}
}

func providerArtifact() protocol.ArtifactIdentity {
	return protocol.ArtifactIdentity{ID: "sandbox-worker", Version: "0.1.0", Digest: digest("provider")}
}

func approvalBinding() protocol.ApprovalBinding {
	runtime := approvalProviderSelection(protocol.RoleSessionRuntime, "direct-pty", "runtime-provider")
	return protocol.ApprovalBinding{
		CommandDigest:    digest("command"),
		SessionID:        "session_456",
		SessionRevision:  6,
		WorkItemRevision: 2,
		ResourceRevision: 4,
		ContextVersion:   "context-v1",
		PolicyRevision:   8,
		Environment:      approvalProviderSelection(protocol.RoleExecutionEnvironment, "sandbox-worker", "environment-provider"),
		Runtime:          &runtime,
		Harness:          approvalProviderSelection(protocol.RoleAgentHarness, "generic-cli", "harness-provider"),
		GatewayID:        "gateway_customer_7",
		Scopes:           []string{"session.create"},
		ExpiresAt:        fixtureNow.Add(5 * time.Minute),
		Nonce:            "approval-nonce-0123456789abcdef",
	}
}

func approvalProviderSelection(role protocol.ProviderRole, id, digestSeed string) protocol.ApprovalProviderSelection {
	return protocol.ApprovalProviderSelection{
		Role: role,
		Provider: protocol.ArtifactIdentity{
			ID:      id,
			Version: "0.1.0",
			Digest:  digest(digestSeed),
		},
	}
}

func cloneApprovalBinding(value protocol.ApprovalBinding) protocol.ApprovalBinding {
	if value.Runtime != nil {
		runtime := *value.Runtime
		value.Runtime = &runtime
	}
	value.Scopes = append([]string(nil), value.Scopes...)
	return value
}

func signedIsolation(t *testing.T, privateKey ed25519.PrivateKey) (protocol.IsolationEvidence, protocol.IsolationBinding) {
	t.Helper()
	binding := protocol.IsolationBinding{
		SessionID:           "session_456",
		PolicyRevision:      8,
		GatewayID:           "gateway_customer_7",
		GatewayKeyID:        "gateway-evidence-key",
		Provider:            providerArtifact(),
		NativeEnvironmentID: "native-environment-opaque",
		ConfigurationDigest: digest("configuration"),
		ImageDigest:         digest("image"),
		Controls:            []string{"network:none", "read-only-root", "non-root"},
		DataMode:            protocol.DataModeMetadataOnly,
	}
	evidence := protocol.IsolationEvidence{
		ProtocolVersion:  protocol.ProtocolVersion,
		EvidenceID:       "isolation-evidence-1",
		Nonce:            "isolation-nonce-0123456789abcdef",
		IsolationBinding: binding,
		IssuedAt:         fixtureNow.Add(-time.Minute),
		ExpiresAt:        fixtureNow.Add(time.Minute),
		Signature:        signatureMetadata(protocol.PurposeIsolationEvidence, binding.GatewayID, binding.GatewayKeyID),
	}
	payload, err := evidence.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = signature(privateKey, protocol.PurposeIsolationEvidence, binding.GatewayID, binding.GatewayKeyID, payload)
	return evidence, binding
}

func signedCustody(t *testing.T, privateKey ed25519.PrivateKey) (protocol.ContentCustodyEvidence, protocol.CustodyBinding) {
	t.Helper()
	binding := protocol.CustodyBinding{
		SessionID:           "session_456",
		PolicyRevision:      8,
		GatewayID:           "gateway_customer_7",
		GatewayKeyID:        "gateway-evidence-key",
		Provider:            providerArtifact(),
		NativeEnvironmentID: "native-environment-opaque",
		ConfigurationDigest: digest("configuration"),
		ImageDigest:         digest("image"),
		Controls:            []string{"no-swap", "no-dump", "zero-on-release"},
		DataMode:            protocol.DataModeEphemeralTranscript,
	}
	evidence := protocol.ContentCustodyEvidence{
		ProtocolVersion: protocol.ProtocolVersion,
		EvidenceID:      "custody-evidence-1",
		Nonce:           "custody-nonce-0123456789abcdef",
		CustodyBinding:  binding,
		IssuedAt:        fixtureNow.Add(-time.Minute),
		ExpiresAt:       fixtureNow.Add(time.Minute),
		Signature:       signatureMetadata(protocol.PurposeCustodyEvidence, binding.GatewayID, binding.GatewayKeyID),
	}
	payload, err := evidence.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = signature(privateKey, protocol.PurposeCustodyEvidence, binding.GatewayID, binding.GatewayKeyID, payload)
	return evidence, binding
}

func verificationSubject() protocol.VerificationSubject {
	return protocol.VerificationSubject{
		Provider:            providerArtifact(),
		NativeArtifact:      protocol.ArtifactIdentity{ID: "native-cli", Version: "2.0.0", Digest: digest("native")},
		Platform:            protocol.Platform{OS: "linux", Architecture: "amd64"},
		Capabilities:        []protocol.CapabilityName{"provider.initialize", "harness.launch"},
		Cases:               []string{"initialize", "launch"},
		SuiteVersion:        "v0.1.0",
		SuiteDigest:         digest("suite"),
		ConfigurationDigest: digest("config"),
		DataModes:           []protocol.DataMode{protocol.DataModeMetadataOnly},
	}
}

func signedVerification(t *testing.T, missionKey, gatewayKey ed25519.PrivateKey, tier protocol.VerificationTier, subject protocol.VerificationSubject) protocol.VerificationEvidence {
	t.Helper()
	evidence := protocol.VerificationEvidence{
		ProtocolVersion: protocol.ProtocolVersion,
		EvidenceID:      "verification-native",
		Tier:            tier,
		Subject:         cloneVerificationSubject(subject),
		Result:          protocol.VerificationPassed,
		Reference:       "evidence://mission/verification/native",
		IssuedAt:        fixtureNow.Add(-time.Minute),
		ExpiresAt:       fixtureNow.Add(time.Hour),
		TrustEpoch:      7,
		Signature:       signatureMetadata(protocol.PurposeContractVerification, "mission-verification", "contract-key"),
	}
	if tier == protocol.TierLiveVerified {
		evidence.EvidenceID = "verification-live"
		evidence.Reference = "evidence://mission/verification/live"
		evidence.Signature = signatureMetadata(protocol.PurposeLiveVerification, "mission-verification", "live-key")
		//nolint:gosec // deterministic non-secret typed reference used only by protocol tests
		authorization := protocol.LiveVerificationAuthorization{
			ProtocolVersion:     protocol.ProtocolVersion,
			AuthorizationID:     "live-authorization-1",
			Subject:             cloneVerificationSubject(subject),
			TenantID:            "tenant_1",
			GatewayID:           "gateway_customer_7",
			GatewayKeyID:        "gateway-evidence-key",
			CorrelationID:       "correlation_1",
			RunNonce:            "live-run-nonce-0123456789abcdef",
			BudgetReference:     "budget://tenant/1",
			CredentialReference: "credential://gateway/ref",
			IssuedAt:            fixtureNow.Add(-2 * time.Minute),
			ExpiresAt:           fixtureNow.Add(5 * time.Minute),
			TrustEpoch:          7,
			Signature:           signatureMetadata(protocol.PurposeLiveRunAuthorization, "mission-live-authorization", "authorization-key"),
		}
		authorizationBytes, err := authorization.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		authorization.Signature = signature(missionKey, protocol.PurposeLiveRunAuthorization, "mission-live-authorization", "authorization-key", authorizationBytes)
		usage := protocol.Usage{InputTokens: 10, OutputTokens: 4, CostMicrounits: 200}
		receipt := protocol.LiveVerificationReceipt{
			ProtocolVersion:     protocol.ProtocolVersion,
			ReceiptID:           "live-receipt-1",
			AuthorizationID:     authorization.AuthorizationID,
			Subject:             cloneVerificationSubject(subject),
			TenantID:            authorization.TenantID,
			GatewayID:           authorization.GatewayID,
			CorrelationID:       authorization.CorrelationID,
			RunNonce:            authorization.RunNonce,
			BudgetReference:     authorization.BudgetReference,
			CredentialReference: authorization.CredentialReference,
			Result:              protocol.VerificationPassed,
			Usage:               &usage,
			AuditEventID:        "audit-event-1",
			IssuedAt:            fixtureNow.Add(-time.Minute),
			Signature:           signatureMetadata(protocol.PurposeLiveRunReceipt, authorization.GatewayID, "gateway-evidence-key"),
		}
		receiptBytes, err := receipt.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		receipt.Signature = signature(gatewayKey, protocol.PurposeLiveRunReceipt, authorization.GatewayID, "gateway-evidence-key", receiptBytes)
		evidence.LiveAuthorization = &authorization
		evidence.LiveReceipt = &receipt
		evidence.IssuedAt = fixtureNow.Add(-30 * time.Second)
	}
	payload, err := evidence.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = signature(missionKey, evidence.Signature.Purpose, evidence.Signature.Issuer, evidence.Signature.KeyID, payload)
	return evidence
}

func liveVerificationExpectation(subject protocol.VerificationSubject) protocol.VerificationExpectation {
	//nolint:gosec // deterministic non-secret typed reference used only by protocol tests
	return protocol.VerificationExpectation{
		Subject:             cloneVerificationSubject(subject),
		TenantID:            "tenant_1",
		GatewayID:           "gateway_customer_7",
		GatewayKeyID:        "gateway-evidence-key",
		CorrelationID:       "correlation_1",
		AuthorizationID:     "live-authorization-1",
		RunNonce:            "live-run-nonce-0123456789abcdef",
		BudgetReference:     "budget://tenant/1",
		CredentialReference: "credential://gateway/ref",
	}
}

func resignLiveEvidence(t *testing.T, evidence *protocol.VerificationEvidence, missionKey, gatewayKey ed25519.PrivateKey) {
	t.Helper()
	if evidence.LiveAuthorization == nil || evidence.LiveReceipt == nil {
		t.Fatal("live evidence records are required")
	}
	authorization := evidence.LiveAuthorization
	authorization.Signature = signatureMetadata(protocol.PurposeLiveRunAuthorization, "mission-live-authorization", "authorization-key")
	authorizationBytes, err := authorization.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	authorization.Signature = signature(missionKey, protocol.PurposeLiveRunAuthorization, "mission-live-authorization", "authorization-key", authorizationBytes)
	receipt := evidence.LiveReceipt
	receipt.Signature = signatureMetadata(protocol.PurposeLiveRunReceipt, receipt.GatewayID, "gateway-evidence-key")
	receiptBytes, err := receipt.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = signature(gatewayKey, protocol.PurposeLiveRunReceipt, receipt.GatewayID, "gateway-evidence-key", receiptBytes)
	resignFinalEvidence(t, evidence, missionKey)
}

func resignFinalEvidence(t *testing.T, evidence *protocol.VerificationEvidence, missionKey ed25519.PrivateKey) {
	t.Helper()
	purpose := protocol.PurposeContractVerification
	keyID := "contract-key"
	if evidence.Tier == protocol.TierLiveVerified {
		purpose = protocol.PurposeLiveVerification
		keyID = "live-key"
	}
	evidence.Signature = signatureMetadata(purpose, "mission-verification", keyID)
	payload, err := evidence.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = signature(missionKey, purpose, "mission-verification", keyID, payload)
}

func cloneVerificationEvidence(value protocol.VerificationEvidence) protocol.VerificationEvidence {
	value.Subject = cloneVerificationSubject(value.Subject)
	if value.LiveAuthorization != nil {
		authorization := *value.LiveAuthorization
		authorization.Subject = cloneVerificationSubject(authorization.Subject)
		value.LiveAuthorization = &authorization
	}
	if value.LiveReceipt != nil {
		receipt := *value.LiveReceipt
		receipt.Subject = cloneVerificationSubject(receipt.Subject)
		if receipt.Usage != nil {
			usage := *receipt.Usage
			receipt.Usage = &usage
		}
		value.LiveReceipt = &receipt
	}
	return value
}

func equalSubject(left, right protocol.VerificationSubject) bool {
	return reflect.DeepEqual(left, right)
}

func cloneTrustKeys(values map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	result := make(map[string]ed25519.PublicKey, len(values))
	for key, value := range values {
		result[key] = append(ed25519.PublicKey(nil), value...)
	}
	return result
}

func cloneVerificationSubject(value protocol.VerificationSubject) protocol.VerificationSubject {
	value.Capabilities = append([]protocol.CapabilityName(nil), value.Capabilities...)
	value.Cases = append([]string(nil), value.Cases...)
	value.DataModes = append([]protocol.DataMode(nil), value.DataModes...)
	return value
}

func assertSigningPreimage(t *testing.T, preimage []byte, purpose string, signature protocol.Signature) {
	t.Helper()
	prefix := []byte(protocol.ProtocolVersion + "\x00" + purpose + "\x00")
	if len(preimage) <= len(prefix) || !bytes.Equal(preimage[:len(prefix)], prefix) {
		t.Fatalf("signing preimage prefix = %q, want exact %q", preimage[:min(len(preimage), len(prefix))], prefix)
	}
	value, err := decodeStrictJSON(preimage[len(prefix):])
	if err != nil {
		t.Fatalf("decode signing document: %v", err)
	}
	document, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("signing document type = %T, want object", value)
	}
	want := map[string]any{
		"algorithm": signature.Algorithm,
		"purpose":   signature.Purpose,
		"issuer":    signature.Issuer,
		"key_id":    signature.KeyID,
		"value":     "",
	}
	if got := document["signature"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("signing document signature = %#v, want metadata retained with only value empty: %#v", got, want)
	}
}

func signingVectorPreimage(t *testing.T, vector signingVector) ([]byte, protocol.Signature) {
	t.Helper()
	switch vector.Name {
	case "isolation_evidence":
		var value protocol.IsolationEvidence
		if err := protocol.Decode(vector.Document, &value); err != nil {
			t.Fatal(err)
		}
		preimage, err := value.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		return preimage, value.Signature
	case "custody_evidence":
		var value protocol.ContentCustodyEvidence
		if err := protocol.Decode(vector.Document, &value); err != nil {
			t.Fatal(err)
		}
		preimage, err := value.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		return preimage, value.Signature
	case "native_contract_verification", "live_verification":
		var value protocol.VerificationEvidence
		if err := protocol.Decode(vector.Document, &value); err != nil {
			t.Fatal(err)
		}
		preimage, err := value.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		return preimage, value.Signature
	case "live_run_authorization":
		var value protocol.LiveVerificationAuthorization
		if err := protocol.Decode(vector.Document, &value); err != nil {
			t.Fatal(err)
		}
		preimage, err := value.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		return preimage, value.Signature
	case "live_run_receipt":
		var value protocol.LiveVerificationReceipt
		if err := protocol.Decode(vector.Document, &value); err != nil {
			t.Fatal(err)
		}
		preimage, err := value.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		return preimage, value.Signature
	default:
		t.Fatalf("unsupported signing vector %q", vector.Name)
		return nil, protocol.Signature{}
	}
}

func readSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "schema", name)) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeStrictJSON(data)
	if err != nil {
		t.Fatalf("decode schema %s: %v", name, err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema %s is not an object", name)
	}
	return root
}

func schemaDefinition(t *testing.T, root map[string]any, name string) map[string]any {
	t.Helper()
	value := schemaPath(t, root, "$defs", name)
	node, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema definition %s is not an object", name)
	}
	return node
}

func openRPCMethodSchema(t *testing.T, root map[string]any, methodName, part string) map[string]any {
	t.Helper()
	methods, ok := root["methods"].([]any)
	if !ok {
		t.Fatal("OpenRPC methods are not an array")
	}
	for _, rawMethod := range methods {
		method := schemaObject(rawMethod)
		if method["name"] != methodName {
			continue
		}
		if part == "result" {
			return schemaObject(schemaObject(method["result"])["schema"])
		}
		params, ok := method["params"].([]any)
		if !ok || len(params) != 1 {
			t.Fatalf("OpenRPC method %s params = %#v, want one request", methodName, method["params"])
		}
		request := schemaObject(schemaObject(params[0])["schema"])
		if clauses, ok := request["allOf"].([]any); ok {
			for _, clause := range clauses {
				properties, _ := schemaObject(clause)["properties"].(map[string]any)
				if payload, exists := properties["payload"]; exists {
					return schemaObject(payload)
				}
			}
		}
		return request
	}
	t.Fatalf("OpenRPC method %s is absent", methodName)
	return nil
}

func schemaPath(t *testing.T, root map[string]any, path ...string) any {
	t.Helper()
	var current any = root
	for _, element := range path {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("schema path %s reached %T", strings.Join(path, "."), current)
		}
		current, ok = object[element]
		if !ok {
			t.Fatalf("schema path %s lacks %q", strings.Join(path, "."), element)
		}
	}
	return current
}

func assertSchemaEnum(t *testing.T, value any, want []string) {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("schema enum = %T, want array", value)
	}
	got := make([]string, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("schema enum item = %T, want string", item)
		}
		got[i] = text
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema enum = %v, want %v", got, want)
	}
}

func assertSchemaNumber(t *testing.T, value any, want int64) {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("schema bound = %T, want JSON number", value)
	}
	got, err := number.Int64()
	if err != nil || got != want {
		t.Fatalf("schema bound = %q, %v; want %d", number, err, want)
	}
}

func validateRawSchema(root, node map[string]any, data []byte) error {
	value, err := decodeStrictJSON(data)
	if err != nil {
		return err
	}
	return validateSchemaValue(root, node, value, "$")
}

func decodeStrictJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	return value, nil
}

func readJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate object key %q", key)
			}
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func validateSchemaValue(root, schema map[string]any, value any, path string) error {
	if reference, ok := schema["$ref"].(string); ok {
		resolvedRoot, resolved, err := resolveSchemaReference(root, reference)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := validateSchemaValue(resolvedRoot, resolved, value, path); err != nil {
			return err
		}
	}
	if clauses, ok := schema["allOf"].([]any); ok {
		for _, clause := range clauses {
			if err := validateSchemaValue(root, schemaObject(clause), value, path); err != nil {
				return err
			}
		}
	}
	if clauses, ok := schema["anyOf"].([]any); ok {
		matched := false
		for _, clause := range clauses {
			if validateSchemaValue(root, schemaObject(clause), value, path) == nil {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: no anyOf branch matched", path)
		}
	}
	if clauses, ok := schema["oneOf"].([]any); ok {
		matches := 0
		for _, clause := range clauses {
			if validateSchemaValue(root, schemaObject(clause), value, path) == nil {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("%s: matched %d oneOf branches", path, matches)
		}
	}
	if prohibited, ok := schema["not"].(map[string]any); ok && validateSchemaValue(root, prohibited, value, path) == nil {
		return fmt.Errorf("%s: prohibited schema matched", path)
	}
	if condition, ok := schema["if"].(map[string]any); ok {
		branch := "else"
		if validateSchemaValue(root, condition, value, path) == nil {
			branch = "then"
		}
		if selected, ok := schema[branch].(map[string]any); ok {
			if err := validateSchemaValue(root, selected, value, path); err != nil {
				return err
			}
		}
	}
	if constant, exists := schema["const"]; exists && !reflect.DeepEqual(value, constant) {
		return fmt.Errorf("%s: value does not match const", path)
	}
	if options, ok := schema["enum"].([]any); ok {
		matched := false
		for _, option := range options {
			if reflect.DeepEqual(value, option) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value is outside enum", path)
		}
	}

	typeName, _ := schema["type"].(string)
	switch typeName {
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("%s: want object, got %T", path, value)
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("%s: want array, got %T", path, value)
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s: want string, got %T", path, value)
		}
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return fmt.Errorf("%s: want integer, got %T", path, value)
		}
		if _, err := number.Int64(); err != nil {
			return fmt.Errorf("%s: want integer: %w", path, err)
		}
	case "number":
		if _, ok := value.(json.Number); !ok {
			return fmt.Errorf("%s: want number, got %T", path, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: want boolean, got %T", path, value)
		}
	case "null":
		if value != nil {
			return fmt.Errorf("%s: want null, got %T", path, value)
		}
	}

	if object, ok := value.(map[string]any); ok {
		if required, ok := schema["required"].([]any); ok {
			for _, raw := range required {
				key, _ := raw.(string)
				if _, exists := object[key]; !exists {
					return fmt.Errorf("%s: required property %q is absent", path, key)
				}
			}
		}
		properties, _ := schema["properties"].(map[string]any)
		for key, child := range object {
			if property, exists := properties[key]; exists {
				if err := validateSchemaValue(root, schemaObject(property), child, path+"."+key); err != nil {
					return err
				}
				continue
			}
			if additional, ok := schema["additionalProperties"].(map[string]any); ok {
				if err := validateSchemaValue(root, additional, child, path+"."+key); err != nil {
					return err
				}
				continue
			}
			if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
				return fmt.Errorf("%s: additional property %q is forbidden", path, key)
			}
		}
		if propertyNames, ok := schema["propertyNames"].(map[string]any); ok {
			for key := range object {
				if err := validateSchemaValue(root, propertyNames, key, path+" property name"); err != nil {
					return err
				}
			}
		}
		if maximum, ok := schemaInteger(schema["maxProperties"]); ok && int64(len(object)) > maximum {
			return fmt.Errorf("%s: too many properties", path)
		}
	}
	if array, ok := value.([]any); ok {
		if minimum, ok := schemaInteger(schema["minItems"]); ok && int64(len(array)) < minimum {
			return fmt.Errorf("%s: too few items", path)
		}
		if maximum, ok := schemaInteger(schema["maxItems"]); ok && int64(len(array)) > maximum {
			return fmt.Errorf("%s: too many items", path)
		}
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for index, item := range array {
				if err := validateSchemaValue(root, itemSchema, item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
					return err
				}
			}
		}
		if unique, _ := schema["uniqueItems"].(bool); unique {
			seen := map[string]bool{}
			for _, item := range array {
				encoded, _ := json.Marshal(item)
				key := string(encoded)
				if seen[key] {
					return fmt.Errorf("%s: duplicate array item", path)
				}
				seen[key] = true
			}
		}
	}
	if text, ok := value.(string); ok {
		length := int64(utf8.RuneCountInString(text))
		if minimum, ok := schemaInteger(schema["minLength"]); ok && length < minimum {
			return fmt.Errorf("%s: string is too short", path)
		}
		if maximum, ok := schemaInteger(schema["maxLength"]); ok && length > maximum {
			return fmt.Errorf("%s: string is too long", path)
		}
		if pattern, ok := schema["pattern"].(string); ok {
			compiled, err := regexp.Compile(pattern)
			if err != nil || !compiled.MatchString(text) {
				return fmt.Errorf("%s: string does not match pattern", path)
			}
		}
		if format, _ := schema["format"].(string); format == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
				return fmt.Errorf("%s: invalid date-time", path)
			}
		}
	}
	if number, ok := value.(json.Number); ok {
		actual, err := number.Float64()
		if err != nil {
			return fmt.Errorf("%s: invalid number", path)
		}
		if minimum, ok := schemaFloat(schema["minimum"]); ok && actual < minimum {
			return fmt.Errorf("%s: number is below minimum", path)
		}
		if maximum, ok := schemaFloat(schema["maximum"]); ok && actual > maximum {
			return fmt.Errorf("%s: number is above maximum", path)
		}
	}
	return nil
}

func resolveSchemaReference(root map[string]any, reference string) (map[string]any, map[string]any, error) {
	if !strings.HasPrefix(reference, "#/") {
		if filepath.Base(reference) != reference || !strings.HasSuffix(reference, ".json") {
			return nil, nil, fmt.Errorf("external schema reference %q is unsafe", reference)
		}
		data, err := os.ReadFile(filepath.Join("..", "schema", reference)) //nolint:gosec // generated sibling schema name is basename-checked.
		if err != nil {
			return nil, nil, fmt.Errorf("read external schema reference %q: %w", reference, err)
		}
		value, err := decodeStrictJSON(data)
		if err != nil {
			return nil, nil, fmt.Errorf("decode external schema reference %q: %w", reference, err)
		}
		externalRoot := schemaObject(value)
		return externalRoot, externalRoot, nil
	}
	var current any = root
	for _, component := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("schema reference %q traverses %T", reference, current)
		}
		current, ok = object[component]
		if !ok {
			return nil, nil, fmt.Errorf("schema reference %q is absent", reference)
		}
	}
	return root, schemaObject(current), nil
}

func schemaObject(value any) map[string]any {
	object, _ := value.(map[string]any)
	if object == nil {
		return map[string]any{"not": map[string]any{}}
	}
	return object
}

func schemaInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := number.Int64()
	return integer, err == nil
}

func schemaFloat(value any) (float64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	floating, err := number.Float64()
	return floating, err == nil
}
