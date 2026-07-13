package protocol

import (
	"fmt"
	"regexp"
	"sort"
)

type ProviderRole string

const (
	// RoleProvider identifies lifecycle and transport capabilities shared by every
	// provider. It is not a provider concern and cannot appear in Manifest.Roles.
	RoleProvider             ProviderRole = "provider"
	RoleAgentHarness         ProviderRole = "agent-harness"
	RoleSessionRuntime       ProviderRole = "session-runtime"
	RoleExecutionEnvironment ProviderRole = "execution-environment"
	RoleOrchestration        ProviderRole = "orchestration"
)

func (r ProviderRole) Validate() error {
	switch r {
	case RoleProvider, RoleAgentHarness, RoleSessionRuntime, RoleExecutionEnvironment, RoleOrchestration:
		return nil
	default:
		return fmt.Errorf("provider role is unsupported")
	}
}

func (r ProviderRole) validateConcern() error {
	if r == RoleProvider {
		return fmt.Errorf("provider is a neutral capability role, not a provider concern")
	}
	return r.Validate()
}

type CapabilityName string
type DeliveryClass string

const (
	DeliveryProviderIdempotent DeliveryClass = "provider_idempotent"
	DeliveryStateReconciled    DeliveryClass = "state_reconciled"
	DeliveryAtMostOnce         DeliveryClass = "at_most_once"
)

type CapabilityDescriptor struct {
	Name          CapabilityName `json:"name"`
	Role          ProviderRole   `json:"role"`
	Mutating      bool           `json:"mutating,omitempty"`
	DeliveryClass DeliveryClass  `json:"delivery_class,omitempty"`
	Required      bool           `json:"required,omitempty"`
}

func (c CapabilityDescriptor) Validate() error {
	if !validCapabilityName(c.Name) {
		return fmt.Errorf("capability name is invalid")
	}
	if err := c.Role.Validate(); err != nil {
		return err
	}
	if c.Mutating {
		if !validDeliveryClass(c.DeliveryClass) {
			return fmt.Errorf("mutating capability requires a delivery class")
		}
	} else if c.DeliveryClass != "" {
		return fmt.Errorf("read-only capability cannot declare a delivery class")
	}
	return nil
}

var (
	// Extension capabilities use the same reverse-DNS namespace form as
	// extension objects. This prevents a provider from claiming a future core
	// method name before Mission Control defines it.
	extensionCapabilityPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,127}$`)
)

var capabilityCatalog = []CapabilityDescriptor{
	{Name: "provider.capabilities", Role: RoleProvider},
	{Name: "provider.health", Role: RoleProvider},
	{Name: "provider.initialize", Role: RoleProvider},
	{Name: "provider.shutdown", Role: RoleProvider, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "events.subscribe", Role: RoleProvider},
	{Name: "events.unsubscribe", Role: RoleProvider, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "command.get_result", Role: RoleProvider},

	{Name: "environment.health", Role: RoleExecutionEnvironment},
	{Name: "environment.inspect", Role: RoleExecutionEnvironment},
	{Name: "environment.mount", Role: RoleExecutionEnvironment, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "environment.provision", Role: RoleExecutionEnvironment, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "environment.shutdown", Role: RoleExecutionEnvironment, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},

	{Name: "runtime.list_sessions", Role: RoleSessionRuntime},
	{Name: "runtime.get_session", Role: RoleSessionRuntime},
	{Name: "runtime.create_session", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.stop_session", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "runtime.terminate_session", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "runtime.attach", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.detach", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "runtime.snapshot", Role: RoleSessionRuntime},
	{Name: "runtime.checkpoint", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "runtime.restore", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.adopt", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.resume", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.clone", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.fork", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.migrate", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.export", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "runtime.import", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "runtime.archive", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},

	{Name: "terminal.read", Role: RoleSessionRuntime},
	{Name: "terminal.subscribe", Role: RoleSessionRuntime},
	{Name: "terminal.send_input", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "terminal.send_keys", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "terminal.resize", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "terminal.attach", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "terminal.detach", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},

	{Name: "workspace.list", Role: RoleSessionRuntime},
	{Name: "workspace.get", Role: RoleSessionRuntime},
	{Name: "workspace.create", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "workspace.close", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "topology.get", Role: RoleSessionRuntime},
	{Name: "topology.subscribe", Role: RoleSessionRuntime},
	{Name: "pane.list", Role: RoleSessionRuntime},
	{Name: "pane.get", Role: RoleSessionRuntime},
	{Name: "pane.create", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "pane.split", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "pane.focus", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "pane.resize", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryStateReconciled},
	{Name: "pane.close", Role: RoleSessionRuntime, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},

	{Name: "harness.list", Role: RoleAgentHarness},
	{Name: "harness.inspect", Role: RoleAgentHarness},
	{Name: "harness.launch", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "harness.resume", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "harness.stop", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
	{Name: "agent.send_message", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "agent.interrupt", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "agent.cancel", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "agent.get_state", Role: RoleAgentHarness},
	{Name: "agent.get_usage", Role: RoleAgentHarness},
	{Name: "agent.get_pending_approvals", Role: RoleAgentHarness},
	{Name: "agent.get_tools", Role: RoleAgentHarness},
	{Name: "agent.get_native_identity", Role: RoleAgentHarness},
	{Name: "context.deliver", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "context.confirm", Role: RoleAgentHarness},
	{Name: "approval.list", Role: RoleAgentHarness},
	{Name: "approval.approve", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "approval.reject", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "approval.expire", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryAtMostOnce},
	{Name: "artifact.list", Role: RoleAgentHarness},
	{Name: "artifact.register", Role: RoleAgentHarness, Mutating: true, DeliveryClass: DeliveryProviderIdempotent},
}

func KnownCapabilities() []CapabilityDescriptor {
	result := append([]CapabilityDescriptor(nil), capabilityCatalog...)
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// Capability returns the immutable core definition for name.
func Capability(name CapabilityName) (CapabilityDescriptor, bool) {
	for _, known := range capabilityCatalog {
		if known.Name == name {
			return known, true
		}
	}
	return CapabilityDescriptor{}, false
}

func validCapabilityName(name CapabilityName) bool {
	value := string(name)
	if _, known := Capability(name); known {
		return true
	}
	return extensionCapabilityPattern.MatchString(value)
}

func validDeliveryClass(class DeliveryClass) bool {
	switch class {
	case DeliveryProviderIdempotent, DeliveryStateReconciled, DeliveryAtMostOnce:
		return true
	default:
		return false
	}
}

func equalCapabilityDefinition(actual, expected CapabilityDescriptor) bool {
	return actual.Name == expected.Name && actual.Role == expected.Role && actual.Mutating == expected.Mutating && actual.DeliveryClass == expected.DeliveryClass
}
