package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

// HandlerSet composes independently optional provider capability groups.
type HandlerSet struct {
	Provider    ProviderHandlers
	Environment EnvironmentHandlers
	Runtime     RuntimeHandlers
	Harness     HarnessHandlers
	Extensions  map[protocol.CapabilityName]ExtensionHandlers
}

// ExtensionHandlers provide the explicit language-neutral escape hatch for
// reverse-DNS capabilities whose schemas are not part of this SDK version.
// Implementations should decode RawMessage into their own closed typed model.
type ExtensionHandlers struct {
	Query    QueryFunc[json.RawMessage, json.RawMessage]
	Mutation MutationFunc[json.RawMessage, json.RawMessage]
}

type postMutationResultError struct{ err error }

func (e *postMutationResultError) Error() string { return e.err.Error() }
func (e *postMutationResultError) Unwrap() error { return e.err }

// ProviderHandlers contains protocol-wide lifecycle, event, and command APIs.
type ProviderHandlers struct {
	Initialize   QueryFunc[protocol.ProviderInitializeRequest, protocol.ProviderInitializeResult]
	Health       QueryFunc[protocol.ProviderHealthRequest, protocol.ProviderHealthResult]
	Capabilities QueryFunc[protocol.ProviderCapabilitiesRequest, protocol.ProviderCapabilitiesResult]
	Shutdown     MutationFunc[protocol.ProviderShutdownRequest, protocol.OperationResult]
	Events       EventHandlers
	Commands     CommandHandlers
}

// EventHandlers contains provider event subscription APIs.
type EventHandlers struct {
	Subscribe   QueryFunc[protocol.EventsSubscribeRequest, EventSubscription]
	Unsubscribe MutationFunc[protocol.EventsUnsubscribeRequest, protocol.OperationResult]
}

// CommandHandlers contains durable command-result lookup APIs.
type CommandHandlers struct {
	GetResult QueryFunc[protocol.CommandGetResultRequest, protocol.CommandResult]
}

// EnvironmentHandlers contains execution-environment APIs.
type EnvironmentHandlers struct {
	Inspect   QueryFunc[protocol.EnvironmentInspectRequest, protocol.EnvironmentResult]
	Health    QueryFunc[protocol.EnvironmentHealthRequest, protocol.EnvironmentResult]
	Provision MutationFunc[protocol.EnvironmentProvisionRequest, protocol.EnvironmentResult]
	Mount     MutationFunc[protocol.EnvironmentMountRequest, protocol.EnvironmentResult]
	Shutdown  MutationFunc[protocol.EnvironmentShutdownRequest, protocol.EnvironmentResult]
}

// RuntimeHandlers contains session-runtime capability groups.
type RuntimeHandlers struct {
	Sessions   RuntimeSessionHandlers
	Terminal   TerminalHandlers
	Workspaces WorkspaceHandlers
	Topology   TopologyHandlers
	Panes      PaneHandlers
}

// RuntimeSessionHandlers contains durable session lifecycle APIs.
type RuntimeSessionHandlers struct {
	List       QueryFunc[protocol.RuntimeListSessionsRequest, protocol.RuntimeListSessionsResult]
	Get        QueryFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Create     MutationFunc[protocol.RuntimeCreateSessionRequest, protocol.RuntimeSessionResult]
	Stop       MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Terminate  MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Attach     MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Detach     MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Snapshot   QueryFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSnapshot]
	Checkpoint MutationFunc[protocol.RuntimeCheckpointRequest, protocol.RuntimeSnapshot]
	Restore    MutationFunc[protocol.RuntimeRestoreRequest, protocol.RuntimeSessionResult]
	Adopt      MutationFunc[protocol.RuntimeAdoptRequest, protocol.RuntimeSessionResult]
	Resume     MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Clone      MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Fork       MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
	Migrate    MutationFunc[protocol.RuntimeTransferRequest, protocol.RuntimeSessionResult]
	Export     MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSnapshot]
	Import     MutationFunc[protocol.RuntimeRestoreRequest, protocol.RuntimeSessionResult]
	Archive    MutationFunc[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult]
}

// TerminalHandlers contains terminal transport APIs.
type TerminalHandlers struct {
	Read      QueryFunc[protocol.TerminalReadRequest, protocol.TerminalChunk]
	Subscribe QueryFunc[protocol.TerminalSubscribeRequest, TerminalSubscription]
	SendInput MutationFunc[protocol.TerminalInputRequest, protocol.TerminalAck]
	SendKeys  MutationFunc[protocol.TerminalKeysRequest, protocol.TerminalAck]
	Resize    MutationFunc[protocol.TerminalResizeRequest, protocol.TerminalAck]
	Attach    MutationFunc[protocol.TerminalSubscribeRequest, TerminalSubscription]
	Detach    MutationFunc[TerminalDetachRequest, protocol.TerminalAck]
}

// WorkspaceHandlers contains optional multiplexer workspace APIs.
type WorkspaceHandlers struct {
	List   QueryFunc[WorkspaceListRequest, protocol.WorkspaceListResult]
	Get    QueryFunc[protocol.WorkspaceRequest, protocol.Workspace]
	Create MutationFunc[protocol.WorkspaceCreateRequest, protocol.Workspace]
	Close  MutationFunc[protocol.WorkspaceRequest, protocol.OperationResult]
}

// TopologyHandlers contains optional workspace-topology APIs.
type TopologyHandlers struct {
	Get       QueryFunc[protocol.WorkspaceRequest, protocol.TopologySnapshot]
	Subscribe QueryFunc[protocol.WorkspaceRequest, TopologySubscription]
}

// PaneHandlers contains optional multiplexer pane APIs.
type PaneHandlers struct {
	List   QueryFunc[protocol.WorkspaceRequest, PaneListResult]
	Get    QueryFunc[protocol.PaneRequest, protocol.Pane]
	Create MutationFunc[protocol.PaneCreateRequest, protocol.Pane]
	Split  MutationFunc[protocol.PaneSplitRequest, protocol.Pane]
	Focus  MutationFunc[protocol.PaneRequest, protocol.Pane]
	Resize MutationFunc[protocol.PaneResizeRequest, protocol.Pane]
	Close  MutationFunc[protocol.PaneRequest, protocol.OperationResult]
}

// HarnessHandlers contains agent-harness capability groups.
type HarnessHandlers struct {
	Sessions  HarnessSessionHandlers
	Agent     AgentHandlers
	Context   ContextHandlers
	Approvals ApprovalHandlers
	Artifacts ArtifactHandlers
}

// HarnessSessionHandlers contains native harness lifecycle APIs.
type HarnessSessionHandlers struct {
	List    QueryFunc[protocol.HarnessListRequest, protocol.HarnessListResult]
	Inspect QueryFunc[protocol.HarnessSessionRequest, protocol.HarnessSessionResult]
	Launch  MutationFunc[protocol.HarnessLaunchRequest, protocol.HarnessSessionResult]
	Resume  MutationFunc[protocol.HarnessResumeRequest, protocol.HarnessSessionResult]
	Stop    MutationFunc[protocol.HarnessSessionRequest, protocol.OperationResult]
}

// AgentHandlers contains structured agent interaction and observation APIs.
type AgentHandlers struct {
	SendMessage         MutationFunc[protocol.AgentMessageRequest, protocol.AgentStateResult]
	Interrupt           MutationFunc[protocol.AgentControlRequest, protocol.OperationResult]
	Cancel              MutationFunc[protocol.AgentControlRequest, protocol.OperationResult]
	GetState            QueryFunc[protocol.HarnessSessionRequest, protocol.AgentStateResult]
	GetUsage            QueryFunc[protocol.HarnessSessionRequest, protocol.AgentUsageResult]
	GetPendingApprovals QueryFunc[protocol.HarnessSessionRequest, protocol.ApprovalListResult]
	GetTools            QueryFunc[protocol.HarnessSessionRequest, protocol.AgentToolsResult]
	GetNativeIdentity   QueryFunc[protocol.HarnessSessionRequest, protocol.AgentNativeIdentityResult]
}

// ContextHandlers contains versioned context delivery APIs.
type ContextHandlers struct {
	Deliver MutationFunc[protocol.ContextDeliverRequest, protocol.ContextDeliverResult]
	Confirm QueryFunc[protocol.ContextConfirmRequest, protocol.ContextConfirmResult]
}

// ApprovalHandlers contains native approval observation and response APIs.
type ApprovalHandlers struct {
	List    QueryFunc[protocol.ApprovalListRequest, protocol.ApprovalListResult]
	Approve MutationFunc[protocol.ApprovalActionRequest, protocol.ApprovalActionResult]
	Reject  MutationFunc[protocol.ApprovalActionRequest, protocol.ApprovalActionResult]
	Expire  MutationFunc[protocol.ApprovalActionRequest, protocol.ApprovalActionResult]
}

// ArtifactHandlers contains provider-local artifact APIs.
type ArtifactHandlers struct {
	List     QueryFunc[protocol.ArtifactListRequest, protocol.ArtifactListResult]
	Register MutationFunc[protocol.ArtifactRegisterRequest, protocol.ArtifactRegisterResult]
}

func (h HandlerSet) supports(capability protocol.CapabilityName) bool {
	switch capability {
	case "provider.initialize", "provider.capabilities", "command.get_result":
		return true
	case "provider.health":
		return h.Provider.Health != nil
	case "provider.shutdown":
		return h.Provider.Shutdown != nil
	case "events.subscribe":
		return h.Provider.Events.Subscribe != nil
	case "events.unsubscribe":
		return h.Provider.Events.Unsubscribe != nil
	case "environment.inspect":
		return h.Environment.Inspect != nil
	case "environment.health":
		return h.Environment.Health != nil
	case "environment.provision":
		return h.Environment.Provision != nil
	case "environment.mount":
		return h.Environment.Mount != nil
	case "environment.shutdown":
		return h.Environment.Shutdown != nil
	case "runtime.list_sessions":
		return h.Runtime.Sessions.List != nil
	case "runtime.get_session":
		return h.Runtime.Sessions.Get != nil
	case "runtime.create_session":
		return h.Runtime.Sessions.Create != nil
	case "runtime.stop_session":
		return h.Runtime.Sessions.Stop != nil
	case "runtime.terminate_session":
		return h.Runtime.Sessions.Terminate != nil
	case "runtime.attach":
		return h.Runtime.Sessions.Attach != nil
	case "runtime.detach":
		return h.Runtime.Sessions.Detach != nil
	case "runtime.snapshot":
		return h.Runtime.Sessions.Snapshot != nil
	case "runtime.checkpoint":
		return h.Runtime.Sessions.Checkpoint != nil
	case "runtime.restore":
		return h.Runtime.Sessions.Restore != nil
	case "runtime.adopt":
		return h.Runtime.Sessions.Adopt != nil
	case "runtime.resume":
		return h.Runtime.Sessions.Resume != nil
	case "runtime.clone":
		return h.Runtime.Sessions.Clone != nil
	case "runtime.fork":
		return h.Runtime.Sessions.Fork != nil
	case "runtime.migrate":
		return h.Runtime.Sessions.Migrate != nil
	case "runtime.export":
		return h.Runtime.Sessions.Export != nil
	case "runtime.import":
		return h.Runtime.Sessions.Import != nil
	case "runtime.archive":
		return h.Runtime.Sessions.Archive != nil
	case "terminal.read":
		return h.Runtime.Terminal.Read != nil
	case "terminal.subscribe":
		return h.Runtime.Terminal.Subscribe != nil
	case "terminal.send_input":
		return h.Runtime.Terminal.SendInput != nil
	case "terminal.send_keys":
		return h.Runtime.Terminal.SendKeys != nil
	case "terminal.resize":
		return h.Runtime.Terminal.Resize != nil
	case "terminal.attach":
		return h.Runtime.Terminal.Attach != nil
	case "terminal.detach":
		return h.Runtime.Terminal.Detach != nil
	case "workspace.list":
		return h.Runtime.Workspaces.List != nil
	case "workspace.get":
		return h.Runtime.Workspaces.Get != nil
	case "workspace.create":
		return h.Runtime.Workspaces.Create != nil
	case "workspace.close":
		return h.Runtime.Workspaces.Close != nil
	case "topology.get":
		return h.Runtime.Topology.Get != nil
	case "topology.subscribe":
		return h.Runtime.Topology.Subscribe != nil
	case "pane.list":
		return h.Runtime.Panes.List != nil
	case "pane.get":
		return h.Runtime.Panes.Get != nil
	case "pane.create":
		return h.Runtime.Panes.Create != nil
	case "pane.split":
		return h.Runtime.Panes.Split != nil
	case "pane.focus":
		return h.Runtime.Panes.Focus != nil
	case "pane.resize":
		return h.Runtime.Panes.Resize != nil
	case "pane.close":
		return h.Runtime.Panes.Close != nil
	case "harness.list":
		return h.Harness.Sessions.List != nil
	case "harness.inspect":
		return h.Harness.Sessions.Inspect != nil
	case "harness.launch":
		return h.Harness.Sessions.Launch != nil
	case "harness.resume":
		return h.Harness.Sessions.Resume != nil
	case "harness.stop":
		return h.Harness.Sessions.Stop != nil
	case "agent.send_message":
		return h.Harness.Agent.SendMessage != nil
	case "agent.interrupt":
		return h.Harness.Agent.Interrupt != nil
	case "agent.cancel":
		return h.Harness.Agent.Cancel != nil
	case "agent.get_state":
		return h.Harness.Agent.GetState != nil
	case "agent.get_usage":
		return h.Harness.Agent.GetUsage != nil
	case "agent.get_pending_approvals":
		return h.Harness.Agent.GetPendingApprovals != nil
	case "agent.get_tools":
		return h.Harness.Agent.GetTools != nil
	case "agent.get_native_identity":
		return h.Harness.Agent.GetNativeIdentity != nil
	case "context.deliver":
		return h.Harness.Context.Deliver != nil
	case "context.confirm":
		return h.Harness.Context.Confirm != nil
	case "approval.list":
		return h.Harness.Approvals.List != nil
	case "approval.approve":
		return h.Harness.Approvals.Approve != nil
	case "approval.reject":
		return h.Harness.Approvals.Reject != nil
	case "approval.expire":
		return h.Harness.Approvals.Expire != nil
	case "artifact.list":
		return h.Harness.Artifacts.List != nil
	case "artifact.register":
		return h.Harness.Artifacts.Register != nil
	default:
		extension, ok := h.Extensions[capability]
		if !ok {
			return false
		}
		_, core := protocol.Capability(capability)
		if core {
			return false
		}
		return extension.Query != nil || extension.Mutation != nil
	}
}

func (h HandlerSet) populated(capability protocol.CapabilityName) bool {
	switch capability {
	case "provider.initialize":
		return h.Provider.Initialize != nil
	case "provider.capabilities":
		return h.Provider.Capabilities != nil
	case "command.get_result":
		return h.Provider.Commands.GetResult != nil
	default:
		return h.supports(capability)
	}
}

func (h HandlerSet) advertisedHandlers() []protocol.CapabilityName {
	capabilities := protocol.KnownCapabilities()
	result := make([]protocol.CapabilityName, 0, len(capabilities))
	for _, capability := range capabilities {
		if h.populated(capability.Name) {
			result = append(result, capability.Name)
		}
	}
	for capability, handlers := range h.Extensions {
		if handlers.Query != nil || handlers.Mutation != nil {
			result = append(result, capability)
		}
	}
	slices.Sort(result)
	return result
}

// dispatch decodes one closed request object, invokes exactly one typed
// handler, and validates its result. Server-owned built-ins may bypass dispatch.
func (h HandlerSet) dispatch(ctx context.Context, capability protocol.CapabilityName, meta *MutationMeta, raw json.RawMessage) (any, error) {
	available := h.advertisedHandlers()
	switch capability {
	case "provider.initialize":
		return invokeQuery(ctx, capability, raw, h.Provider.Initialize, available)
	case "provider.health":
		return invokeQuery(ctx, capability, raw, h.Provider.Health, available)
	case "provider.capabilities":
		return invokeQuery(ctx, capability, raw, h.Provider.Capabilities, available)
	case "provider.shutdown":
		return invokeMutation(ctx, capability, meta, raw, h.Provider.Shutdown, available)
	case "events.subscribe":
		return invokeQuery(ctx, capability, raw, h.Provider.Events.Subscribe, available)
	case "events.unsubscribe":
		return invokeMutation(ctx, capability, meta, raw, h.Provider.Events.Unsubscribe, available)
	case "command.get_result":
		return invokeQuery(ctx, capability, raw, h.Provider.Commands.GetResult, available)
	case "environment.inspect":
		return invokeQuery(ctx, capability, raw, h.Environment.Inspect, available)
	case "environment.health":
		return invokeQuery(ctx, capability, raw, h.Environment.Health, available)
	case "environment.provision":
		return invokeMutation(ctx, capability, meta, raw, h.Environment.Provision, available)
	case "environment.mount":
		return invokeMutation(ctx, capability, meta, raw, h.Environment.Mount, available)
	case "environment.shutdown":
		return invokeMutation(ctx, capability, meta, raw, h.Environment.Shutdown, available)
	case "runtime.list_sessions":
		return invokeQuery(ctx, capability, raw, h.Runtime.Sessions.List, available)
	case "runtime.get_session":
		return invokeQuery(ctx, capability, raw, h.Runtime.Sessions.Get, available)
	case "runtime.create_session":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Create, available)
	case "runtime.stop_session":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Stop, available)
	case "runtime.terminate_session":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Terminate, available)
	case "runtime.attach":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Attach, available)
	case "runtime.detach":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Detach, available)
	case "runtime.snapshot":
		return invokeQuery(ctx, capability, raw, h.Runtime.Sessions.Snapshot, available)
	case "runtime.checkpoint":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Checkpoint, available)
	case "runtime.restore":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Restore, available)
	case "runtime.adopt":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Adopt, available)
	case "runtime.resume":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Resume, available)
	case "runtime.clone":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Clone, available)
	case "runtime.fork":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Fork, available)
	case "runtime.migrate":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Migrate, available)
	case "runtime.export":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Export, available)
	case "runtime.import":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Import, available)
	case "runtime.archive":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Sessions.Archive, available)
	case "terminal.read":
		return invokeQuery(ctx, capability, raw, h.Runtime.Terminal.Read, available)
	case "terminal.subscribe":
		return invokeQuery(ctx, capability, raw, h.Runtime.Terminal.Subscribe, available)
	case "terminal.send_input":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Terminal.SendInput, available)
	case "terminal.send_keys":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Terminal.SendKeys, available)
	case "terminal.resize":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Terminal.Resize, available)
	case "terminal.attach":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Terminal.Attach, available)
	case "terminal.detach":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Terminal.Detach, available)
	case "workspace.list":
		return invokeQuery(ctx, capability, raw, h.Runtime.Workspaces.List, available)
	case "workspace.get":
		return invokeQuery(ctx, capability, raw, h.Runtime.Workspaces.Get, available)
	case "workspace.create":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Workspaces.Create, available)
	case "workspace.close":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Workspaces.Close, available)
	case "topology.get":
		return invokeQuery(ctx, capability, raw, h.Runtime.Topology.Get, available)
	case "topology.subscribe":
		return invokeQuery(ctx, capability, raw, h.Runtime.Topology.Subscribe, available)
	case "pane.list":
		return invokeQuery(ctx, capability, raw, h.Runtime.Panes.List, available)
	case "pane.get":
		return invokeQuery(ctx, capability, raw, h.Runtime.Panes.Get, available)
	case "pane.create":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Panes.Create, available)
	case "pane.split":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Panes.Split, available)
	case "pane.focus":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Panes.Focus, available)
	case "pane.resize":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Panes.Resize, available)
	case "pane.close":
		return invokeMutation(ctx, capability, meta, raw, h.Runtime.Panes.Close, available)
	case "harness.list":
		return invokeQuery(ctx, capability, raw, h.Harness.Sessions.List, available)
	case "harness.inspect":
		return invokeQuery(ctx, capability, raw, h.Harness.Sessions.Inspect, available)
	case "harness.launch":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Sessions.Launch, available)
	case "harness.resume":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Sessions.Resume, available)
	case "harness.stop":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Sessions.Stop, available)
	case "agent.send_message":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Agent.SendMessage, available)
	case "agent.interrupt":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Agent.Interrupt, available)
	case "agent.cancel":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Agent.Cancel, available)
	case "agent.get_state":
		return invokeQuery(ctx, capability, raw, h.Harness.Agent.GetState, available)
	case "agent.get_usage":
		return invokeQuery(ctx, capability, raw, h.Harness.Agent.GetUsage, available)
	case "agent.get_pending_approvals":
		return invokeQuery(ctx, capability, raw, h.Harness.Agent.GetPendingApprovals, available)
	case "agent.get_tools":
		return invokeQuery(ctx, capability, raw, h.Harness.Agent.GetTools, available)
	case "agent.get_native_identity":
		return invokeQuery(ctx, capability, raw, h.Harness.Agent.GetNativeIdentity, available)
	case "context.deliver":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Context.Deliver, available)
	case "context.confirm":
		return invokeQuery(ctx, capability, raw, h.Harness.Context.Confirm, available)
	case "approval.list":
		return invokeQuery(ctx, capability, raw, h.Harness.Approvals.List, available)
	case "approval.approve":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Approvals.Approve, available)
	case "approval.reject":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Approvals.Reject, available)
	case "approval.expire":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Approvals.Expire, available)
	case "artifact.list":
		return invokeQuery(ctx, capability, raw, h.Harness.Artifacts.List, available)
	case "artifact.register":
		return invokeMutation(ctx, capability, meta, raw, h.Harness.Artifacts.Register, available)
	default:
		extension, ok := h.Extensions[capability]
		if !ok {
			return nil, protocol.NotSupported(capability, available)
		}
		if meta == nil {
			if extension.Query == nil {
				return nil, protocol.NotSupported(capability, available)
			}
			return invokeExtensionQuery(ctx, raw, extension.Query)
		}
		if extension.Mutation == nil {
			return nil, protocol.NotSupported(capability, available)
		}
		return invokeExtensionMutation(ctx, meta, raw, extension.Mutation)
	}
}

func invokeExtensionQuery(ctx context.Context, raw json.RawMessage, handler QueryFunc[json.RawMessage, json.RawMessage]) (any, error) {
	if err := validateExtensionValue(raw); err != nil {
		return nil, err
	}
	result, err := handler(ctx, append(json.RawMessage(nil), raw...))
	if err != nil {
		return nil, err
	}
	if err := validateExtensionValue(result); err != nil {
		return nil, err
	}
	return result, nil
}

func invokeExtensionMutation(ctx context.Context, meta *MutationMeta, raw json.RawMessage, handler MutationFunc[json.RawMessage, json.RawMessage]) (any, error) {
	if meta == nil || meta.Validate() != nil || !samePayload(meta.Payload, raw) {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := validateExtensionValue(raw); err != nil {
		return nil, err
	}
	result, err := handler(ctx, *meta, append(json.RawMessage(nil), raw...))
	if err != nil {
		return nil, err
	}
	if err := validateExtensionValue(result); err != nil {
		return nil, &postMutationResultError{err: err}
	}
	return result, nil
}

var extensionReservedKeys = map[string]struct{}{
	"tenant_id": {}, "project_id": {}, "initiative_id": {}, "work_item_id": {},
	"gateway_id": {}, "session_id": {}, "canonical_session_id": {},
	"correlation_id": {}, "causation_id": {}, "sensitivity": {}, "authority": {},
	"verification_tier": {}, "tier": {}, "verified": {}, "artifact_id": {},
	"creator_type": {}, "creator_id": {}, "review_state": {}, "classification": {},
	"approval_id": {}, "approved": {}, "decision_revision": {},
}

func validateExtensionValue(raw json.RawMessage) error {
	if err := validateJSON(raw); err != nil {
		return err
	}
	return validateExtensionAuthority(raw)
}

func validateExtensionAuthority(raw json.RawMessage) error {
	var root any
	if err := protocol.Decode(raw, &root); err != nil {
		return err
	}
	stack := []any{root}
	for len(stack) > 0 {
		value := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, reserved := extensionReservedKeys[key]; reserved {
					return newProtocolError(protocol.CodePermissionDenied)
				}
				stack = append(stack, child)
			}
		case []any:
			stack = append(stack, typed...)
		}
	}
	return nil
}

func invokeQuery[Request, Result any](ctx context.Context, capability protocol.CapabilityName, raw json.RawMessage, handler QueryFunc[Request, Result], available []protocol.CapabilityName) (any, error) {
	if handler == nil {
		return nil, protocol.NotSupported(capability, available)
	}
	request, err := decodeClosed[Request](raw)
	if err != nil {
		return nil, err
	}
	result, err := handler(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := validateResult(result); err != nil {
		return nil, fmt.Errorf("%s handler returned an invalid result: %w", capability, err)
	}
	return result, nil
}

func invokeMutation[Request, Result any](ctx context.Context, capability protocol.CapabilityName, meta *MutationMeta, raw json.RawMessage, handler MutationFunc[Request, Result], available []protocol.CapabilityName) (any, error) {
	if handler == nil {
		return nil, protocol.NotSupported(capability, available)
	}
	if meta == nil {
		return nil, fmt.Errorf("mutation metadata is required")
	}
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if meta.Capability != capability || !samePayload(meta.Payload, raw) {
		return nil, fmt.Errorf("mutation metadata does not match the dispatch request")
	}
	request, err := decodeClosed[Request](raw)
	if err != nil {
		return nil, err
	}
	result, err := handler(ctx, *meta, request)
	if err != nil {
		return nil, err
	}
	if err := validateResult(result); err != nil {
		return nil, &postMutationResultError{err: fmt.Errorf("%s handler returned an invalid result: %w", capability, err)}
	}
	return result, nil
}

func decodeClosed[Value any](raw json.RawMessage) (Value, error) {
	var strict Value
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&strict); err != nil {
		return strict, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return strict, newProtocolError(protocol.CodeInvalidArgument)
	}
	var value Value
	if err := protocol.Decode(raw, &value); err != nil {
		return value, err
	}
	return value, nil
}

func validateResult(result any) error {
	if validatable, ok := result.(interface{ Validate() error }); ok {
		if err := validatable.Validate(); err != nil {
			return err
		}
	}
	return validateRuntimeWorkspaceExtensions(result)
}

func validateRuntimeWorkspaceExtensions(result any) error {
	switch value := result.(type) {
	case protocol.RuntimeSession:
		return validateExtensionMapAuthority(value.Extensions)
	case *protocol.RuntimeSession:
		if value != nil {
			return validateExtensionMapAuthority(value.Extensions)
		}
	case protocol.RuntimeSessionResult:
		return validateRuntimeWorkspaceExtensions(value.Session)
	case *protocol.RuntimeSessionResult:
		if value != nil {
			return validateRuntimeWorkspaceExtensions(value.Session)
		}
	case protocol.RuntimeListSessionsResult:
		for _, session := range value.Sessions {
			if err := validateRuntimeWorkspaceExtensions(session); err != nil {
				return err
			}
		}
	case *protocol.RuntimeListSessionsResult:
		if value != nil {
			return validateRuntimeWorkspaceExtensions(*value)
		}
	case protocol.Workspace:
		return validateExtensionMapAuthority(value.Extensions)
	case *protocol.Workspace:
		if value != nil {
			return validateExtensionMapAuthority(value.Extensions)
		}
	case protocol.WorkspaceListResult:
		for _, workspace := range value.Workspaces {
			if err := validateRuntimeWorkspaceExtensions(workspace); err != nil {
				return err
			}
		}
	case *protocol.WorkspaceListResult:
		if value != nil {
			return validateRuntimeWorkspaceExtensions(*value)
		}
	}
	return nil
}

func validateExtensionMapAuthority(extensions map[string]json.RawMessage) error {
	for _, value := range extensions {
		if err := validateExtensionAuthority(value); err != nil {
			return err
		}
	}
	return nil
}
