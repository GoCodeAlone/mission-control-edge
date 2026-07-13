import { createHash } from "node:crypto";

import { Ajv2020, type AnySchema, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import commandSchema from "../../../schema/command.v1alpha1.schema.json" with { type: "json" };
import eventSchema from "../../../schema/event.v1alpha1.schema.json" with { type: "json" };
import openRPC from "../../../schema/openrpc.v1alpha1.json" with { type: "json" };
import manifestSchema from "../../../schema/provider-manifest.v1alpha1.schema.json" with { type: "json" };
import sessionSchema from "../../../schema/session.v1alpha1.schema.json" with { type: "json" };

import { ProtocolError, protocolError } from "./errors.js";

export const PROTOCOL_VERSION = "mission-control.provider.v1alpha1" as const;
export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([PROTOCOL_VERSION] as const);
export const MAX_MESSAGE_BYTES = 4 << 20;
export const MAX_TERMINAL_CHUNK_BYTES = 256 << 10;
export const MAX_TERMINAL_WINDOW_BYTES = 8 << 20;

export const NOTIFICATION_EVENT = "$mc/event" as const;
export const NOTIFICATION_TERMINAL_CHUNK = "$mc/terminal.chunk" as const;
export const NOTIFICATION_TOPOLOGY_SNAPSHOT = "$mc/topology.snapshot" as const;
export const NOTIFICATION_HEARTBEAT = "$mc/heartbeat" as const;
export const NOTIFICATION_CANCEL = "$mc/cancel" as const;
export const NOTIFICATION_TERMINAL_CREDIT = "$mc/terminal.credit" as const;

export type JSONPrimitive = string | number | boolean | null;
export type JSONValue = JSONPrimitive | JSONObject | readonly JSONValue[];
export interface JSONObject { readonly [key: string]: JSONValue }
export type NativeID = string;
export type Digest = `sha256:${string}`;
export type ProtocolVersion = typeof PROTOCOL_VERSION;
export type UTCDateTime = string;

export type ProviderRole =
  | "provider"
  | "agent-harness"
  | "session-runtime"
  | "execution-environment"
  | "orchestration";
export type DeliveryClass = "provider_idempotent" | "state_reconciled" | "at_most_once";

export const CAPABILITY_CATALOG = Object.freeze([
  { name: "provider.capabilities", role: "provider" },
  { name: "provider.health", role: "provider" },
  { name: "provider.initialize", role: "provider" },
  { name: "provider.shutdown", role: "provider", mutating: true, delivery_class: "provider_idempotent" },
  { name: "events.subscribe", role: "provider" },
  { name: "events.unsubscribe", role: "provider", mutating: true, delivery_class: "provider_idempotent" },
  { name: "command.get_result", role: "provider" },
  { name: "environment.health", role: "execution-environment" },
  { name: "environment.inspect", role: "execution-environment" },
  { name: "environment.mount", role: "execution-environment", mutating: true, delivery_class: "state_reconciled" },
  { name: "environment.provision", role: "execution-environment", mutating: true, delivery_class: "state_reconciled" },
  { name: "environment.shutdown", role: "execution-environment", mutating: true, delivery_class: "provider_idempotent" },
  { name: "runtime.list_sessions", role: "session-runtime" },
  { name: "runtime.get_session", role: "session-runtime" },
  { name: "runtime.create_session", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.stop_session", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "runtime.terminate_session", role: "session-runtime", mutating: true, delivery_class: "at_most_once" },
  { name: "runtime.attach", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.detach", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "runtime.snapshot", role: "session-runtime" },
  { name: "runtime.checkpoint", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "runtime.restore", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.adopt", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.resume", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.clone", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.fork", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.migrate", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.export", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "runtime.import", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "runtime.archive", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "terminal.read", role: "session-runtime" },
  { name: "terminal.subscribe", role: "session-runtime" },
  { name: "terminal.send_input", role: "session-runtime", mutating: true, delivery_class: "at_most_once" },
  { name: "terminal.send_keys", role: "session-runtime", mutating: true, delivery_class: "at_most_once" },
  { name: "terminal.resize", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "terminal.attach", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "terminal.detach", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "workspace.list", role: "session-runtime" },
  { name: "workspace.get", role: "session-runtime" },
  { name: "workspace.create", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "workspace.close", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "topology.get", role: "session-runtime" },
  { name: "topology.subscribe", role: "session-runtime" },
  { name: "pane.list", role: "session-runtime" },
  { name: "pane.get", role: "session-runtime" },
  { name: "pane.create", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "pane.split", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "pane.focus", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "pane.resize", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
  { name: "pane.close", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
  { name: "harness.list", role: "agent-harness" },
  { name: "harness.inspect", role: "agent-harness" },
  { name: "harness.launch", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "harness.resume", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "harness.stop", role: "agent-harness", mutating: true, delivery_class: "provider_idempotent" },
  { name: "agent.send_message", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "agent.interrupt", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "agent.cancel", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "agent.get_state", role: "agent-harness" },
  { name: "agent.get_usage", role: "agent-harness" },
  { name: "agent.get_pending_approvals", role: "agent-harness" },
  { name: "agent.get_tools", role: "agent-harness" },
  { name: "agent.get_native_identity", role: "agent-harness" },
  { name: "context.deliver", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "context.confirm", role: "agent-harness" },
  { name: "approval.list", role: "agent-harness" },
  { name: "approval.approve", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "approval.reject", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "approval.expire", role: "agent-harness", mutating: true, delivery_class: "at_most_once" },
  { name: "artifact.list", role: "agent-harness" },
  { name: "artifact.register", role: "agent-harness", mutating: true, delivery_class: "provider_idempotent" },
] as const);

export type CoreCapabilityName = (typeof CAPABILITY_CATALOG)[number]["name"];
export type CapabilityName = CoreCapabilityName | (string & {});
export const CORE_CAPABILITIES: readonly CoreCapabilityName[] = Object.freeze(
  CAPABILITY_CATALOG.map(({ name }) => name),
);

type ParsedJSONSource = { readonly compact: string; readonly canonical: string };
const parsedJSONSources = new WeakMap<object, ParsedJSONSource>();
const parsedJSONProperties = new WeakMap<object, ReadonlyMap<string, ParsedJSONSource>>();

export interface CapabilityDescriptor {
  name: CapabilityName;
  role: ProviderRole;
  mutating?: boolean;
  delivery_class?: DeliveryClass;
  required?: boolean;
}

export interface Platform { os: string; architecture: string }
export interface ArtifactIdentity { id: string; version: string; digest: Digest }
export interface ProviderBinding {
  provider_id: string;
  provider_version: string;
  native_id: NativeID;
  native_resume_reference?: NativeID;
  artifact_digest: Digest;
}

export type StateAxis = "lifecycle" | "activity" | "health";
export type LifecycleState = "provisioning" | "starting" | "running" | "stopped" | "terminated" | "archived" | "disconnected" | "unknown";
export type ActivityState = "idle" | "working" | "waiting_for_user" | "waiting_for_approval" | "blocked" | "done" | "failed" | "unknown";
export type HealthState = "healthy" | "degraded" | "unreachable" | "unknown";
export type State = LifecycleState | ActivityState | HealthState;
export type StateAuthority = "authoritative" | "inferred";
export interface StateReport {
  axis: StateAxis;
  state: State;
  source: string;
  observed_at: UTCDateTime;
  sequence: number;
  confidence: number;
  expires_at?: UTCDateTime;
  authority: StateAuthority;
  status?: string;
}

export interface Session {
  protocol_version: ProtocolVersion;
  session_id: string;
  gateway_id: string;
  environment: ProviderBinding;
  runtime?: ProviderBinding;
  harness: ProviderBinding;
  lifecycle: StateReport;
  activity: StateReport;
  health: StateReport;
  context_version: string;
  extensions: Record<string, JSONValue>;
}

export interface ProviderManifest {
  protocol_version: ProtocolVersion;
  id: string;
  roles: ProviderRole[];
  name: string;
  version: string;
  executable: string;
  platforms: Platform[];
  capabilities: CapabilityDescriptor[];
  interaction_modes: string[];
  permissions: string[];
  configuration_schema: string;
  extensions: Record<string, JSONValue>;
}

export interface ProviderInitializeRequest {
  supported_protocol_versions: string[];
  gateway_version: string;
  platform: Platform;
  required_capabilities: CapabilityName[];
  maximum_message_bytes: number;
  maximum_chunk_bytes: number;
  replay_supported: boolean;
  authentication_modes: string[];
  experimental_features: string[];
}
export interface ProviderInitializeResult {
  protocol_version: ProtocolVersion;
  manifest: ProviderManifest;
  native_runtime_version?: string;
  maximum_message_bytes: number;
  maximum_chunk_bytes: number;
  replay_supported: boolean;
  authentication_mode: string;
  experimental_features: string[];
}
export type EmptyRequest = Record<string, never>;
export type ProviderHealthRequest = EmptyRequest;
export interface ProviderHealthResult { provider_id: string; health: StateReport }
export type ProviderCapabilitiesRequest = EmptyRequest;
export interface ProviderCapabilitiesResult {
  provider_id: string;
  roles: ProviderRole[];
  capabilities: CapabilityDescriptor[];
}
export type ProviderShutdownRequest = EmptyRequest;

export type ErrorCode =
  | "invalid_argument" | "message_too_large" | "not_supported" | "sequence_conflict"
  | "replay" | "expired" | "unauthenticated" | "permission_denied" | "conflict"
  | "deadline_exceeded" | "cancelled" | "resource_exhausted" | "unavailable" | "outcome_unknown";
export interface ProtocolErrorData {
  code: ErrorCode;
  message: string;
  required_capability?: CapabilityName;
  advertised_capabilities?: CapabilityName[];
}
export type OperationStatus = "accepted" | "running" | "succeeded" | "failed" | "outcome_unknown";
export interface OperationResult {
  operation_id: NativeID;
  status: OperationStatus;
  observed_at: UTCDateTime;
  result_reference?: string;
  error?: ProtocolErrorData;
}

export interface Command<Capability extends CapabilityName = CapabilityName, Payload = JSONValue> {
  protocol_version: ProtocolVersion;
  command_id: string;
  session_id?: string;
  capability: Capability;
  idempotency_key: string;
  cancellation_token: string;
  deadline: UTCDateTime;
  delivery_class: DeliveryClass;
  payload: Payload;
}
export interface CommandGetResultRequest { command_id: string }
export type CommandResultStatus = "pending" | "succeeded" | "failed" | "outcome_unknown";
export interface CommandResult {
  command_id: string;
  status: CommandResultStatus;
  result?: JSONValue;
  error?: ProtocolErrorData;
  observed_at: UTCDateTime;
}

export interface ProviderEvent {
  protocol_version: ProtocolVersion;
  event_id: string;
  provider_id: string;
  role: ProviderRole;
  stream_id: string;
  native_session_id?: NativeID;
  type: string;
  sequence: number;
  observed_at: UTCDateTime;
  payload: JSONValue;
  extensions: Record<string, JSONValue>;
}
export type Sensitivity = "public" | "metadata" | "internal" | "confidential" | "restricted";
export interface CanonicalEvent {
  protocol_version: ProtocolVersion;
  tenant_id: string;
  gateway_id: string;
  session_id?: string;
  correlation_id: string;
  causation_id?: string;
  sensitivity: Sensitivity;
  authority: "gateway-assigned";
  provider_event: ProviderEvent;
}
export interface EventSubscriptionCursor { role: ProviderRole; stream_id: string; after_sequence: number }
export interface EventsSubscribeRequest { cursors: EventSubscriptionCursor[]; event_types: string[]; window_size: number }
export interface EventsSubscribeResult { subscription_id: NativeID; cursors: EventSubscriptionCursor[] }
export interface EventsUnsubscribeRequest { subscription_id: NativeID }

export interface Environment {
  provider_id: string;
  native_environment_id: NativeID;
  platform: Platform;
  health: StateReport;
  configuration?: JSONValue;
}
export interface EnvironmentInspectRequest { native_environment_id: NativeID }
export type EnvironmentHealthRequest = EnvironmentInspectRequest;
export type EnvironmentShutdownRequest = EnvironmentInspectRequest;
export interface EnvironmentProvisionRequest { configuration: JSONValue; configuration_digest: Digest; image_digest?: Digest }
export interface EnvironmentMountRequest {
  native_environment_id: NativeID;
  mount_id: string;
  resource_reference: string;
  read_only: boolean;
}
export interface EnvironmentResult { environment: Environment }

export interface RuntimeSession {
  provider_id: string;
  native_session_id: NativeID;
  lifecycle: StateReport;
  health: StateReport;
  extensions: Record<string, JSONValue>;
}
export interface RuntimeSessionRequest { native_session_id: NativeID }
export type RuntimeCheckpointRequest = RuntimeSessionRequest;
export type RuntimeAdoptRequest = RuntimeSessionRequest;
export type RuntimeListSessionsRequest = EmptyRequest;
export interface RuntimeListSessionsResult { sessions: RuntimeSession[] }
export interface RuntimeCreateSessionRequest {
  native_environment_id: NativeID;
  name?: string;
  configuration: JSONValue;
  configuration_digest: Digest;
}
export interface RuntimeRestoreRequest { snapshot_id: NativeID; native_environment_id: NativeID }
export interface RuntimeTransferRequest {
  native_session_id: NativeID;
  native_environment_id: NativeID;
  checkpoint_reference?: NativeID;
}
export interface RuntimeSessionResult { session: RuntimeSession }
export interface RuntimeSnapshot {
  native_session_id: NativeID;
  snapshot_id: NativeID;
  digest: Digest;
  created_at: UTCDateTime;
}

export interface Workspace { provider_id: string; native_workspace_id: NativeID; name: string; extensions: Record<string, JSONValue> }
export type WorkspaceListRequest = EmptyRequest;
export interface WorkspaceRequest { native_workspace_id: NativeID }
export interface WorkspaceCreateRequest { name: string; configuration: JSONValue }
export interface WorkspaceListResult { workspaces: Workspace[] }
export interface Pane { native_workspace_id: NativeID; native_pane_id: NativeID; native_session_id?: NativeID; rows: number; columns: number }
export interface PaneRequest { native_workspace_id: NativeID; native_pane_id: NativeID }
export interface PaneCreateRequest { native_workspace_id: NativeID; native_session_id?: NativeID; rows: number; columns: number }
export interface PaneSplitRequest extends PaneRequest { direction: "horizontal" | "vertical" }
export interface PaneResizeRequest extends PaneRequest { rows: number; columns: number }
export interface PaneListResult { panes: Pane[] }
export interface TopologySnapshot { native_workspace_id: NativeID; revision: number; observed_at: UTCDateTime; panes: Pane[] }

export type TerminalEncoding = "utf-8" | "base64";
export interface TerminalRedaction { start: number; end: number; reason: string }
export interface TerminalChunk {
  native_session_id: NativeID;
  stream_id: string;
  encoding: TerminalEncoding;
  sequence: number;
  offset: number;
  observed_at: UTCDateTime;
  data: string;
  replayed: boolean;
  truncated: boolean;
  redactions: TerminalRedaction[];
  credit_remaining: number;
}
export interface TerminalReadRequest { native_session_id: NativeID; stream_id: string; after_offset: number; maximum_bytes: number }
export interface TerminalSubscribeRequest { native_session_id: NativeID; stream_id: string; after_offset: number; window_bytes: number }
export interface TerminalInputRequest { native_session_id: NativeID; stream_id: string; encoding: TerminalEncoding; data: string }
export interface TerminalKeysRequest { native_session_id: NativeID; stream_id: string; keys: string[] }
export interface TerminalResizeRequest { native_session_id: NativeID; stream_id: string; rows: number; columns: number }
export interface TerminalDetachRequest { native_session_id: NativeID; stream_id: string; subscription_id: string }
export interface TerminalAck { native_session_id: NativeID; stream_id: string; sequence: number; offset: number }
export interface TerminalCredit { native_session_id: NativeID; stream_id: string; bytes: number; through_offset: number }

export interface Usage { input_tokens: number; output_tokens: number; cost_microunits: number }
export interface HarnessState { provider_id: string; native_session_id: NativeID; activity: StateReport; usage: Usage }
export type HarnessSessionRequest = RuntimeSessionRequest;
export type HarnessListRequest = EmptyRequest;
export interface HarnessLaunchRequest {
  native_environment_id: NativeID;
  native_runtime_id?: NativeID;
  context_version: string;
  configuration: JSONValue;
  configuration_digest: Digest;
}
export interface HarnessResumeRequest { native_resume_reference: NativeID; context_version: string }
export interface HarnessSessionResult {
  provider_id: string;
  native_session_id: NativeID;
  native_resume_reference?: NativeID;
  state: HarnessState;
}
export interface HarnessListResult { sessions: HarnessSessionResult[] }
export interface AgentMessageRequest { native_session_id: NativeID; message: JSONValue; message_digest: Digest }
export type AgentControlRequest = HarnessSessionRequest;
export interface AgentStateResult { state: HarnessState }
export interface AgentUsageResult { usage: Usage }
export interface AgentTool { name: string; description?: string; input_schema: JSONValue }
export interface AgentToolsResult { tools: AgentTool[] }
export interface AgentNativeIdentityResult { native_session_id: NativeID; native_agent_id: NativeID }

export type ApprovalOutcome = "approved" | "rejected" | "expired";
export interface ProviderApproval {
  native_approval_id: NativeID;
  native_session_id: NativeID;
  type: string;
  summary: string;
  risk: "low" | "medium" | "high" | "critical";
  requested_scopes: string[];
  request_digest: Digest;
  revision: number;
  expires_at: UTCDateTime;
}
export interface ApprovalListRequest { native_session_id: NativeID }
export interface ApprovalListResult { approvals: ProviderApproval[] }
export interface ApprovalActionRequest {
  native_session_id: NativeID;
  native_approval_id: NativeID;
  outcome: ApprovalOutcome;
  expected_revision: number;
  decision_digest: Digest;
}
export interface ApprovalActionResult { operation: OperationResult }
export interface ApprovalProviderSelection { role: ProviderRole; provider: ArtifactIdentity }
export interface ApprovalBinding {
  command_digest: Digest;
  session_id: string;
  session_revision: number;
  work_item_revision: number;
  resource_revision: number;
  context_version: string;
  policy_revision: number;
  environment: ApprovalProviderSelection;
  runtime?: ApprovalProviderSelection;
  harness: ApprovalProviderSelection;
  gateway_id: string;
  scopes: string[];
  expires_at: UTCDateTime;
  nonce: string;
}
export interface ApprovalDecision {
  protocol_version: ProtocolVersion;
  approval_id: string;
  outcome: ApprovalOutcome;
  binding: ApprovalBinding;
  decision_revision: number;
  decided_at: UTCDateTime;
}

export type ArtifactCreatorType = "agent" | "human" | "workflow" | "system";
export type ArtifactReviewState = "pending" | "approved" | "rejected";
export type ArtifactLocality = "local-only" | "upload-eligible" | "hosted";
export interface Artifact {
  protocol_version: ProtocolVersion;
  artifact_id: string;
  session_id: string;
  creator_type: ArtifactCreatorType;
  creator_id: string;
  version: string;
  review_state: ArtifactReviewState;
  locality: ArtifactLocality;
  locator: string;
  mime_type: string;
  size: number;
  digest: Digest;
  classification: Sensitivity;
  source_resources: string[];
  extensions: Record<string, JSONValue>;
}
export interface ProviderArtifactReport {
  protocol_version: ProtocolVersion;
  report_id: string;
  provider_id: string;
  role: ProviderRole;
  stream_id: string;
  native_session_id?: NativeID;
  native_artifact_id: NativeID;
  version: string;
  locality: Exclude<ArtifactLocality, "hosted">;
  locator: string;
  mime_type: string;
  size: number;
  digest: Digest;
  source_locators: string[];
  extensions: Record<string, JSONValue>;
}
export interface ArtifactListRequest { native_session_id: NativeID }
export interface ArtifactListResult { artifacts: ProviderArtifactReport[] }
export interface ArtifactRegisterRequest { artifact: ProviderArtifactReport }
export interface ArtifactRegisterResult { operation: OperationResult }

export type ContextDeliveryMode = "initial_prompt" | "system_instructions" | "mounted_file" | "environment_reference" | "mcp_resource" | "acp_initialization" | "project_instructions" | "follow_up_message";
export type ContextDeliveryStatus = "accepted" | "rejected" | "failed";
export interface ContextReceipt {
  protocol_version: ProtocolVersion;
  session_id: string;
  provider_id: string;
  native_session_id: NativeID;
  context_version: string;
  source_digest: Digest;
  delivery_mode: ContextDeliveryMode;
  delivered_at: UTCDateTime;
  status: ContextDeliveryStatus;
  native_runtime_may_ignore: boolean;
}
export interface ContextDeliverRequest {
  native_session_id: NativeID;
  context_version: string;
  source_digest: Digest;
  delivery_mode: ContextDeliveryMode;
  content: JSONValue;
  content_digest: Digest;
}
export interface ContextDeliverResult { receipt: ContextReceipt }
export interface ContextConfirmRequest { native_session_id: NativeID; context_version: string }
export interface ContextConfirmResult { receipt: ContextReceipt }

type Mutation<C extends CoreCapabilityName, P> = Command<C, P>;
export interface CapabilityRequestMap {
  "provider.initialize": ProviderInitializeRequest;
  "provider.health": ProviderHealthRequest;
  "provider.capabilities": ProviderCapabilitiesRequest;
  "provider.shutdown": Mutation<"provider.shutdown", ProviderShutdownRequest>;
  "events.subscribe": EventsSubscribeRequest;
  "events.unsubscribe": Mutation<"events.unsubscribe", EventsUnsubscribeRequest>;
  "command.get_result": CommandGetResultRequest;
  "environment.inspect": EnvironmentInspectRequest;
  "environment.health": EnvironmentHealthRequest;
  "environment.provision": Mutation<"environment.provision", EnvironmentProvisionRequest>;
  "environment.mount": Mutation<"environment.mount", EnvironmentMountRequest>;
  "environment.shutdown": Mutation<"environment.shutdown", EnvironmentShutdownRequest>;
  "runtime.list_sessions": RuntimeListSessionsRequest;
  "runtime.get_session": RuntimeSessionRequest;
  "runtime.create_session": Mutation<"runtime.create_session", RuntimeCreateSessionRequest>;
  "runtime.stop_session": Mutation<"runtime.stop_session", RuntimeSessionRequest>;
  "runtime.terminate_session": Mutation<"runtime.terminate_session", RuntimeSessionRequest>;
  "runtime.attach": Mutation<"runtime.attach", RuntimeSessionRequest>;
  "runtime.detach": Mutation<"runtime.detach", RuntimeSessionRequest>;
  "runtime.snapshot": RuntimeSessionRequest;
  "runtime.checkpoint": Mutation<"runtime.checkpoint", RuntimeCheckpointRequest>;
  "runtime.restore": Mutation<"runtime.restore", RuntimeRestoreRequest>;
  "runtime.adopt": Mutation<"runtime.adopt", RuntimeAdoptRequest>;
  "runtime.resume": Mutation<"runtime.resume", RuntimeSessionRequest>;
  "runtime.clone": Mutation<"runtime.clone", RuntimeSessionRequest>;
  "runtime.fork": Mutation<"runtime.fork", RuntimeSessionRequest>;
  "runtime.migrate": Mutation<"runtime.migrate", RuntimeTransferRequest>;
  "runtime.export": Mutation<"runtime.export", RuntimeSessionRequest>;
  "runtime.import": Mutation<"runtime.import", RuntimeRestoreRequest>;
  "runtime.archive": Mutation<"runtime.archive", RuntimeSessionRequest>;
  "terminal.read": TerminalReadRequest;
  "terminal.subscribe": TerminalSubscribeRequest;
  "terminal.send_input": Mutation<"terminal.send_input", TerminalInputRequest>;
  "terminal.send_keys": Mutation<"terminal.send_keys", TerminalKeysRequest>;
  "terminal.resize": Mutation<"terminal.resize", TerminalResizeRequest>;
  "terminal.attach": Mutation<"terminal.attach", TerminalSubscribeRequest>;
  "terminal.detach": Mutation<"terminal.detach", TerminalDetachRequest>;
  "workspace.list": WorkspaceListRequest;
  "workspace.get": WorkspaceRequest;
  "workspace.create": Mutation<"workspace.create", WorkspaceCreateRequest>;
  "workspace.close": Mutation<"workspace.close", WorkspaceRequest>;
  "topology.get": WorkspaceRequest;
  "topology.subscribe": WorkspaceRequest;
  "pane.list": WorkspaceRequest;
  "pane.get": PaneRequest;
  "pane.create": Mutation<"pane.create", PaneCreateRequest>;
  "pane.split": Mutation<"pane.split", PaneSplitRequest>;
  "pane.focus": Mutation<"pane.focus", PaneRequest>;
  "pane.resize": Mutation<"pane.resize", PaneResizeRequest>;
  "pane.close": Mutation<"pane.close", PaneRequest>;
  "harness.list": HarnessListRequest;
  "harness.inspect": HarnessSessionRequest;
  "harness.launch": Mutation<"harness.launch", HarnessLaunchRequest>;
  "harness.resume": Mutation<"harness.resume", HarnessResumeRequest>;
  "harness.stop": Mutation<"harness.stop", HarnessSessionRequest>;
  "agent.send_message": Mutation<"agent.send_message", AgentMessageRequest>;
  "agent.interrupt": Mutation<"agent.interrupt", AgentControlRequest>;
  "agent.cancel": Mutation<"agent.cancel", AgentControlRequest>;
  "agent.get_state": HarnessSessionRequest;
  "agent.get_usage": HarnessSessionRequest;
  "agent.get_pending_approvals": HarnessSessionRequest;
  "agent.get_tools": HarnessSessionRequest;
  "agent.get_native_identity": HarnessSessionRequest;
  "context.deliver": Mutation<"context.deliver", ContextDeliverRequest>;
  "context.confirm": ContextConfirmRequest;
  "approval.list": ApprovalListRequest;
  "approval.approve": Mutation<"approval.approve", ApprovalActionRequest>;
  "approval.reject": Mutation<"approval.reject", ApprovalActionRequest>;
  "approval.expire": Mutation<"approval.expire", ApprovalActionRequest>;
  "artifact.list": ArtifactListRequest;
  "artifact.register": Mutation<"artifact.register", ArtifactRegisterRequest>;
}

export interface CapabilityResultMap {
  "provider.initialize": ProviderInitializeResult;
  "provider.health": ProviderHealthResult;
  "provider.capabilities": ProviderCapabilitiesResult;
  "provider.shutdown": OperationResult;
  "events.subscribe": EventsSubscribeResult;
  "events.unsubscribe": OperationResult;
  "command.get_result": CommandResult;
  "environment.inspect": EnvironmentResult;
  "environment.health": EnvironmentResult;
  "environment.provision": EnvironmentResult;
  "environment.mount": EnvironmentResult;
  "environment.shutdown": EnvironmentResult;
  "runtime.list_sessions": RuntimeListSessionsResult;
  "runtime.get_session": RuntimeSessionResult;
  "runtime.create_session": RuntimeSessionResult;
  "runtime.stop_session": RuntimeSessionResult;
  "runtime.terminate_session": RuntimeSessionResult;
  "runtime.attach": RuntimeSessionResult;
  "runtime.detach": RuntimeSessionResult;
  "runtime.snapshot": RuntimeSnapshot;
  "runtime.checkpoint": RuntimeSnapshot;
  "runtime.restore": RuntimeSessionResult;
  "runtime.adopt": RuntimeSessionResult;
  "runtime.resume": RuntimeSessionResult;
  "runtime.clone": RuntimeSessionResult;
  "runtime.fork": RuntimeSessionResult;
  "runtime.migrate": RuntimeSessionResult;
  "runtime.export": RuntimeSnapshot;
  "runtime.import": RuntimeSessionResult;
  "runtime.archive": RuntimeSessionResult;
  "terminal.read": TerminalChunk;
  "terminal.subscribe": EventsSubscribeResult;
  "terminal.send_input": TerminalAck;
  "terminal.send_keys": TerminalAck;
  "terminal.resize": TerminalAck;
  "terminal.attach": EventsSubscribeResult;
  "terminal.detach": TerminalAck;
  "workspace.list": WorkspaceListResult;
  "workspace.get": Workspace;
  "workspace.create": Workspace;
  "workspace.close": OperationResult;
  "topology.get": TopologySnapshot;
  "topology.subscribe": EventsSubscribeResult;
  "pane.list": PaneListResult;
  "pane.get": Pane;
  "pane.create": Pane;
  "pane.split": Pane;
  "pane.focus": Pane;
  "pane.resize": Pane;
  "pane.close": OperationResult;
  "harness.list": HarnessListResult;
  "harness.inspect": HarnessSessionResult;
  "harness.launch": HarnessSessionResult;
  "harness.resume": HarnessSessionResult;
  "harness.stop": OperationResult;
  "agent.send_message": AgentStateResult;
  "agent.interrupt": OperationResult;
  "agent.cancel": OperationResult;
  "agent.get_state": AgentStateResult;
  "agent.get_usage": AgentUsageResult;
  "agent.get_pending_approvals": ApprovalListResult;
  "agent.get_tools": AgentToolsResult;
  "agent.get_native_identity": AgentNativeIdentityResult;
  "context.deliver": ContextDeliverResult;
  "context.confirm": ContextConfirmResult;
  "approval.list": ApprovalListResult;
  "approval.approve": ApprovalActionResult;
  "approval.reject": ApprovalActionResult;
  "approval.expire": ApprovalActionResult;
  "artifact.list": ArtifactListResult;
  "artifact.register": ArtifactRegisterResult;
}

export type CapabilityRequest<C extends CoreCapabilityName> = CapabilityRequestMap[C];
export type CapabilityResult<C extends CoreCapabilityName> = CapabilityResultMap[C];

export interface Heartbeat { observed_at: UTCDateTime }
export interface CancelRequest { request_id: string }
export type Notification =
  | { method: typeof NOTIFICATION_EVENT; params: ProviderEvent }
  | { method: typeof NOTIFICATION_TERMINAL_CHUNK; params: TerminalChunk }
  | { method: typeof NOTIFICATION_TOPOLOGY_SNAPSHOT; params: TopologySnapshot }
  | { method: typeof NOTIFICATION_HEARTBEAT; params: Heartbeat }
  | { method: typeof NOTIFICATION_CANCEL; params: CancelRequest }
  | { method: typeof NOTIFICATION_TERMINAL_CREDIT; params: TerminalCredit };

export type ProtocolDocumentKind = "provider_manifest" | "session" | "command" | "event" | "artifact" | "approval_decision" | "context_receipt";

const ajv = new Ajv2020({ allErrors: false, strict: false, validateFormats: true });
(addFormats as unknown as (instance: Ajv2020) => Ajv2020)(ajv);
ajv.addSchema(commandSchema as AnySchema, "command.v1alpha1.schema.json");
ajv.addSchema(eventSchema as AnySchema, "event.v1alpha1.schema.json");
ajv.addSchema(manifestSchema as AnySchema, "provider-manifest.v1alpha1.schema.json");
ajv.addSchema(sessionSchema as AnySchema, "session.v1alpha1.schema.json");

const openRPCDocument = openRPC as unknown as {
  components: { schemas: Record<string, AnySchema> };
  methods: Array<{ name: string; params: Array<{ schema: AnySchema }>; result: { schema: AnySchema } }>;
};

function compileOpenRPC(schema: AnySchema): ValidateFunction {
  return ajv.compile({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    components: openRPCDocument.components,
    allOf: [schema],
  } as AnySchema);
}

const methodValidators = new Map<string, { request: ValidateFunction; result: ValidateFunction }>();
for (const method of openRPCDocument.methods) {
  const parameter = method.params[0];
  if (parameter !== undefined) {
    methodValidators.set(method.name, {
      request: compileOpenRPC(parameter.schema),
      result: compileOpenRPC(method.result.schema),
    });
  }
}

const documentValidators: Record<ProtocolDocumentKind, ValidateFunction> = {
  provider_manifest: ajv.getSchema("provider-manifest.v1alpha1.schema.json") ?? ajv.compile(manifestSchema as AnySchema),
  session: ajv.getSchema("session.v1alpha1.schema.json") ?? ajv.compile(sessionSchema as AnySchema),
  command: ajv.getSchema("command.v1alpha1.schema.json") ?? ajv.compile(commandSchema as AnySchema),
  event: ajv.getSchema("event.v1alpha1.schema.json") ?? ajv.compile(eventSchema as AnySchema),
  artifact: compileOpenRPC(openRPCDocument.components.schemas.Artifact ?? false),
  approval_decision: compileOpenRPC(openRPCDocument.components.schemas.ApprovalDecision ?? false),
  context_receipt: compileOpenRPC(openRPCDocument.components.schemas.ContextReceipt ?? false),
};

export function validateProtocolDocument(kind: ProtocolDocumentKind, value: unknown): boolean {
  return (
    hasSafeNumbers(value) &&
    documentValidators[kind](value) &&
    validateProviderAuthority(kind, value) &&
    validateDocumentSemantics(kind, value) &&
    validateNativeIDFields(value, kind === "event" || kind === "command")
  );
}

export function assertProtocolDocument<T = unknown>(kind: ProtocolDocumentKind, value: unknown): T {
  if (!validateProtocolDocument(kind, value)) throw protocolError("invalid_argument");
  return value as T;
}

export function validateCapabilityRequest<C extends CoreCapabilityName>(capability: C, value: unknown): value is CapabilityRequest<C>;
export function validateCapabilityRequest(capability: CapabilityName, value: unknown): value is JSONObject;
export function validateCapabilityRequest(capability: CapabilityName, value: unknown): value is JSONObject {
  return validateCapabilityRequestValue(capability, value, false);
}

/** Validates a request decoded from protocol JSON while preserving Go-compatible raw digests. */
export function validateWireCapabilityRequest(
  capability: CapabilityName,
  value: unknown,
): value is JSONObject {
  return validateCapabilityRequestValue(capability, value, true);
}

function validateCapabilityRequestValue(
  capability: CapabilityName,
  value: unknown,
  useParsedSource: boolean,
): value is JSONObject {
  const validator = methodValidators.get(capability);
  if (validator !== undefined) {
    return (
      hasSafeNumbers(value) &&
      validator.request(value) &&
      validateCapabilityRequestSemantics(capability, value, useParsedSource) &&
      validateNativeIDFields(value, false)
    );
  }
  return isExtensionCapability(capability) && isObject(value) && !containsReservedAuthority(value);
}

export function validateCapabilityResult<C extends CoreCapabilityName>(capability: C, value: unknown): value is CapabilityResult<C>;
export function validateCapabilityResult(capability: CapabilityName, value: unknown): value is JSONValue;
export function validateCapabilityResult(capability: CapabilityName, value: unknown): value is JSONValue {
  const validator = methodValidators.get(capability);
  if (validator !== undefined) {
    return (
      hasSafeNumbers(value) &&
      validator.result(value) &&
      validateCapabilityAuthority(capability, value) &&
      validateNativeIDFields(value, false)
    );
  }
  return isExtensionCapability(capability) && validateExtensionValue(value);
}

export function validateExtensionValue(value: unknown): value is Exclude<JSONValue, null> {
  return value !== null && isJSONValue(value) && !containsReservedAuthority(value);
}

export function assertCapabilityRequest<C extends CoreCapabilityName>(capability: C, value: unknown): CapabilityRequest<C>;
export function assertCapabilityRequest(capability: CapabilityName, value: unknown): JSONObject;
export function assertCapabilityRequest(capability: CapabilityName, value: unknown): JSONObject {
  if (!validateCapabilityRequest(capability, value)) throw protocolError("invalid_argument");
  return value as JSONObject;
}

export function assertCapabilityResult<C extends CoreCapabilityName>(capability: C, value: unknown): CapabilityResult<C>;
export function assertCapabilityResult(capability: CapabilityName, value: unknown): JSONValue;
export function assertCapabilityResult(capability: CapabilityName, value: unknown): JSONValue {
  if (!validateCapabilityResult(capability, value)) throw protocolError("invalid_argument");
  return value as JSONValue;
}

export function validateProviderManifest(value: unknown): value is ProviderManifest {
  return validateProtocolDocument("provider_manifest", value);
}
export function validateCommand(value: unknown): value is Command {
  return validateProtocolDocument("command", value);
}
export function validateTerminalChunk(value: unknown): value is TerminalChunk {
  return validateCapabilityResult("terminal.read", value);
}
export function validateProviderEvent(value: unknown): value is ProviderEvent {
  return isObject(value) && "provider_id" in value && validateProtocolDocument("event", value);
}
export function validateTopologySnapshot(value: unknown): value is TopologySnapshot {
  return validateCapabilityResult("topology.get", value);
}
export function validateTerminalCredit(value: unknown): value is TerminalCredit {
  return (
    isObject(value) &&
    hasOnlyKeys(value, ["native_session_id", "stream_id", "bytes", "through_offset"]) &&
    isNativeID(value.native_session_id) &&
    isCanonicalID(value.stream_id) &&
    isBoundedInteger(value.bytes, 1, MAX_TERMINAL_WINDOW_BYTES) &&
    isBoundedInteger(value.through_offset, 0, Number.MAX_SAFE_INTEGER)
  );
}
export function validateNotification(method: string, value: unknown): value is JSONObject {
  switch (method) {
    case NOTIFICATION_EVENT:
      return validateProviderEvent(value);
    case NOTIFICATION_TERMINAL_CHUNK:
      return validateTerminalChunk(value);
    case NOTIFICATION_TOPOLOGY_SNAPSHOT:
      return validateTopologySnapshot(value);
    case NOTIFICATION_HEARTBEAT:
      return isObject(value) && hasOnlyKeys(value, ["observed_at"]) && isUTCTimestamp(value.observed_at);
    case NOTIFICATION_CANCEL:
      return isObject(value) && hasOnlyKeys(value, ["request_id"]) && isWireToken(value.request_id);
    case NOTIFICATION_TERMINAL_CREDIT:
      return validateTerminalCredit(value);
    default:
      return false;
  }
}
export function validateProviderInitializeRequest(value: unknown): value is ProviderInitializeRequest {
  return validateCapabilityRequest("provider.initialize", value);
}
export function validateProviderInitializeResult(value: unknown): value is ProviderInitializeResult {
  return validateCapabilityResult("provider.initialize", value);
}

export function validateProviderNegotiation(request: ProviderInitializeRequest, result: ProviderInitializeResult): boolean {
  return (
    validateProviderInitializeRequest(request) &&
    validateProviderInitializeResult(result) &&
    request.supported_protocol_versions.includes(result.protocol_version) &&
    result.manifest.platforms.some((platform) => platform.os === request.platform.os && platform.architecture === request.platform.architecture) &&
    request.required_capabilities.every((required) => result.manifest.capabilities.some(({ name }) => name === required)) &&
    result.maximum_message_bytes <= request.maximum_message_bytes &&
    result.maximum_chunk_bytes <= request.maximum_chunk_bytes &&
    (!result.replay_supported || request.replay_supported) &&
    request.authentication_modes.includes(result.authentication_mode) &&
    result.experimental_features.every((feature) => request.experimental_features.includes(feature))
  );
}

export function parseProtocolJSON(text: string): JSONValue {
  try {
    return new StrictJSONParser(text).parse();
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw protocolError("invalid_argument");
  }
}

class StrictJSONParser {
  private position = 0;
  constructor(private readonly source: string) {}

  parse(): JSONValue {
    this.skipWhitespace();
    const value = this.value();
    this.skipWhitespace();
    if (this.position !== this.source.length) throw new SyntaxError("trailing JSON data");
    return value;
  }

  private value(): JSONValue {
    this.skipWhitespace();
    const sourceStart = this.position;
    const character = this.source[this.position];
    if (character === "{") {
      const value = this.object();
      rememberParsedJSON(value, this.source.slice(sourceStart, this.position));
      return value;
    }
    if (character === "[") {
      const value = this.array();
      rememberParsedJSON(value, this.source.slice(sourceStart, this.position));
      return value;
    }
    if (character === '"') return this.string();
    const primitiveStart = this.position;
    while (this.position < this.source.length && !/[\s,}\]]/.test(this.source[this.position] ?? "")) this.position++;
    if (primitiveStart === this.position) throw new SyntaxError("JSON value required");
    const primitive: unknown = JSON.parse(this.source.slice(primitiveStart, this.position));
    if (primitive !== null && typeof primitive !== "string" && typeof primitive !== "number" && typeof primitive !== "boolean") {
      throw new SyntaxError("invalid JSON primitive");
    }
    if (typeof primitive === "number" && (!Number.isFinite(primitive) || (Number.isInteger(primitive) && !Number.isSafeInteger(primitive)))) {
      throw new SyntaxError("unsafe JSON number");
    }
    return primitive;
  }

  private object(): JSONObject {
    this.position++;
    const result: Record<string, JSONValue> = {};
    const keys = new Set<string>();
    const properties = new Map<string, ParsedJSONSource>();
    this.skipWhitespace();
    if (this.source[this.position] === "}") {
      this.position++;
      parsedJSONProperties.set(result, properties);
      return result;
    }
    while (true) {
      this.skipWhitespace();
      if (this.source[this.position] !== '"') throw new SyntaxError("object key required");
      const key = this.string();
      if (keys.has(key)) throw protocolError("invalid_argument");
      keys.add(key);
      this.skipWhitespace();
      if (this.source[this.position++] !== ":") throw new SyntaxError("object colon required");
      this.skipWhitespace();
      const valueStart = this.position;
      const value = this.value();
      properties.set(key, parsedSource(value, this.source.slice(valueStart, this.position)));
      Object.defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value,
        writable: true,
      });
      this.skipWhitespace();
      const separator = this.source[this.position++];
      if (separator === "}") {
        parsedJSONProperties.set(result, properties);
        return result;
      }
      if (separator !== ",") throw new SyntaxError("object separator required");
    }
  }

  private array(): readonly JSONValue[] {
    this.position++;
    const result: JSONValue[] = [];
    this.skipWhitespace();
    if (this.source[this.position] === "]") { this.position++; return result; }
    while (true) {
      result.push(this.value());
      this.skipWhitespace();
      const separator = this.source[this.position++];
      if (separator === "]") return result;
      if (separator !== ",") throw new SyntaxError("array separator required");
    }
  }

  private string(): string {
    const start = this.position++;
    while (this.position < this.source.length) {
      const character = this.source[this.position++];
      if (character === '"') return JSON.parse(this.source.slice(start, this.position)) as string;
      if (character === "\\") this.position++;
    }
    throw new SyntaxError("unterminated JSON string");
  }

  private skipWhitespace(): void {
    while (/[\t\n\r ]/.test(this.source[this.position] ?? "")) this.position++;
  }
}

function isExtensionCapability(value: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\/[a-z][a-z0-9._-]{0,127}$/.test(value);
}
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function hasSafeNumbers(value: unknown): boolean {
  if (typeof value === "number") return Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
  if (Array.isArray(value)) return value.every(hasSafeNumbers);
  if (isObject(value)) return Object.values(value).every(hasSafeNumbers);
  return true;
}
function isJSONValue(value: unknown): value is JSONValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return hasSafeNumbers(value);
  if (Array.isArray(value)) return value.every(isJSONValue);
  return isObject(value) && Object.values(value).every(isJSONValue);
}

const RESERVED_AUTHORITY = new Set([
  "tenant_id", "project_id", "initiative_id", "work_item_id", "gateway_id", "session_id",
  "canonical_session_id", "correlation_id", "causation_id", "sensitivity", "authority",
  "verification_tier", "tier", "verified", "artifact_id", "creator_type", "creator_id",
  "review_state", "classification", "approval_id", "approved", "decision_revision",
]);
function containsReservedAuthority(value: unknown, allowedRoot: ReadonlySet<string> = new Set(), root = true): boolean {
  if (Array.isArray(value)) return value.some((entry) => containsReservedAuthority(entry));
  if (!isObject(value)) return false;
  return Object.entries(value).some(([key, child]) =>
    (RESERVED_AUTHORITY.has(key) && !(root && allowedRoot.has(key))) || containsReservedAuthority(child, new Set(), false),
  );
}
function validateProviderAuthority(kind: ProtocolDocumentKind, value: unknown): boolean {
  if (!isObject(value)) return false;
  if (kind === "provider_manifest") {
    return (
      validateProviderCapabilitySet(value.roles, value.capabilities) &&
      validateProviderManifestText(value) &&
      validateProviderExtensionMap(value.extensions)
    );
  }
  if (kind === "event") {
    const event = "provider_event" in value && isObject(value.provider_event) ? value.provider_event : value;
    const allowed = event.type === "session.state_changed" ? new Set(["authority"]) : new Set<string>();
    if (typeof event.type === "string" && event.type.startsWith("artifact.")) {
      const report = event.payload;
      if (
        !isObject(report) ||
        report.provider_id !== event.provider_id ||
        report.role !== event.role ||
        report.stream_id !== event.stream_id ||
        (report.native_session_id ?? "") !== (event.native_session_id ?? "")
      ) {
        return false;
      }
      if (
        !validateProviderText(report.mime_type, 1, 256) ||
        !validateProviderExtensionMap(report.extensions)
      ) {
        return false;
      }
    }
    return validateProviderExtensionMap(event.extensions) && !containsReservedAuthority(event.payload, allowed);
  }
  if (kind === "session" || kind === "artifact") {
    return validateProviderExtensionMap(value.extensions);
  }
  return true;
}
function validateCapabilityRequestSemantics(
  capability: CapabilityName,
  value: unknown,
  useParsedSource: boolean,
): boolean {
  if (!isObject(value)) return false;
  const descriptor = CAPABILITY_CATALOG.find(({ name }) => name === capability);
  const payload = descriptor !== undefined && "mutating" in descriptor && descriptor.mutating === true ? value.payload : value;
  if (!isObject(payload)) return false;
  if (
    descriptor !== undefined &&
    "mutating" in descriptor &&
    descriptor.mutating === true &&
    (!validateProviderText(value.idempotency_key, 16, 256) ||
      !validateProviderText(value.cancellation_token, 16, 256))
  ) {
    return false;
  }
  switch (capability) {
    case "provider.initialize":
      return (
        typeof payload.maximum_message_bytes === "number" &&
        typeof payload.maximum_chunk_bytes === "number" &&
        payload.maximum_chunk_bytes <= payload.maximum_message_bytes
      );
    case "terminal.send_input": {
      const size = terminalPayloadByteLength(payload);
      return size >= 1 && size <= MAX_TERMINAL_CHUNK_BYTES;
    }
    case "terminal.send_keys":
      return (
        Array.isArray(payload.keys) &&
        payload.keys.every((key) => validateProviderText(key, 1, 64))
      );
    case "workspace.create":
      return validateProviderText(payload.name, 1, 256);
    case "environment.provision":
      return compactDigestMatches(payload.configuration, payload.configuration_digest, payload, "configuration", useParsedSource);
    case "runtime.create_session":
      return (
        (payload.name === undefined || validateProviderText(payload.name, 1, 128)) &&
        compactDigestMatches(
          payload.configuration,
          payload.configuration_digest,
          payload,
          "configuration",
          useParsedSource,
        )
      );
    case "harness.launch":
      return compactDigestMatches(payload.configuration, payload.configuration_digest, payload, "configuration", useParsedSource);
    case "agent.send_message":
      return compactDigestMatches(payload.message, payload.message_digest, payload, "message", useParsedSource);
    case "context.deliver":
      return compactDigestMatches(payload.content, payload.content_digest, payload, "content", useParsedSource);
    case "artifact.register":
      return (
        isObject(payload.artifact) &&
        validateProviderText(payload.artifact.mime_type, 1, 256) &&
        validateProviderVersion(payload.artifact.version) &&
        validateProviderExtensionMap(payload.artifact.extensions)
      );
    case "events.subscribe":
      return hasUniqueCompositeKey(payload.cursors, ["role", "stream_id"]);
    default:
      return true;
  }
}
function validateCapabilityAuthority(capability: CapabilityName, value: unknown): boolean {
  if (!isObject(value)) return false;
  if (capability === "provider.initialize") {
    return (
      isObject(value.manifest) &&
      validateProviderAuthority("provider_manifest", value.manifest) &&
      typeof value.maximum_message_bytes === "number" &&
      typeof value.maximum_chunk_bytes === "number" &&
      value.maximum_chunk_bytes <= value.maximum_message_bytes &&
      (value.native_runtime_version === undefined || validateProviderVersion(value.native_runtime_version))
    );
  }
  if (capability === "provider.capabilities") {
    return validateProviderCapabilitySet(value.roles, value.capabilities);
  }
  if (capability === "provider.health") return validateStateReportSemantics(value.health);
  if (["environment.inspect", "environment.health", "environment.provision", "environment.mount", "environment.shutdown"].includes(capability)) {
    return isObject(value.environment) && validateStateReportSemantics(value.environment.health);
  }
  if (capability === "terminal.read") return validateTerminalChunkSemantics(value);
  if (["runtime.list_sessions", "runtime.get_session", "runtime.create_session", "runtime.stop_session", "runtime.terminate_session", "runtime.attach", "runtime.detach", "runtime.restore", "runtime.adopt", "runtime.resume", "runtime.clone", "runtime.fork", "runtime.migrate", "runtime.import", "runtime.archive"].includes(capability)) {
    const sessions = Array.isArray(value.sessions) ? value.sessions : isObject(value.session) ? [value.session] : [];
    return (
      sessions.every(
        (session) =>
          isObject(session) &&
          validateProviderExtensionMap(session.extensions) &&
          validateStateReportSemantics(session.lifecycle) &&
          validateStateReportSemantics(session.health),
      ) &&
      (capability !== "runtime.list_sessions" || hasUniqueCompositeKey(sessions, ["native_session_id"]))
    );
  }
  if (["workspace.list", "workspace.get", "workspace.create"].includes(capability)) {
    const workspaces = Array.isArray(value.workspaces) ? value.workspaces : [value];
    return (
      workspaces.every(
        (workspace) =>
          isObject(workspace) &&
          validateProviderText(workspace.name, 1, 256) &&
          validateProviderExtensionMap(workspace.extensions),
      ) &&
      (capability !== "workspace.list" || hasUniqueCompositeKey(workspaces, ["native_workspace_id"]))
    );
  }
  if (capability === "artifact.list") {
    return (
      Array.isArray(value.artifacts) &&
      value.artifacts.every(
        (artifact) =>
          isObject(artifact) &&
          validateProviderText(artifact.mime_type, 1, 256) &&
          validateProviderExtensionMap(artifact.extensions),
      ) &&
      hasUniqueCompositeKey(value.artifacts, ["native_artifact_id"])
    );
  }
  if (capability === "pane.list") {
    return hasUniqueCompositeKey(value.panes, ["native_pane_id"]);
  }
  if (capability === "topology.get") return validateTopologySemantics(value);
  if (capability === "harness.list") {
    return (
      Array.isArray(value.sessions) &&
      value.sessions.every(validateHarnessSessionIdentity) &&
      hasUniqueCompositeKey(value.sessions, ["native_session_id"])
    );
  }
  if (
    capability === "harness.inspect" ||
    capability === "harness.launch" ||
    capability === "harness.resume"
  ) {
    return validateHarnessSessionIdentity(value);
  }
  if (capability === "agent.get_state" || capability === "agent.send_message") {
    return isObject(value.state) && validateStateReportSemantics(value.state.activity);
  }
  if (capability === "agent.get_tools") {
    return (
      Array.isArray(value.tools) &&
      value.tools.every(
        (tool) =>
          isObject(tool) &&
          (tool.description === undefined || validateProviderText(tool.description, 1, 512)),
      ) && hasUniqueCompositeKey(value.tools, ["name"])
    );
  }
  if (capability === "approval.list" || capability === "agent.get_pending_approvals") {
    return (
      Array.isArray(value.approvals) &&
      value.approvals.every(
        (approval) => isObject(approval) && validateProviderText(approval.summary, 1, 512),
      ) && hasUniqueCompositeKey(value.approvals, ["native_approval_id"])
    );
  }
  return true;
}

function validateProviderCapabilitySet(rolesValue: unknown, capabilitiesValue: unknown): boolean {
  if (!Array.isArray(rolesValue) || !Array.isArray(capabilitiesValue)) return false;
  const roles = new Set(rolesValue.filter((role): role is string => typeof role === "string"));
  if (roles.size !== rolesValue.length) return false;
  const names = new Set<string>();
  for (const capability of capabilitiesValue) {
    if (!isObject(capability) || typeof capability.name !== "string" || typeof capability.role !== "string") {
      return false;
    }
    if (names.has(capability.name)) return false;
    names.add(capability.name);
    if (capability.role !== "provider" && !roles.has(capability.role)) return false;
    const known = CAPABILITY_CATALOG.find(({ name }) => name === capability.name);
    if (
      known !== undefined &&
      (capability.role !== known.role ||
        (capability.mutating === true) !== ("mutating" in known && known.mutating === true) ||
        (capability.delivery_class ?? undefined) !==
          ("delivery_class" in known ? known.delivery_class : undefined))
    ) {
      return false;
    }
  }
  return true;
}

function validateProviderExtensionMap(value: unknown): boolean {
  if (!isObject(value) || containsReservedAuthority(value)) return false;
  let total = 0;
  for (const [key, child] of Object.entries(value)) {
    let compact: string | undefined;
    try {
      compact = parsedSourceFor(child, value, key)?.compact ?? JSON.stringify(child);
    } catch {
      return false;
    }
    if (compact === undefined) return false;
    total += Buffer.byteLength(key, "utf8") + Buffer.byteLength(compact, "utf8");
    if (total > 256 << 10) return false;
  }
  return true;
}

function validateProviderManifestText(value: Record<string, unknown>): boolean {
  return (
    validateProviderText(value.name, 1, 256) &&
    validateProviderText(value.executable, 1, 256) &&
    validateProviderVersion(value.version)
  );
}

function validateHarnessSessionIdentity(value: unknown): boolean {
  return (
    isObject(value) &&
    isObject(value.state) &&
    value.state.provider_id === value.provider_id &&
    value.state.native_session_id === value.native_session_id &&
    validateStateReportSemantics(value.state.activity)
  );
}

function validateDocumentSemantics(kind: ProtocolDocumentKind, value: unknown): boolean {
  if (!isObject(value)) return false;
  if (kind === "session") {
    return [value.lifecycle, value.activity, value.health].every(validateStateReportSemantics);
  }
  if (kind === "event") {
    const event = "provider_event" in value && isObject(value.provider_event)
      ? value.provider_event
      : value;
    return event.type !== "session.state_changed" || validateStateReportSemantics(event.payload);
  }
  if (kind === "command") {
    return (
      validateProviderText(value.idempotency_key, 16, 256) &&
      validateProviderText(value.cancellation_token, 16, 256)
    );
  }
  if (kind === "artifact") return validateProviderText(value.mime_type, 1, 256);
  return true;
}

function validateStateReportSemantics(value: unknown): boolean {
  if (!isObject(value)) return false;
  if (
    !validateProviderText(value.source, 1, 128) ||
    (value.status !== undefined && !validateProviderText(value.status, 1, 1024))
  ) {
    return false;
  }
  if (value.expires_at === undefined) return true;
  const observed = parseRFC3339Nanoseconds(value.observed_at);
  const expires = parseRFC3339Nanoseconds(value.expires_at);
  return observed !== undefined && expires !== undefined && expires > observed;
}

const NATIVE_ID_FIELDS = new Set([
  "native_id",
  "native_environment_id",
  "native_session_id",
  "native_workspace_id",
  "native_pane_id",
  "native_runtime_id",
  "native_resume_reference",
  "native_agent_id",
  "native_approval_id",
  "native_artifact_id",
  "snapshot_id",
  "checkpoint_reference",
  "subscription_id",
  "operation_id",
]);

const OPAQUE_JSON_FIELDS = new Set([
  "extensions",
  "configuration",
  "message",
  "content",
  "input_schema",
  "result",
]);

function validateNativeIDFields(value: unknown, skipPayload: boolean): boolean {
  if (Array.isArray(value)) return value.every((item) => validateNativeIDFields(item, skipPayload));
  if (!isObject(value)) return true;
  for (const [key, child] of Object.entries(value)) {
    if (NATIVE_ID_FIELDS.has(key)) {
      if (!isNativeID(child)) return false;
      continue;
    }
    if (OPAQUE_JSON_FIELDS.has(key) || (skipPayload && key === "payload")) continue;
    if (!validateNativeIDFields(child, skipPayload)) return false;
  }
  return true;
}

function validateTopologySemantics(value: unknown): boolean {
  if (!isObject(value) || typeof value.native_workspace_id !== "string" || !Array.isArray(value.panes)) {
    return false;
  }
  return (
    value.panes.every(
      (pane) => isObject(pane) && pane.native_workspace_id === value.native_workspace_id,
    ) && hasUniqueCompositeKey(value.panes, ["native_pane_id"])
  );
}

function validateTerminalChunkSemantics(value: unknown): boolean {
  if (
    !isObject(value) ||
    !Number.isSafeInteger(value.offset) ||
    !Array.isArray(value.redactions)
  ) {
    return false;
  }
  const size = terminalChunkByteLength(value);
  const offset = value.offset as number;
  const end = offset + size;
  if (size < 1 || size > MAX_TERMINAL_CHUNK_BYTES || !Number.isSafeInteger(end)) return false;
  let priorEnd = offset;
  for (const redaction of value.redactions) {
    if (
      !isObject(redaction) ||
      !Number.isSafeInteger(redaction.start) ||
      !Number.isSafeInteger(redaction.end) ||
      (redaction.start as number) < offset ||
      (redaction.start as number) < priorEnd ||
      (redaction.end as number) <= (redaction.start as number) ||
      (redaction.end as number) > end ||
      typeof redaction.reason !== "string" ||
      !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(redaction.reason)
    ) {
      return false;
    }
    priorEnd = redaction.end as number;
  }
  return true;
}

function terminalChunkByteLength(value: Record<string, unknown>): number {
  return terminalPayloadByteLength(value);
}

function terminalPayloadByteLength(value: Record<string, unknown>): number {
  if (typeof value.data !== "string") return -1;
  if (value.encoding === "utf-8") {
    return isWellFormedUnicode(value.data) ? Buffer.byteLength(value.data, "utf8") : -1;
  }
  if (value.encoding !== "base64") return -1;
  try {
    const decoded = Buffer.from(value.data, "base64");
    return decoded.toString("base64") === value.data ? decoded.length : -1;
  } catch {
    return -1;
  }
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function hasUniqueCompositeKey(value: unknown, fields: readonly string[]): boolean {
  if (!Array.isArray(value)) return false;
  const seen = new Set<string>();
  for (const entry of value) {
    if (!isObject(entry)) return false;
    const parts: string[] = [];
    for (const field of fields) {
      const part = entry[field];
      if (typeof part !== "string") return false;
      parts.push(`${part.length}:${part}`);
    }
    const key = parts.join("");
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

function compactDigestMatches(
  value: unknown,
  digest: unknown,
  parent: Record<string, unknown>,
  field: string,
  useParsedSource: boolean,
): boolean {
  if (typeof digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(digest)) return false;
  try {
    const source = useParsedSource ? parsedSourceFor(value, parent, field) : undefined;
    const compact = source?.compact ?? JSON.stringify(value);
    if (compact === undefined) return false;
    return `sha256:${createHash("sha256").update(compact).digest("hex")}` === digest;
  } catch {
    return false;
  }
}

function rememberParsedJSON(value: object, raw: string): void {
  parsedJSONSources.set(value, parsedSource(value, raw));
}

function parsedSource(value: unknown, raw: string): ParsedJSONSource {
  const canonical = JSON.stringify(value);
  if (canonical === undefined) throw new SyntaxError("invalid JSON value");
  return { compact: compactJSON(raw), canonical };
}

function parsedSourceFor(
  value: unknown,
  parent: Record<string, unknown>,
  field: string,
): ParsedJSONSource | undefined {
  const source = typeof value === "object" && value !== null
    ? parsedJSONSources.get(value)
    : parsedJSONProperties.get(parent)?.get(field);
  if (source === undefined) return undefined;
  return JSON.stringify(value) === source.canonical ? source : undefined;
}

function compactJSON(raw: string): string {
  let compact = "";
  let inString = false;
  let escaped = false;
  for (const character of raw) {
    if (inString) {
      compact += character;
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      compact += character;
    } else if (!/[\t\n\r ]/.test(character)) {
      compact += character;
    }
  }
  return compact;
}
function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}
function validateProviderText(
  value: unknown,
  minimumBytes: number,
  maximumBytes: number,
): value is string {
  return (
    typeof value === "string" &&
    isWellFormedUnicode(value) &&
    Buffer.byteLength(value, "utf8") >= minimumBytes &&
    Buffer.byteLength(value, "utf8") <= maximumBytes &&
    !/[\0\r\n]/.test(value)
  );
}
function validateProviderVersion(value: unknown): value is string {
  return (
    validateProviderText(value, 1, 128) &&
    value.trim() === value &&
    !/[\t ]/.test(value)
  );
}
function isNativeID(value: unknown): value is NativeID {
  return (
    typeof value === "string" &&
    isWellFormedUnicode(value) &&
    value.length > 0 &&
    Buffer.byteLength(value) <= 1024 &&
    !/[\0\r\n]/.test(value)
  );
}
function isCanonicalID(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
}
function isWireToken(value: unknown): value is string {
  return typeof value === "string" && /^[\x21-\x7e]{1,256}$/.test(value);
}
function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value >= minimum && value <= maximum;
}
function isUTCTimestamp(value: unknown): value is UTCDateTime {
  return parseRFC3339Nanoseconds(value) !== undefined;
}

function parseRFC3339Nanoseconds(value: unknown): bigint | undefined {
  if (typeof value !== "string") return undefined;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (match === null) return undefined;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const wholeSecond = `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
  const milliseconds = Date.parse(wholeSecond);
  if (!Number.isFinite(milliseconds)) return undefined;
  const date = new Date(milliseconds);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() + 1 !== month ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second
  ) {
    return undefined;
  }
  const fraction = BigInt((match[7] ?? "").padEnd(9, "0") || "0");
  return BigInt(milliseconds / 1000) * 1_000_000_000n + fraction;
}
