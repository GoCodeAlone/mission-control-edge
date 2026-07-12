import type { CapabilityName, ErrorCode, ProtocolErrorData } from "./types.js";

export const ERROR_MESSAGES = Object.freeze({
  invalid_argument: "protocol value is invalid",
  message_too_large: "protocol message exceeds its limit",
  not_supported: "required capability is not supported",
  sequence_conflict: "event sequence conflicts with prior content",
  replay: "one-use value was already consumed",
  expired: "authorization or evidence has expired",
  unauthenticated: "protocol identity or signature is not authenticated",
  permission_denied: "operation is not authorized",
  conflict: "operation conflicts with current state",
  deadline_exceeded: "operation deadline was exceeded",
  cancelled: "operation was cancelled",
  resource_exhausted: "protocol resource limit was exhausted",
  unavailable: "provider is unavailable",
  outcome_unknown: "operation outcome is unknown",
} satisfies Readonly<Record<ErrorCode, string>>);

const trustedConstruction = Symbol("trusted ProtocolError construction");

/** A canonical, content-free provider protocol failure. */
export class ProtocolError extends Error {
  readonly code: ErrorCode;
  readonly requiredCapability?: CapabilityName;
  readonly advertisedCapabilities?: readonly CapabilityName[];

  constructor(data: ProtocolErrorData, trusted?: typeof trustedConstruction) {
    if (trusted !== trustedConstruction && !isProtocolErrorData(data)) {
      throw new ProtocolError(canonicalData("invalid_argument"), trustedConstruction);
    }
    super(data.message);
    this.name = "ProtocolError";
    this.code = data.code;
    if (data.required_capability !== undefined) {
      this.requiredCapability = data.required_capability;
    }
    if (data.advertised_capabilities !== undefined) {
      this.advertisedCapabilities = Object.freeze([...data.advertised_capabilities]);
    }
  }

  get data(): ProtocolErrorData {
    const value: ProtocolErrorData = { code: this.code, message: this.message };
    if (this.requiredCapability !== undefined) {
      value.required_capability = this.requiredCapability;
    }
    if (this.advertisedCapabilities !== undefined) {
      value.advertised_capabilities = [...this.advertisedCapabilities];
    }
    return value;
  }

  toJSON(): ProtocolErrorData {
    return this.data;
  }
}

export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === "string" && Object.hasOwn(ERROR_MESSAGES, value);
}

export function isProtocolErrorData(value: unknown): value is ProtocolErrorData {
  if (!isRecord(value) || !hasOnlyKeys(value, ["code", "message", "required_capability", "advertised_capabilities"])) {
    return false;
  }
  if (!isErrorCode(value.code) || value.message !== ERROR_MESSAGES[value.code]) {
    return false;
  }
  const required = value.required_capability;
  const advertised = value.advertised_capabilities;
  if (value.code !== "not_supported") {
    return required === undefined && advertised === undefined;
  }
  return (
    isCapabilityName(required) &&
    Array.isArray(advertised) &&
    advertised.length <= 256 &&
    advertised.every(isCapabilityName) &&
    new Set(advertised).size === advertised.length
  );
}

export function isProtocolError(value: unknown, code?: ErrorCode): value is ProtocolError {
  return value instanceof ProtocolError && (code === undefined || value.code === code);
}

export function protocolError(
  code: ErrorCode,
  requiredCapability?: CapabilityName,
  advertisedCapabilities: readonly CapabilityName[] = [],
): ProtocolError {
  if (code === "not_supported") {
    if (requiredCapability === undefined) {
      return new ProtocolError(canonicalData("invalid_argument"), trustedConstruction);
    }
    return new ProtocolError(
      {
        code,
        message: ERROR_MESSAGES[code],
        required_capability: requiredCapability,
        advertised_capabilities: [...advertisedCapabilities],
      },
    );
  }
  return new ProtocolError(canonicalData(code), trustedConstruction);
}

export function notSupported(
  requiredCapability: CapabilityName,
  advertisedCapabilities: readonly CapabilityName[],
): ProtocolError {
  return protocolError("not_supported", requiredCapability, advertisedCapabilities);
}

export function protocolErrorFrom(value: unknown): ProtocolError {
  if (!isProtocolErrorData(value)) {
    return protocolError("invalid_argument");
  }
  return new ProtocolError(value, trustedConstruction);
}

function canonicalData(code: Exclude<ErrorCode, "not_supported">): ProtocolErrorData {
  return { code, message: ERROR_MESSAGES[code] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.every((key) => allowed.includes(key));
}

function isCapabilityName(value: unknown): value is CapabilityName {
  if (typeof value !== "string") return false;
  if (CORE_CAPABILITY_NAMES.has(value)) return true;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\/[a-z][a-z0-9._-]{0,127}$/.test(
    value,
  );
}

// Kept local to avoid an errors.ts -> runtime catalog dependency cycle.
const CORE_CAPABILITY_NAMES: ReadonlySet<string> = new Set([
  "agent.cancel", "agent.get_native_identity", "agent.get_pending_approvals", "agent.get_state",
  "agent.get_tools", "agent.get_usage", "agent.interrupt", "agent.send_message", "approval.approve",
  "approval.expire", "approval.list", "approval.reject", "artifact.list", "artifact.register",
  "command.get_result", "context.confirm", "context.deliver", "environment.health",
  "environment.inspect", "environment.mount", "environment.provision", "environment.shutdown",
  "events.subscribe", "events.unsubscribe", "harness.inspect", "harness.launch", "harness.list",
  "harness.resume", "harness.stop", "pane.close", "pane.create", "pane.focus", "pane.get",
  "pane.list", "pane.resize", "pane.split", "provider.capabilities", "provider.health",
  "provider.initialize", "provider.shutdown", "runtime.adopt", "runtime.archive", "runtime.attach",
  "runtime.checkpoint", "runtime.clone", "runtime.create_session", "runtime.detach", "runtime.export",
  "runtime.fork", "runtime.get_session", "runtime.import", "runtime.list_sessions", "runtime.migrate",
  "runtime.restore", "runtime.resume", "runtime.snapshot", "runtime.stop_session",
  "runtime.terminate_session", "terminal.attach", "terminal.detach", "terminal.read",
  "terminal.resize", "terminal.send_input", "terminal.send_keys", "terminal.subscribe", "topology.get",
  "topology.subscribe", "workspace.close", "workspace.create", "workspace.get", "workspace.list",
]);
