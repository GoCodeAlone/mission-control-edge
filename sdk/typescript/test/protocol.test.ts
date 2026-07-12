import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ERROR_MESSAGES,
  MAX_MESSAGE_BYTES,
  MAX_TERMINAL_CHUNK_BYTES,
  PROTOCOL_VERSION,
  ProtocolError,
  assertProtocolDocument,
  isProtocolError,
  notSupported,
  parseProtocolJSON,
  protocolError,
  validateCapabilityRequest,
  validateCapabilityResult,
  validateNotification,
  validateProviderNegotiation,
  validateProtocolDocument,
  validateWireCapabilityRequest,
  type ProtocolDocumentKind,
  type Command,
  type ProviderInitializeRequest,
  type ProviderInitializeResult,
} from "../src/index.js";

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));

function fixture(path: string): unknown {
  return parseProtocolJSON(readFileSync(join(repositoryRoot, path), "utf8"));
}

function fixtureKind(name: string): ProtocolDocumentKind | undefined {
  if (name.startsWith("manifest-")) return "provider_manifest";
  if (name.startsWith("session-")) return "session";
  if (name.startsWith("command-")) return "command";
  if (name.startsWith("event-") || name.includes("event")) return "event";
  if (name.startsWith("artifact-")) return "artifact";
  if (name.startsWith("approval-decision-")) return "approval_decision";
  if (name.startsWith("context-receipt")) return "context_receipt";
  return undefined;
}

describe("protocol constants", () => {
  it("exports the frozen protocol range and hard limits", () => {
    expect(PROTOCOL_VERSION).toBe("mission-control.provider.v1alpha1");
    expect(MAX_MESSAGE_BYTES).toBe(4 << 20);
    expect(MAX_TERMINAL_CHUNK_BYTES).toBe(256 << 10);
  });
});

describe("JSON and shared fixture validation", () => {
  it("rejects duplicate object keys before JSON.parse can erase them", () => {
    expect(() => parseProtocolJSON('{"event_id":"first","event_id":"second"}')).toThrow(
      ProtocolError,
    );
  });

  it("rejects integers JavaScript cannot represent exactly", () => {
    expect(() => parseProtocolJSON('{"sequence":9007199254740993}')).toThrow(ProtocolError);
  });

  it("retains __proto__ as inert protocol data", () => {
    const value = parseProtocolJSON('{"__proto__":{"value":true}}');
    expect(Object.hasOwn(value as object, "__proto__")).toBe(true);
    expect((value as { __proto__: unknown }).__proto__).toEqual({ value: true });
  });

  it("accepts every applicable Go valid fixture", () => {
    const directory = join(repositoryRoot, "protocol/testdata/valid");
    for (const entry of readdirSync(directory).sort()) {
      const kind = fixtureKind(entry);
      if (kind === undefined) continue;
      const value = fixture(`protocol/testdata/valid/${entry}`);
      expect(validateProtocolDocument(kind, value), entry).toBe(true);
      expect(assertProtocolDocument(kind, value), entry).toBe(value);
    }
  });

  it("rejects every applicable Go invalid fixture", () => {
    const directory = join(repositoryRoot, "protocol/testdata/invalid");
    for (const entry of readdirSync(directory).sort()) {
      const kind = fixtureKind(entry);
      if (kind === undefined) continue;
      const raw = readFileSync(join(directory, entry), "utf8");
      try {
        const value = parseProtocolJSON(raw);
        expect(validateProtocolDocument(kind, value), entry).toBe(false);
        expect(() => assertProtocolDocument(kind, value), entry).toThrow(ProtocolError);
      } catch (error) {
        expect(isProtocolError(error), entry).toBe(true);
      }
    }
  });

  it("does not infer a document kind from a filename", () => {
    expect(fixtureKind(basename("signing-vectors.json"))).toBeUndefined();
  });

  it("rejects duplicate capability names and mismatched artifact event identity", () => {
    const manifest = fixture("protocol/testdata/valid/provider-manifest-runtime.json") as {
      capabilities: Array<Record<string, unknown>>;
    };
    expect(validateProtocolDocument("provider_manifest", {
      ...manifest,
      capabilities: [...manifest.capabilities, { ...manifest.capabilities[0] }],
    })).toBe(false);

    const event = fixture("protocol/testdata/valid/provider-artifact-event.json") as {
      payload: Record<string, unknown>;
    } & Record<string, unknown>;
    expect(validateProtocolDocument("event", {
      ...event,
      payload: { ...event.payload, provider_id: "different-provider" },
    })).toBe(false);
  });
});

describe("capability and negotiation validation", () => {
  const initializeRequest: ProviderInitializeRequest = {
    supported_protocol_versions: [PROTOCOL_VERSION],
    gateway_version: "0.1.0",
    platform: { os: "darwin", architecture: "arm64" },
    required_capabilities: ["provider.initialize", "runtime.create_session"],
    maximum_message_bytes: MAX_MESSAGE_BYTES,
    maximum_chunk_bytes: MAX_TERMINAL_CHUNK_BYTES,
    replay_supported: true,
    authentication_modes: ["local"],
    experimental_features: [],
  };

  const initializeResult: ProviderInitializeResult = {
    protocol_version: PROTOCOL_VERSION,
    manifest: fixture("protocol/testdata/valid/provider-manifest-runtime.json") as ProviderInitializeResult["manifest"],
    native_runtime_version: "1.0.0",
    maximum_message_bytes: MAX_MESSAGE_BYTES,
    maximum_chunk_bytes: MAX_TERMINAL_CHUNK_BYTES,
    replay_supported: true,
    authentication_mode: "local",
    experimental_features: [],
  };

  it("validates initialize and capabilities request/result schemas", () => {
    expect(validateCapabilityRequest("provider.initialize", initializeRequest)).toBe(true);
    expect(validateCapabilityResult("provider.initialize", initializeResult)).toBe(true);
    expect(validateCapabilityRequest("provider.capabilities", {})).toBe(true);
    expect(
      validateCapabilityResult("provider.capabilities", {
        provider_id: initializeResult.manifest.id,
        roles: initializeResult.manifest.roles,
        capabilities: initializeResult.manifest.capabilities,
      }),
    ).toBe(true);
  });

  it("checks selections against the initialization offer", () => {
    expect(validateProviderNegotiation(initializeRequest, initializeResult)).toBe(true);
    expect(
      validateProviderNegotiation(initializeRequest, {
        ...initializeResult,
        authentication_mode: "unoffered",
      }),
    ).toBe(false);
  });

  it("rejects initialization chunk limits above the message limit", () => {
    expect(validateCapabilityRequest("provider.initialize", {
      ...initializeRequest,
      maximum_message_bytes: 1024,
      maximum_chunk_bytes: 2048,
    })).toBe(false);
    expect(validateCapabilityResult("provider.initialize", {
      ...initializeResult,
      maximum_message_bytes: 1024,
      maximum_chunk_bytes: 2048,
    })).toBe(false);
  });

  it("requires state expiry to follow its observation", () => {
    const health = {
      axis: "health",
      state: "healthy",
      source: "provider",
      observed_at: "2030-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      sequence: 1,
      confidence: 1,
      authority: "authoritative",
    };
    expect(validateCapabilityResult("provider.health", {
      provider_id: "provider-one",
      health,
    })).toBe(false);

    const session = fixture("protocol/testdata/valid/session-terminal.json") as Record<string, unknown>;
    expect(validateProtocolDocument("session", {
      ...session,
      activity: {
        ...(session.activity as Record<string, unknown>),
        expires_at: (session.activity as Record<string, unknown>).observed_at,
      },
    })).toBe(false);

    const event = fixture("protocol/testdata/valid/provider-event.json") as Record<string, unknown>;
    expect(validateProtocolDocument("event", {
      ...event,
      payload: {
        ...(event.payload as Record<string, unknown>),
        expires_at: (event.payload as Record<string, unknown>).observed_at,
      },
    })).toBe(false);
  });

  it("validates lifecycle commands and subscription replay values", () => {
    const command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "command_123456789",
      session_id: "session_123456789",
      capability: "runtime.stop_session",
      idempotency_key: "idempotency_1234",
      cancellation_token: "cancellation_1234",
      deadline: "2030-01-01T00:00:00Z",
      delivery_class: "provider_idempotent",
      payload: { native_session_id: "native-session" },
    };
    expect(validateCapabilityRequest("runtime.stop_session", command)).toBe(true);
    expect(validateCapabilityRequest("terminal.subscribe", {
      native_session_id: "native-session",
      stream_id: "stdout",
      after_offset: 0,
      window_bytes: 4096,
    })).toBe(true);
    expect(validateCapabilityResult("terminal.read", {
      native_session_id: "native-session",
      stream_id: "stdout",
      encoding: "utf-8",
      sequence: 1,
      offset: 0,
      observed_at: "2030-01-01T00:00:00Z",
      data: "hello",
      replayed: true,
      truncated: false,
      redactions: [],
      credit_remaining: 4091,
    })).toBe(true);
  });

  it("rejects terminal redactions outside the byte range or out of order", () => {
    const chunk = {
      native_session_id: "native-session",
      stream_id: "stdout",
      encoding: "utf-8",
      sequence: 1,
      offset: 10,
      observed_at: "2030-01-01T00:00:00Z",
      data: "hello",
      replayed: true,
      truncated: false,
      redactions: [{ start: 10, end: 12, reason: "secret" }],
      credit_remaining: 4091,
    };
    expect(validateCapabilityResult("terminal.read", chunk)).toBe(true);
    expect(validateCapabilityResult("terminal.read", {
      ...chunk,
      redactions: [{ start: 9, end: 11, reason: "secret" }],
    })).toBe(false);
    expect(validateCapabilityResult("terminal.read", {
      ...chunk,
      redactions: [
        { start: 11, end: 14, reason: "secret" },
        { start: 13, end: 15, reason: "secret" },
      ],
    })).toBe(false);
    expect(validateCapabilityResult("terminal.read", {
      ...chunk,
      redactions: [{ start: 10, end: 12, reason: "Secret" }],
    })).toBe(false);
    expect(validateCapabilityResult("terminal.read", {
      ...chunk,
      data: "\ud800",
      redactions: [],
    })).toBe(false);
  });

  it("enforces terminal input decoded-byte and Unicode limits in the public validator", () => {
    const terminalCommand = (data: string): Command => ({
      protocol_version: PROTOCOL_VERSION,
      command_id: "terminal-input-command-123",
      session_id: "canonical-session-123",
      capability: "terminal.send_input",
      idempotency_key: "terminal-input-idempotency-123",
      cancellation_token: "terminal-input-cancellation-123",
      deadline: "2030-01-01T00:00:00Z",
      delivery_class: "at_most_once",
      payload: {
        native_session_id: "native-session",
        stream_id: "stdin",
        encoding: "utf-8",
        data,
      },
    });
    expect(validateCapabilityRequest("terminal.send_input", terminalCommand("hello"))).toBe(true);
    expect(validateCapabilityRequest(
      "terminal.send_input",
      terminalCommand("é".repeat(MAX_TERMINAL_CHUNK_BYTES / 2 + 1)),
    )).toBe(false);
    expect(validateCapabilityRequest("terminal.send_input", terminalCommand("\ud800"))).toBe(false);
  });

  it("rejects duplicate provider identities even when entries differ", () => {
    const lifecycle = {
      axis: "lifecycle",
      state: "running",
      source: "runtime-provider",
      observed_at: "2030-01-01T00:00:00Z",
      sequence: 1,
      confidence: 1,
      authority: "authoritative",
    };
    const health = {
      axis: "health",
      state: "healthy",
      source: "runtime-provider",
      observed_at: "2030-01-01T00:00:00Z",
      sequence: 1,
      confidence: 1,
      authority: "authoritative",
    };
    const session = {
      provider_id: "direct-pty",
      native_session_id: "native-session",
      lifecycle,
      health,
      extensions: {},
    };
    expect(validateCapabilityResult("runtime.list_sessions", {
      sessions: [session, { ...session, lifecycle: { ...lifecycle, status: "still running" } }],
    })).toBe(false);

    const workspace = {
      provider_id: "direct-pty",
      native_workspace_id: "native-workspace",
      name: "first",
      extensions: {},
    };
    expect(validateCapabilityResult("workspace.list", {
      workspaces: [workspace, { ...workspace, name: "second" }],
    })).toBe(false);

    const artifact = {
      protocol_version: PROTOCOL_VERSION,
      report_id: "report-one",
      provider_id: "generic-cli",
      role: "agent-harness",
      stream_id: "artifacts",
      native_session_id: "native-session",
      native_artifact_id: "native-artifact",
      version: "1",
      locality: "local-only",
      locator: "local-resource://gateway-one/artifact-one",
      mime_type: "text/plain",
      size: 1,
      digest: `sha256:${"a".repeat(64)}`,
      source_locators: [],
      extensions: {},
    };
    expect(validateCapabilityResult("artifact.list", {
      artifacts: [artifact, {
        ...artifact,
        report_id: "report-two",
        version: "2",
        locator: "local-resource://gateway-one/artifact-two",
      }],
    })).toBe(false);

    expect(validateCapabilityResult("provider.capabilities", {
      provider_id: "direct-pty",
      roles: ["session-runtime"],
      capabilities: [
        { name: "provider.health", role: "provider" },
        { name: "provider.health", role: "provider", required: true },
      ],
    })).toBe(false);

    expect(validateCapabilityResult("provider.initialize", {
      ...initializeResult,
      manifest: {
        ...initializeResult.manifest,
        capabilities: [
          ...initializeResult.manifest.capabilities,
          { ...initializeResult.manifest.capabilities[0], required: true },
        ],
      },
    })).toBe(false);
  });

  it("rejects duplicate event cursor streams even when offsets differ", () => {
    expect(validateCapabilityRequest("events.subscribe", {
      cursors: [
        { role: "session-runtime", stream_id: "sessions", after_sequence: 1 },
        { role: "session-runtime", stream_id: "sessions", after_sequence: 2 },
      ],
      event_types: [],
      window_size: 1,
    })).toBe(false);
  });

  it("enforces keyed provider results and nested identity relationships", () => {
    const activity = {
      axis: "activity",
      state: "working",
      source: "harness-provider",
      observed_at: "2030-01-01T00:00:00Z",
      sequence: 1,
      confidence: 1,
      authority: "authoritative",
    };
    const state = {
      provider_id: "harness-provider",
      native_session_id: "native-harness-session",
      activity,
      usage: { input_tokens: 1, output_tokens: 2, cost_microunits: 3 },
    };
    const harnessSession = {
      provider_id: "harness-provider",
      native_session_id: "native-harness-session",
      state,
    };
    expect(validateCapabilityResult("harness.inspect", harnessSession)).toBe(true);
    expect(validateCapabilityResult("harness.inspect", {
      ...harnessSession,
      state: { ...state, native_session_id: "different-session" },
    })).toBe(false);
    expect(validateCapabilityResult("harness.list", {
      sessions: [harnessSession, { ...harnessSession, native_resume_reference: "different-resume" }],
    })).toBe(false);

    const tool = { name: "search", description: "Search", input_schema: { type: "object" } };
    expect(validateCapabilityResult("agent.get_tools", {
      tools: [tool, { ...tool, description: "Different description" }],
    })).toBe(false);

    const approval = {
      native_approval_id: "native-approval",
      native_session_id: "native-harness-session",
      type: "command_execution",
      summary: "Run the command",
      risk: "high",
      requested_scopes: ["command.execute"],
      request_digest: `sha256:${"a".repeat(64)}`,
      revision: 1,
      expires_at: "2030-01-01T00:00:00Z",
    };
    for (const capability of ["approval.list", "agent.get_pending_approvals"] as const) {
      expect(validateCapabilityResult(capability, {
        approvals: [approval, { ...approval, summary: "Different summary" }],
      })).toBe(false);
    }

    const pane = {
      native_workspace_id: "native-workspace",
      native_pane_id: "native-pane",
      rows: 24,
      columns: 80,
    };
    expect(validateCapabilityResult("pane.list", {
      panes: [pane, { ...pane, rows: 25 }],
    })).toBe(false);
    const topology = {
      native_workspace_id: "native-workspace",
      revision: 1,
      observed_at: "2030-01-01T00:00:00Z",
      panes: [pane],
    };
    expect(validateCapabilityResult("topology.get", topology)).toBe(true);
    expect(validateCapabilityResult("topology.get", {
      ...topology,
      panes: [pane, { ...pane, columns: 81 }],
    })).toBe(false);
    expect(validateCapabilityResult("topology.get", {
      ...topology,
      panes: [{ ...pane, native_workspace_id: "different-workspace" }],
    })).toBe(false);
  });

  it("requires canonical metadata and supported roles for known capabilities", () => {
    const manifest = initializeResult.manifest;
    const known = manifest.capabilities.find(({ name }) => name === "runtime.create_session");
    expect(known).toBeDefined();
    expect(validateCapabilityResult("provider.initialize", {
      ...initializeResult,
      manifest: {
        ...manifest,
        capabilities: manifest.capabilities.map((capability) =>
          capability.name === known?.name ? { ...capability, required: true } : capability,
        ),
      },
    })).toBe(true);
    expect(validateCapabilityResult("provider.initialize", {
      ...initializeResult,
      manifest: {
        ...manifest,
        capabilities: manifest.capabilities.map((capability) =>
          capability.name === known?.name ? { ...capability, delivery_class: "at_most_once" } : capability,
        ),
      },
    })).toBe(false);
    expect(validateCapabilityResult("provider.capabilities", {
      provider_id: manifest.id,
      roles: ["execution-environment"],
      capabilities: manifest.capabilities,
    })).toBe(false);
  });

  it("rejects unknown core-like capabilities", () => {
    expect(validateCapabilityRequest("runtime.future", {})).toBe(false);
  });

  it("accepts non-null extension results while rejecting reserved authority", () => {
    expect(validateCapabilityResult("example.test/value", ["ok", 1])).toBe(true);
    expect(validateCapabilityResult("example.test/value", "ok")).toBe(true);
    expect(validateCapabilityResult("example.test/value", null)).toBe(false);
    expect(validateCapabilityResult("example.test/value", { tenant_id: "forged" })).toBe(false);
  });

  it("checks compact payload digests at the SDK boundary", () => {
    const configuration = { image: "sandbox", cpu: 2 };
    const configurationDigest = `sha256:${createHash("sha256").update(JSON.stringify(configuration)).digest("hex")}`;
    const command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "command_123456789",
      capability: "environment.provision",
      idempotency_key: "idempotency_1234",
      cancellation_token: "cancellation_1234",
      deadline: "2030-01-01T00:00:00Z",
      delivery_class: "state_reconciled",
      payload: { configuration, configuration_digest: configurationDigest },
    };
    expect(validateCapabilityRequest("environment.provision", command)).toBe(true);
    expect(validateCapabilityRequest("environment.provision", {
      ...command,
      payload: { ...command.payload, configuration_digest: `sha256:${"0".repeat(64)}` },
    })).toBe(false);
  });

  it("hashes the exact compact JSON spelling received from another SDK", () => {
    const configuration = '{"10":1.0,"2":2}';
    const configurationDigest = `sha256:${createHash("sha256").update(configuration).digest("hex")}`;
    const command = parseProtocolJSON(`{
      "protocol_version":"${PROTOCOL_VERSION}",
      "command_id":"raw-digest-command-123",
      "capability":"environment.provision",
      "idempotency_key":"raw-digest-idempotency-123",
      "cancellation_token":"raw-digest-cancellation-123",
      "deadline":"2030-01-01T00:00:00Z",
      "delivery_class":"state_reconciled",
      "payload":{
        "configuration":${configuration},
        "configuration_digest":"${configurationDigest}"
      }
    }`);
    expect(validateWireCapabilityRequest("environment.provision", command)).toBe(true);
    expect(validateCapabilityRequest("environment.provision", command)).toBe(false);
  });

  it("rejects provider authority smuggled through negotiated and artifact extensions", () => {
    expect(validateCapabilityResult("provider.initialize", {
      ...initializeResult,
      manifest: {
        ...initializeResult.manifest,
        extensions: { "example.test/metadata": { tenant_id: "tenant_123" } },
      },
    })).toBe(false);

    const event = fixture("protocol/testdata/valid/provider-artifact-event.json") as { payload: Record<string, unknown> };
    expect(validateCapabilityResult("artifact.list", { artifacts: [event.payload] })).toBe(true);
    expect(validateCapabilityResult("artifact.list", {
      artifacts: [{
        ...event.payload,
        extensions: { "example.test/metadata": { review_state: "approved" } },
      }],
    })).toBe(false);
  });

  it("enforces the aggregate provider extension byte limit", () => {
    const largeExtensions = { "example.test/large": "x".repeat((256 << 10) + 1) };
    expect(validateCapabilityResult("provider.initialize", {
      ...initializeResult,
      manifest: {
        ...initializeResult.manifest,
        extensions: largeExtensions,
      },
    })).toBe(false);
    expect(validateCapabilityResult("runtime.list_sessions", {
      sessions: [{
        provider_id: "runtime-provider",
        native_session_id: "native-session",
        lifecycle: {
          axis: "lifecycle",
          state: "running",
          source: "runtime-provider",
          observed_at: "2030-01-01T00:00:00Z",
          sequence: 1,
          confidence: 1,
          authority: "authoritative",
        },
        health: {
          axis: "health",
          state: "healthy",
          source: "runtime-provider",
          observed_at: "2030-01-01T00:00:00Z",
          sequence: 1,
          confidence: 1,
          authority: "authoritative",
        },
        extensions: largeExtensions,
      }],
    })).toBe(false);
  });

  it("applies Go UTF-8 byte and control-character limits to typed provider fields", () => {
    const lifecycle = {
      axis: "lifecycle",
      state: "running",
      source: "runtime-provider",
      observed_at: "2030-01-01T00:00:00Z",
      sequence: 1,
      confidence: 1,
      authority: "authoritative",
    };
    const health = {
      axis: "health",
      state: "healthy",
      source: "runtime-provider",
      observed_at: "2030-01-01T00:00:00Z",
      sequence: 1,
      confidence: 1,
      authority: "authoritative",
    };
    expect(validateCapabilityResult("runtime.list_sessions", {
      sessions: [{
        provider_id: "runtime-provider",
        native_session_id: "é".repeat(600),
        lifecycle,
        health,
        extensions: {},
      }],
    })).toBe(false);

    expect(validateCapabilityResult("workspace.list", {
      workspaces: [{
        provider_id: "runtime-provider",
        native_workspace_id: "workspace-one",
        name: "é".repeat(200),
        extensions: {},
      }],
    })).toBe(false);
    expect(validateCapabilityResult("provider.health", {
      provider_id: "provider-one",
      health: { ...health, status: "bad\nstatus" },
    })).toBe(false);
    expect(validateCapabilityResult("agent.get_tools", {
      tools: [{ name: "search", description: "bad\ndescription", input_schema: {} }],
    })).toBe(false);

    const approval = {
      native_approval_id: "approval-one",
      native_session_id: "session-one",
      type: "command_execution",
      summary: "bad\nsummary",
      risk: "high",
      requested_scopes: ["command.execute"],
      request_digest: `sha256:${"a".repeat(64)}`,
      revision: 1,
      expires_at: "2030-01-01T00:00:00Z",
    };
    expect(validateCapabilityResult("approval.list", { approvals: [approval] })).toBe(false);

    const keyCommand: Command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "terminal-keys-command-123",
      capability: "terminal.send_keys",
      idempotency_key: "terminal-keys-idempotency-123",
      cancellation_token: "terminal-keys-cancellation-123",
      deadline: "2030-01-01T00:00:00Z",
      delivery_class: "at_most_once",
      payload: {
        native_session_id: "native-session",
        stream_id: "stdin",
        keys: ["bad\nkey"],
      },
    };
    expect(validateCapabilityRequest("terminal.send_keys", keyCommand)).toBe(false);
    expect(validateProtocolDocument("command", {
      ...keyCommand,
      idempotency_key: "é".repeat(129),
    })).toBe(false);

    const configuration = {};
    const configurationDigest = `sha256:${createHash("sha256").update(JSON.stringify(configuration)).digest("hex")}`;
    expect(validateCapabilityRequest("runtime.create_session", {
      protocol_version: PROTOCOL_VERSION,
      command_id: "runtime-create-command-123",
      session_id: "canonical-session-123",
      capability: "runtime.create_session",
      idempotency_key: "runtime-create-idempotency-123",
      cancellation_token: "runtime-create-cancellation-123",
      deadline: "2030-01-01T00:00:00Z",
      delivery_class: "state_reconciled",
      payload: {
        native_environment_id: "native-environment",
        name: "é".repeat(65),
        configuration,
        configuration_digest: configurationDigest,
      },
    })).toBe(false);
  });

  it("strictly validates every canonical notification payload", () => {
    expect(validateNotification("$mc/event", fixture("protocol/testdata/valid/provider-event.json"))).toBe(true);
    expect(validateNotification("$mc/heartbeat", { observed_at: "2030-01-01T00:00:00Z" })).toBe(true);
    expect(validateNotification("$mc/heartbeat", { observed_at: "2030-01-01T00:00:00.123456789Z" })).toBe(true);
    expect(validateNotification("$mc/terminal.credit", {
      native_session_id: "native-session",
      stream_id: "stdout",
      bytes: 1024,
      through_offset: 12,
    })).toBe(true);
    expect(validateNotification("$mc/heartbeat", { observed_at: "not-a-time" })).toBe(false);
    expect(validateNotification("$mc/heartbeat", { observed_at: "2030-01-01Z" })).toBe(false);
    expect(validateNotification("$mc/heartbeat", { observed_at: "01 Jan 2030 Z" })).toBe(false);
    expect(validateNotification("$mc/future", {})).toBe(false);
  });
});

describe("canonical protocol errors", () => {
  it("constructs content-free failures", () => {
    const error = protocolError("cancelled");
    expect(error.code).toBe("cancelled");
    expect(error.message).toBe(ERROR_MESSAGES.cancelled);
    expect(isProtocolError(error, "cancelled")).toBe(true);
  });

  it("requires capability details only for not_supported", () => {
    const error = notSupported("runtime.migrate", ["runtime.list_sessions"]);
    expect(error.code).toBe("not_supported");
    expect(error.requiredCapability).toBe("runtime.migrate");
    expect(error.advertisedCapabilities).toEqual(["runtime.list_sessions"]);
    expect(() => new ProtocolError({ code: "not_supported", message: ERROR_MESSAGES.not_supported })).toThrow(
      ProtocolError,
    );
  });
});

describe("strict NDJSON transport", () => {
  it("reads LF-delimited object frames and writes exactly one LF", async () => {
    const { PassThrough } = await import("node:stream");
    const { FrameWriter, decodeFrame, encodeFrame, readFrames } = await import("../src/stdio.js");

    const input = new PassThrough();
    input.end('{"first":1}\n{"second":2}\n');
    const decoded: unknown[] = [];
    for await (const frame of readFrames(input, 128)) decoded.push(decodeFrame(frame));
    expect(decoded).toEqual([{ first: 1 }, { second: 2 }]);

    const output = new PassThrough();
    const chunks: Buffer[] = [];
    output.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
    const writer = new FrameWriter(output, 128, 2);
    await writer.write(encodeFrame({ jsonrpc: "2.0" }, 128));
    expect(Buffer.concat(chunks).toString("utf8")).toBe('{"jsonrpc":"2.0"}\n');
    writer.close();
  });

  it.each([
    ["CRLF", '{"value":1}\r\n', "invalid_argument"],
    ["blank", "\n", "invalid_argument"],
    ["unterminated", '{"value":1}', "invalid_argument"],
    ["oversized", `${"x".repeat(33)}\n`, "message_too_large"],
  ])("rejects %s frames", async (_name, wire, code) => {
    const { PassThrough } = await import("node:stream");
    const { readFrames } = await import("../src/stdio.js");
    const input = new PassThrough();
    input.end(wire);
    const consume = async (): Promise<void> => {
      for await (const _frame of readFrames(input, 32)) {
        // Exhaust the reader so framing failures surface.
      }
    };
    await expect(consume()).rejects.toMatchObject({ code });
  });

  it("rejects duplicate object keys before dispatch", async () => {
    const { decodeFrame } = await import("../src/stdio.js");
    expect(() => decodeFrame(Buffer.from('{"id":"one","id":"two"}'))).toThrow(ProtocolError);
  });

  it("rejects values JSON.stringify would silently discard or round", async () => {
    const { encodeFrame } = await import("../src/stdio.js");
    expect(() => encodeFrame({ discarded: undefined }, 128)).toThrow(ProtocolError);
    expect(() => encodeFrame({ rounded: Number.MAX_SAFE_INTEGER + 1 }, 128)).toThrow(ProtocolError);
    const disguised = { value: 1 };
    Object.defineProperty(disguised, "toJSON", { value: () => ({ tenant_id: "forged" }) });
    expect(() => encodeFrame(disguised, 128)).toThrow(ProtocolError);
  });

  it("rejects arrays with serialization hooks, custom prototypes, or symbol data", async () => {
    const { encodeFrame } = await import("../src/stdio.js");
    const inheritedToJSON = [1];
    Object.setPrototypeOf(inheritedToJSON, Object.assign(Object.create(Array.prototype), {
      toJSON: () => ["forged"],
    }));
    const customPrototype = [1];
    Object.setPrototypeOf(customPrototype, Object.create(Array.prototype));
    const symbolData = [1];
    Object.defineProperty(symbolData, Symbol("hidden"), { value: "discarded" });

    for (const value of [inheritedToJSON, customPrototype, symbolData]) {
      expect(() => encodeFrame({ value }, 128)).toThrow(ProtocolError);
    }
  });

  it("converts Writable errors to content-free protocol failures", async () => {
    const { Writable } = await import("node:stream");
    const { FrameWriter, encodeFrame } = await import("../src/stdio.js");
    let finish: ((error?: Error | null) => void) | undefined;
    const output = new Writable({
      write(_chunk, _encoding, callback) {
        finish = callback;
      },
    });
    const writer = new FrameWriter(output, 128, 2);
    const writing = writer.write(encodeFrame({ value: 1 }, 128));
    output.emit("error", new Error("native secret"));
    await expect(writing).rejects.toMatchObject({ code: "unavailable" });
    finish?.(new Error("native secret"));
  });

  it("lets a started write report its real flush outcome after cancellation", async () => {
    const { Writable } = await import("node:stream");
    const { FrameWriter, encodeFrame } = await import("../src/stdio.js");
    let finish: ((error?: Error | null) => void) | undefined;
    const output = new Writable({
      write(_chunk, _encoding, callback) {
        finish = callback;
      },
    });
    const writer = new FrameWriter(output, 128, 2);
    const controller = new AbortController();
    const writing = writer.write(encodeFrame({ value: 1 }, 128), controller.signal);
    await new Promise<void>((resolve) => setImmediate(resolve));
    controller.abort();
    let settled = false;
    void writing.finally(() => {
      settled = true;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(settled).toBe(false);
    finish?.();
    await expect(writing).resolves.toBeUndefined();
    writer.close();
  });

  it("lets a started write report its real flush outcome while closing", async () => {
    const { Writable } = await import("node:stream");
    const { FrameWriter, encodeFrame } = await import("../src/stdio.js");
    let finish: ((error?: Error | null) => void) | undefined;
    const output = new Writable({
      write(_chunk, _encoding, callback) {
        finish = callback;
      },
    });
    const writer = new FrameWriter(output, 128, 2);
    const writing = writer.write(encodeFrame({ value: 1 }, 128));
    await new Promise<void>((resolve) => setImmediate(resolve));
    writer.close();
    let settled = false;
    void writing.finally(() => {
      settled = true;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(settled).toBe(false);
    finish?.();
    await expect(writing).resolves.toBeUndefined();
  });
});

describe("provider client", () => {
  it("negotiates initialization and sends one-object query parameters", async () => {
    const harness = await newClientHarness();
    const request = clientInitializeRequest();
    const initialized = harness.client.initialize(request);
    const initializeEnvelope = await harness.nextRequest();
    expect(initializeEnvelope.method).toBe("provider.initialize");
    expect(initializeEnvelope.params).toEqual([request]);
    await harness.respond(initializeEnvelope.id, clientInitializeResult());
    await expect(initialized).resolves.toEqual(clientInitializeResult());

    const capabilities = harness.client.capabilities();
    const capabilitiesEnvelope = await harness.nextRequest();
    expect(capabilitiesEnvelope.method).toBe("provider.capabilities");
    expect(capabilitiesEnvelope.params).toEqual([{}]);
    const expected = {
      provider_id: clientInitializeResult().manifest.id,
      roles: clientInitializeResult().manifest.roles,
      capabilities: clientInitializeResult().manifest.capabilities,
    };
    await harness.respond(capabilitiesEnvelope.id, expected);
    await expect(capabilities).resolves.toEqual(expected);
    await harness.client.close();
  });

  it("maps AbortSignal cancellation to a canonical error and cancel notification", async () => {
    const harness = await initializedClientHarness();
    const controller = new AbortController();
    const health = harness.client.query("provider.health", {}, { signal: controller.signal });
    const request = await harness.nextRequest();
    controller.abort();
    await expect(health).rejects.toMatchObject({ code: "cancelled" });
    const cancellation = await harness.nextRequest();
    expect(cancellation).toMatchObject({
      method: "$mc/cancel",
      params: [{ request_id: request.id }],
    });
    expect(cancellation).not.toHaveProperty("id");
    await harness.client.close();
  });

  it("bounds in-flight requests", async () => {
    const harness = await initializedClientHarness({ maxPendingRequests: 1 });
    const controller = new AbortController();
    const first = harness.client.query("provider.health", {}, { signal: controller.signal });
    await harness.nextRequest();
    await expect(harness.client.query("provider.health", {})).rejects.toMatchObject({
      code: "resource_exhausted",
    });
    controller.abort();
    await expect(first).rejects.toMatchObject({ code: "cancelled" });
    await harness.client.close();
  });

  it("returns a deadline while an already-started write is still flushing", async () => {
    const { PassThrough, Writable } = await import("node:stream");
    const { ProviderClient } = await import("../src/client.js");
    const inbound = new PassThrough();
    let writeCount = 0;
    let held: ((error?: Error | null) => void) | undefined;
    const output = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        writeCount += 1;
        const envelope = JSON.parse(chunk.toString("utf8")) as { id?: string };
        if (writeCount === 1) {
          callback();
          inbound.write(`${JSON.stringify({ jsonrpc: "2.0", id: envelope.id, result: clientInitializeResult() })}\n`);
        } else {
          held = callback;
        }
      },
    });
    const client = new ProviderClient({ readable: inbound, writable: output });
    await client.initialize(clientInitializeRequest());
    const health = client.query("provider.health", {}, { timeoutMs: 10 });
    await expect(Promise.race([
      health,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("deadline hung")), 100)),
    ])).rejects.toMatchObject({ code: "deadline_exceeded" });
    held?.();
    await client.close();
  });

  it("binds terminal.read results to the requested stream and byte limit", async () => {
    const harness = await initializedClientHarness();
    const reading = harness.client.query("terminal.read", {
      native_session_id: "native-session",
      stream_id: "stdout",
      after_offset: 0,
      maximum_bytes: 4,
    });
    const request = await harness.nextRequest();
    await harness.respond(request.id, {
      native_session_id: "different-session",
      stream_id: "stdout",
      encoding: "utf-8",
      sequence: 1,
      offset: 0,
      observed_at: "2030-01-01T00:00:00Z",
      data: "hey",
      replayed: true,
      truncated: false,
      redactions: [],
      credit_remaining: 0,
    });
    await expect(reading).rejects.toMatchObject({ code: "invalid_argument" });
    await harness.client.close();
  });

  it("sends canonical extension commands and accepts primitive extension results", async () => {
    const harness = await initializedClientHarness();
    const command = extensionCommand();
    const mutation = harness.client.mutate(command);
    const request = await harness.nextRequest();
    expect(request).toMatchObject({ method: "example.test/do", params: [command] });
    await harness.respond(request.id, "ok");
    await expect(mutation).resolves.toBe("ok");
    await harness.client.close();
  });

  it("retains ambiguous terminal.attach state for an exact-command retry", async () => {
    const harness = await initializedClientHarness();
    const command = terminalAttachCommand();
    const first = harness.client.mutate(command, { timeoutMs: 10 });
    await harness.nextRequest();
    await expect(first).rejects.toMatchObject({ code: "deadline_exceeded" });
    const cancellation = await harness.nextRequest();
    expect(cancellation.method).toBe("$mc/cancel");

    const retry = harness.client.mutate(command);
    const retriedRequest = await harness.nextRequest();
    expect(retriedRequest.method).toBe("terminal.attach");
    await harness.respond(retriedRequest.id, {
      subscription_id: "attached-terminal-subscription",
      cursors: [],
    });
    await expect(retry).resolves.toMatchObject({ subscription_id: "attached-terminal-subscription" });
    await harness.client.close();
  });

  it("preflights cancellation before reserving terminal flows", async () => {
    const harness = await initializedClientHarness();
    const controller = new AbortController();
    controller.abort();

    await expect(harness.client.query("terminal.subscribe", {
      native_session_id: "query-session",
      stream_id: "stdout",
      after_offset: 0,
      window_bytes: 1024,
    }, { signal: controller.signal })).rejects.toMatchObject({ code: "cancelled" });
    const replacementSubscription = {
      native_session_id: "query-session",
      stream_id: "stdout",
      after_offset: 1,
      window_bytes: 1024,
    };
    const subscribing = harness.client.query("terminal.subscribe", replacementSubscription);
    const subscribeRequest = await harness.nextRequest();
    expect(subscribeRequest.method).toBe("terminal.subscribe");
    expect(subscribeRequest.params).toEqual([replacementSubscription]);
    await harness.respond(subscribeRequest.id, { subscription_id: "query-subscription", cursors: [] });
    await expect(subscribing).resolves.toMatchObject({ subscription_id: "query-subscription" });

    await expect(harness.client.mutate(terminalAttachCommand(), {
      signal: controller.signal,
    })).rejects.toMatchObject({ code: "cancelled" });
    const replacement = {
      ...terminalAttachCommand(),
      command_id: "replacement-attach-command",
      idempotency_key: "replacement-attach-idempotency",
      cancellation_token: "replacement-attach-cancellation",
    };
    const attaching = harness.client.mutate(replacement);
    const attachRequest = await harness.nextRequest();
    expect(attachRequest.method).toBe("terminal.attach");
    expect(attachRequest.params).toEqual([replacement]);
    await harness.respond(attachRequest.id, { subscription_id: "attach-subscription", cursors: [] });
    await expect(attaching).resolves.toMatchObject({ subscription_id: "attach-subscription" });
    await harness.client.close();
  });

  it("removes external abort listeners when request encoding fails", async () => {
    const { getEventListeners } = await import("node:events");
    const { PassThrough } = await import("node:stream");
    const { ProviderClient } = await import("../src/client.js");
    const controller = new AbortController();
    const client = new ProviderClient(
      { readable: new PassThrough(), writable: new PassThrough() },
      { maximumMessageBytes: 128 },
    );

    await expect(client.initialize(clientInitializeRequest(), {
      signal: controller.signal,
    })).rejects.toMatchObject({ code: "message_too_large" });
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
    await client.close();
  });

  it("accepts the protocol's aggregate-bounded maximum in-flight limit", async () => {
    const { PassThrough } = await import("node:stream");
    const { ProviderClient } = await import("../src/client.js");
    const inbound = new PassThrough();
    const outbound = new PassThrough();
    const client = new ProviderClient(
      { readable: inbound, writable: outbound },
      { maximumMessageBytes: 4096, maxPendingRequests: 65_536 },
    );
    await client.close();
    expect(
      () => new ProviderClient(
        { readable: new PassThrough(), writable: new PassThrough() },
        { maximumMessageBytes: 4096, maxPendingRequests: 65_537 },
      ),
    ).toThrow(ProtocolError);
  });

  it("rejects a noncanonical error response without orphaning its request", async () => {
    const harness = await initializedClientHarness();
    const health = harness.client.query("provider.health", {});
    const request = await harness.nextRequest();
    await harness.send({
      jsonrpc: "2.0",
      id: request.id,
      error: {
        code: -32000,
        message: "native diagnostics must not cross the boundary",
        data: { code: "cancelled", message: ERROR_MESSAGES.cancelled },
      },
    });
    const observed = Promise.race([
      health,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("request was orphaned")), 100)),
    ]);
    await expect(observed).rejects.toMatchObject({ code: "invalid_argument" });
    await harness.client.close();
  });

  it("rejects notification fields outside the canonical payload", async () => {
    const harness = await initializedClientHarness();
    const notification = harness.client.notifications()[Symbol.asyncIterator]().next();
    await harness.send({
      jsonrpc: "2.0",
      method: "$mc/heartbeat",
      params: [{ observed_at: "2030-01-01T00:00:00Z", native_path: "/must-not-escape" }],
    });
    await expect(notification).rejects.toMatchObject({ code: "invalid_argument" });
    await harness.client.close();
  });

  it("accounts terminal subscription replay against its negotiated credit window", async () => {
    const harness = await initializedClientHarness();
    const subscribing = harness.client.query("terminal.subscribe", {
      native_session_id: "native-session",
      stream_id: "stdout",
      after_offset: 0,
      window_bytes: 5,
    });
    const request = await harness.nextRequest();
    await harness.respond(request.id, { subscription_id: "terminal-subscription", cursors: [] });
    await subscribing;

    const notifications = harness.client.notifications()[Symbol.asyncIterator]();
    const first = notifications.next();
    await harness.send({
      jsonrpc: "2.0",
      method: "$mc/terminal.chunk",
      params: [{
        native_session_id: "native-session",
        stream_id: "stdout",
        encoding: "utf-8",
        sequence: 1,
        offset: 0,
        observed_at: "2030-01-01T00:00:00Z",
        data: "hello",
        replayed: true,
        truncated: false,
        redactions: [],
        credit_remaining: 0,
      }],
    });
    await expect(first).resolves.toMatchObject({
      value: { method: "$mc/terminal.chunk", value: { data: "hello", replayed: true } },
      done: false,
    });

    const forged = notifications.next();
    await harness.send({
      jsonrpc: "2.0",
      method: "$mc/terminal.chunk",
      params: [{
        native_session_id: "native-session",
        stream_id: "stdout",
        encoding: "utf-8",
        sequence: 2,
        offset: 5,
        observed_at: "2030-01-01T00:00:01Z",
        data: "x",
        replayed: false,
        truncated: false,
        redactions: [],
        credit_remaining: 0,
      }],
    });
    await expect(forged).rejects.toMatchObject({ code: "invalid_argument" });
    await harness.client.close();
  });
});

type TestEnvelope = {
  jsonrpc: "2.0";
  id?: string;
  method?: string;
  params?: unknown[];
  result?: unknown;
};

type TestClientHarness = {
  client: import("../src/client.js").ProviderClient;
  nextRequest(): Promise<TestEnvelope>;
  respond(id: string | undefined, result: unknown): Promise<void>;
  send(envelope: unknown): Promise<void>;
};

async function newClientHarness(
  limits: Partial<import("../src/client.js").ClientLimits> = {},
): Promise<TestClientHarness> {
  const { PassThrough } = await import("node:stream");
  const { ProviderClient } = await import("../src/client.js");
  const { FrameWriter, decodeFrame, encodeFrame, readFrames } = await import("../src/stdio.js");
  const inbound = new PassThrough();
  const outbound = new PassThrough();
  const requests = readFrames(outbound, MAX_MESSAGE_BYTES)[Symbol.asyncIterator]();
  const responses = new FrameWriter(inbound, MAX_MESSAGE_BYTES, 8);
  const client = new ProviderClient({ readable: inbound, writable: outbound }, limits);
  return {
    client,
    async nextRequest(): Promise<TestEnvelope> {
      const next = await requests.next();
      if (next.done) throw new Error("client request stream ended");
      return decodeFrame(next.value) as TestEnvelope;
    },
    async respond(id: string | undefined, result: unknown): Promise<void> {
      if (id === undefined) throw new Error("response requires request id");
      await responses.write(encodeFrame({ jsonrpc: "2.0", id, result }, MAX_MESSAGE_BYTES));
    },
    async send(envelope: unknown): Promise<void> {
      await responses.write(encodeFrame(envelope, MAX_MESSAGE_BYTES));
    },
  };
}

async function initializedClientHarness(
  limits: Partial<import("../src/client.js").ClientLimits> = {},
): Promise<TestClientHarness> {
  const harness = await newClientHarness(limits);
  const initialized = harness.client.initialize(clientInitializeRequest());
  const request = await harness.nextRequest();
  await harness.respond(request.id, clientInitializeResult());
  await initialized;
  return harness;
}

function clientInitializeRequest(): ProviderInitializeRequest {
  return {
    supported_protocol_versions: [PROTOCOL_VERSION],
    gateway_version: "0.1.0",
    platform: { os: "darwin", architecture: "arm64" },
    required_capabilities: ["provider.capabilities", "provider.health"],
    maximum_message_bytes: MAX_MESSAGE_BYTES,
    maximum_chunk_bytes: MAX_TERMINAL_CHUNK_BYTES,
    replay_supported: true,
    authentication_modes: ["local"],
    experimental_features: [],
  };
}

function clientInitializeResult(): ProviderInitializeResult {
  const source = fixture("protocol/testdata/valid/provider-manifest-runtime.json") as ProviderInitializeResult["manifest"];
  return {
    protocol_version: PROTOCOL_VERSION,
    manifest: {
      ...source,
      capabilities: [
        ...source.capabilities,
        { name: "provider.capabilities", role: "provider" },
        { name: "provider.health", role: "provider" },
        { name: "terminal.read", role: "session-runtime" },
        { name: "terminal.subscribe", role: "session-runtime" },
        { name: "terminal.attach", role: "session-runtime", mutating: true, delivery_class: "state_reconciled" },
        { name: "example.test/do", role: "session-runtime", mutating: true, delivery_class: "provider_idempotent" },
      ],
    },
    native_runtime_version: "1.0.0",
    maximum_message_bytes: MAX_MESSAGE_BYTES,
    maximum_chunk_bytes: MAX_TERMINAL_CHUNK_BYTES,
    replay_supported: true,
    authentication_mode: "local",
    experimental_features: [],
  };
}

function extensionCommand(): Command {
  return {
    protocol_version: PROTOCOL_VERSION,
    command_id: "extension-command-123",
    session_id: "canonical-session-123",
    capability: "example.test/do",
    idempotency_key: "extension-idempotency-123",
    cancellation_token: "extension-cancellation-123",
    deadline: "2030-01-01T00:00:00Z",
    delivery_class: "provider_idempotent",
    payload: ["primitive", 1],
  };
}

function terminalAttachCommand(): Command {
  return {
    protocol_version: PROTOCOL_VERSION,
    command_id: "terminal-attach-command-123",
    session_id: "canonical-session-123",
    capability: "terminal.attach",
    idempotency_key: "terminal-attach-idempotency-123",
    cancellation_token: "terminal-attach-cancellation-123",
    deadline: "2030-01-01T00:00:00Z",
    delivery_class: "state_reconciled",
    payload: {
      native_session_id: "native-session",
      stream_id: "stdout",
      after_offset: 0,
      window_bytes: 1024,
    },
  };
}
