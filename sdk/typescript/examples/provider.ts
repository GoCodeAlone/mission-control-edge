import { platform as operatingSystem, arch as architecture } from "node:process";

import {
  CAPABILITY_CATALOG,
  NOTIFICATION_TERMINAL_CHUNK,
  PROTOCOL_VERSION,
  ProviderServer,
  providerSubscription,
  type CapabilityDescriptor,
  type ProviderManifest,
  type RuntimeSession,
  type StateReport,
  type TerminalSubscribeRequest,
} from "../src/index.js";

const PROVIDER_ID = "typescript-reference";
const NATIVE_SESSION_ID = "typescript-native-session";

const manifest: ProviderManifest = {
  protocol_version: PROTOCOL_VERSION,
  id: PROVIDER_ID,
  roles: ["session-runtime"],
  name: "TypeScript Reference Provider",
  version: "0.1.0",
  executable: "mission-control-provider-typescript",
  platforms: [{ os: normalizedOperatingSystem(), architecture: normalizedArchitecture() }],
  capabilities: [
    capability("provider.initialize"),
    capability("provider.capabilities"),
    capability("runtime.create_session"),
    capability("runtime.stop_session"),
    capability("terminal.subscribe"),
  ],
  interaction_modes: ["json-rpc"],
  permissions: ["local-process"],
  configuration_schema: "schema.json",
  extensions: {},
};

const server = new ProviderServer({
  manifest,
  authenticationModes: ["none"],
  replaySupported: true,
  nativeRuntimeVersion: "0.1.0",
  limits: {
    maximumMessageBytes: 64 << 10,
    maximumChunkBytes: 64 << 10,
    maximumOutboundQueue: 16,
    maximumInFlightRequests: 16,
    maximumIdempotencyEntries: 64,
  },
  handlers: {
    "runtime.create_session": () => ({ session: runtimeSession(NATIVE_SESSION_ID) }),
    "runtime.stop_session": () => ({ session: runtimeSession(NATIVE_SESSION_ID, "stopped") }),
    "terminal.subscribe": (value) => {
      const request = value as unknown as TerminalSubscribeRequest;
      const data = "typescript-ready".slice(0, request.window_bytes);
      return providerSubscription(
        { subscription_id: "typescript-terminal-subscription", cursors: [] },
        [
          {
            method: NOTIFICATION_TERMINAL_CHUNK,
            params: {
              native_session_id: request.native_session_id,
              stream_id: request.stream_id,
              encoding: "utf-8",
              sequence: 1,
              offset: request.after_offset,
              observed_at: new Date().toISOString(),
              data,
              replayed: true,
              truncated: false,
              redactions: [],
              credit_remaining: request.window_bytes - Buffer.byteLength(data, "utf8"),
            },
          },
        ],
      );
    },
  },
});

try {
  await server.serve();
} catch {
  process.exitCode = 1;
}

function capability(name: CapabilityDescriptor["name"]): CapabilityDescriptor {
  const descriptor = CAPABILITY_CATALOG.find((candidate) => candidate.name === name);
  if (descriptor === undefined) throw new Error("static capability is unknown");
  return { ...descriptor };
}

function runtimeSession(
  nativeSessionId: string,
  lifecycle: "running" | "stopped" = "running",
): RuntimeSession {
  const observedAt = new Date().toISOString();
  return {
    provider_id: PROVIDER_ID,
    native_session_id: nativeSessionId,
    lifecycle: state("lifecycle", lifecycle, observedAt),
    health: state("health", "healthy", observedAt),
    extensions: {},
  };
}

function state(
  axis: "lifecycle" | "health",
  value: "running" | "stopped" | "healthy",
  observedAt: string,
): StateReport {
  return {
    axis,
    state: value,
    source: "typescript-reference",
    observed_at: observedAt,
    sequence: 1,
    confidence: 1,
    authority: "authoritative",
  };
}

function normalizedOperatingSystem(): string {
  return operatingSystem === "win32" ? "windows" : operatingSystem;
}

function normalizedArchitecture(): string {
  return architecture === "x64" ? "amd64" : architecture;
}
