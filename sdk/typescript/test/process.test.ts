import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PassThrough, Writable } from "node:stream";

import { afterEach, describe, expect, test } from "vitest";

import {
  CAPABILITY_CATALOG,
  MAX_TERMINAL_CHUNK_BYTES,
  PROTOCOL_VERSION,
  ProtocolError,
  ProviderClient,
  ProviderServer,
  providerSubscription,
  type CapabilityDescriptor,
  type Command,
  type ProviderHandler,
  type ProviderManifest,
  type TerminalSubscribeRequest,
} from "../src/index.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(testDirectory, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("TypeScript provider interoperability", () => {
  test("the external Go SDK drives the built Node provider", async () => {
    await runChecked("npm", ["run", "build"], packageRoot);

    const temporaryDirectory = await mkdtemp(resolve(tmpdir(), "mission-control-typescript-"));
    temporaryDirectories.push(temporaryDirectory);
    const goClient = resolve(temporaryDirectory, process.platform === "win32" ? "go-client.exe" : "go-client");
    await runChecked(
      "go",
      ["build", "-o", goClient, "./sdk/typescript/testdata/go-client"],
      repositoryRoot,
      { GOWORK: "off" },
    );

    const providerPath = resolve(packageRoot, "dist/examples/provider.js");
    const provider = spawn(process.execPath, [providerPath], {
      cwd: packageRoot,
      env: { ...process.env, MC_TYPESCRIPT_SECRET_MARKER: "must-not-escape" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const client = spawn(goClient, [], {
      cwd: repositoryRoot,
      env: { ...process.env, GOWORK: "off" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    provider.stdout.pipe(client.stdin);
    client.stdout.pipe(provider.stdin);
    const providerError = collectBounded(provider.stderr);
    const clientError = collectBounded(client.stderr);

    const [clientExit, providerExit] = await withTimeout(
      Promise.all([waitForExit(client), waitForExit(provider)]),
      15_000,
      () => {
        client.kill("SIGKILL");
        provider.kill("SIGKILL");
      },
    );
    expect(clientExit).toBe(0);
    expect(providerExit).toBe(0);
    expect(await clientError).toBe("");
    expect(await providerError).toBe("");
  }, 120_000);
});

describe("TypeScript provider server", () => {
  test("returns structured not_supported for a missing required capability", async () => {
    const server = testServer(["provider.initialize", "provider.capabilities"], {});
    const toProvider = new PassThrough();
    const fromProvider = new PassThrough();
    const serverTask = server.serve({ readable: toProvider, writable: fromProvider });
    const client = new ProviderClient(
      { readable: fromProvider, writable: toProvider },
      { maximumMessageBytes: 64 << 10 },
    );

    await expect(client.initialize({
      supported_protocol_versions: [PROTOCOL_VERSION],
      gateway_version: "0.1.0",
      platform: { os: normalizedOS(), architecture: normalizedArchitecture() },
      required_capabilities: ["runtime.get_session"],
      maximum_message_bytes: 64 << 10,
      maximum_chunk_bytes: 64 << 10,
      replay_supported: true,
      authentication_modes: ["none"],
      experimental_features: [],
    })).rejects.toMatchObject({
      code: "not_supported",
      requiredCapability: "runtime.get_session",
      advertisedCapabilities: expect.arrayContaining(["provider.initialize", "provider.capabilities"]),
    });

    toProvider.end();
    await serverTask;
    await client.close();
    fromProvider.destroy();
  });

  test("streams live terminal output only after credited replay", async () => {
    const live = async function* (): AsyncGenerator<{
      method: "$mc/terminal.chunk";
      params: ReturnType<typeof terminalChunk>;
    }> {
      yield {
        method: "$mc/terminal.chunk",
        params: terminalChunk(2, 3, "d", 2, false),
      };
    };
    const handler: ProviderHandler = (value) => {
      const request = value as unknown as TerminalSubscribeRequest;
      return providerSubscription(
        { subscription_id: "live-terminal-subscription", cursors: [] },
        [{
          method: "$mc/terminal.chunk",
          params: terminalChunk(1, request.after_offset, "abc", 0, true),
        }],
        live(),
      );
    };
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "terminal.subscribe"],
      { "terminal.subscribe": handler },
    );
    const connection = await connectServer(server);
    const subscription = await connection.client.query<{ subscription_id: string }>(
      "terminal.subscribe",
      { native_session_id: "native-session", stream_id: "stdout", after_offset: 0, window_bytes: 3 },
    );
    expect(subscription.subscription_id).toBe("live-terminal-subscription");
    const notifications = connection.client.notifications()[Symbol.asyncIterator]();
    await expect(notifications.next()).resolves.toMatchObject({ value: { value: { data: "abc" } } });

    const pendingLive = notifications.next();
    let liveArrived = false;
    void pendingLive.then(() => { liveArrived = true; });
    await new Promise<void>((resolveValue) => setImmediate(resolveValue));
    expect(liveArrived).toBe(false);
    await connection.client.sendTerminalCredit({
      native_session_id: "native-session",
      stream_id: "stdout",
      bytes: 3,
      through_offset: 3,
    });
    await expect(pendingLive).resolves.toMatchObject({ value: { value: { data: "d", credit_remaining: 2 } } });
    await closeConnection(connection);
  });

  test("supports a clean sequential reconnect", async () => {
    const server = testServer(["provider.initialize", "provider.capabilities"], {});
    const first = await connectServer(server);
    await closeConnection(first);
    const second = await connectServer(server);
    await closeConnection(second);
  });

  test("snapshots extension outcomes for idempotent retries and command lookup", async () => {
    const mutable = { value: "first" };
    let calls = 0;
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "command.get_result", "example.test/do"],
      { "example.test/do": () => { calls += 1; return mutable; } },
    );
    const connection = await connectServer(server);
    const command: Command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "server-extension-command-123",
      session_id: "canonical-session-123",
      capability: "example.test/do",
      idempotency_key: "server-extension-idempotency-123",
      cancellation_token: "server-extension-cancellation-123",
      deadline: new Date(Date.now() + 5000).toISOString(),
      delivery_class: "provider_idempotent",
      payload: ["extension", 1],
    };
    await expect(connection.client.mutate(command)).resolves.toEqual({ value: "first" });
    mutable.value = "second";
    await expect(connection.client.mutate(command)).resolves.toEqual({ value: "first" });
    expect(calls).toBe(1);
    await expect(connection.client.query("command.get_result", {
      command_id: command.command_id,
    })).resolves.toMatchObject({ status: "succeeded", result: { value: "first" } });
    await closeConnection(connection);
  });

  test("does not confuse an extension result field with a subscription", async () => {
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "example.test/do"],
      { "example.test/do": () => ({ result: "ok" }) },
    );
    const connection = await connectServer(server);
    const command: Command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "server-extension-result-command-123",
      capability: "example.test/do",
      idempotency_key: "server-extension-result-idempotency-123",
      cancellation_token: "server-extension-result-cancellation-123",
      deadline: new Date(Date.now() + 5000).toISOString(),
      delivery_class: "provider_idempotent",
      payload: {},
    };
    await expect(connection.client.mutate(command)).resolves.toEqual({ result: "ok" });
    await closeConnection(connection);
  });

  test("admits concurrent live streams without overflowing the bounded writer", async () => {
    let releaseLive = (): void => undefined;
    const liveReady = new Promise<void>((resolveValue) => {
      releaseLive = resolveValue;
    });
    const handler: ProviderHandler = (value) => {
      const request = value as unknown as TerminalSubscribeRequest;
      const nativeSessionId = request.native_session_id;
      const stream = async function* () {
        await liveReady;
        yield {
          method: "$mc/terminal.chunk" as const,
          params: terminalChunkFor(nativeSessionId, 1, 0, "x", 7, false),
        };
      };
      return providerSubscription(
        { subscription_id: `subscription-${nativeSessionId}`, cursors: [] },
        [],
        stream(),
      );
    };
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "terminal.subscribe"],
      { "terminal.subscribe": handler },
      { maximumOutboundQueue: 2 },
    );
    const toProvider = new PassThrough();
    const fromProvider = new PassThrough();
    let holdWrites = false;
    const heldCallbacks: Array<() => void> = [];
    const gated = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        fromProvider.write(chunk);
        if (holdWrites) heldCallbacks.push(callback);
        else callback();
      },
    });
    const serverTask = server.serve({ readable: toProvider, writable: gated });
    const client = new ProviderClient(
      { readable: fromProvider, writable: toProvider },
      { maximumMessageBytes: 64 << 10 },
    );
    await initializeTestClient(client);
    await Promise.all(["one", "two", "three"].map(async (nativeSessionId) => {
      await client.query("terminal.subscribe", {
        native_session_id: nativeSessionId,
        stream_id: "stdout",
        after_offset: 0,
        window_bytes: 8,
      });
    }));

    holdWrites = true;
    const notifications = client.notifications()[Symbol.asyncIterator]();
    const received = [notifications.next(), notifications.next(), notifications.next()];
    releaseLive();
    while (heldCallbacks.length === 0) {
      await new Promise<void>((resolveValue) => setImmediate(resolveValue));
    }
    for (let index = 0; index < 3; index += 1) {
      heldCallbacks.shift()?.();
      await new Promise<void>((resolveValue) => setImmediate(resolveValue));
    }
    const chunks = await withTimeout(Promise.all(received), 1000, () => undefined);
    expect(chunks.map(({ value }) => value.value.native_session_id).sort()).toEqual([
      "one",
      "three",
      "two",
    ]);
    toProvider.end();
    await serverTask;
    await client.close();
    fromProvider.destroy();
  });

  test("rejects advertised capabilities that lack handlers", () => {
    expect(() => testServer(
      ["provider.initialize", "provider.capabilities", "provider.health"],
      {},
    )).toThrow(ProtocolError);
  });

  test("does not commit a mutation whose response flush misses its deadline", async () => {
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "command.get_result", "example.test/do"],
      { "example.test/do": () => ({ value: "late" }) },
    );
    const toProvider = new PassThrough();
    const fromProvider = new PassThrough();
    let writes = 0;
    let responseStarted = false;
    const gated = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        writes += 1;
        if (writes === 1) {
          fromProvider.write(chunk);
          callback();
          return;
        }
        responseStarted = true;
      },
    });
    const serverTask = server.serve({
      readable: toProvider,
      writable: gated,
      close() {
        toProvider.destroy();
        fromProvider.destroy();
      },
    });
    const client = new ProviderClient(
      { readable: fromProvider, writable: toProvider },
      { maximumMessageBytes: 64 << 10 },
    );
    await initializeTestClient(client);
    const command: Command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "deadline-flush-command-123",
      capability: "example.test/do",
      idempotency_key: "deadline-flush-idempotency-123",
      cancellation_token: "deadline-flush-cancellation-123",
      deadline: new Date(Date.now() + 30).toISOString(),
      delivery_class: "provider_idempotent",
      payload: {},
    };
    const mutation = client.mutate(command);
    while (!responseStarted) {
      await new Promise<void>((resolveValue) => setImmediate(resolveValue));
    }
    await expect(withTimeout(mutation, 250, () => {
      gated.destroy();
      toProvider.destroy();
      fromProvider.destroy();
    })).rejects.toMatchObject({ code: "unavailable" });
    await expect(withTimeout(serverTask, 250, () => undefined)).resolves.toBeUndefined();
    await client.close();

    const reconnected = await connectServer(server);
    await expect(reconnected.client.query("command.get_result", {
      command_id: command.command_id,
    })).resolves.toMatchObject({ status: "outcome_unknown" });
    await closeConnection(reconnected);
  });

  test("does not commit after a synchronous handler starves the deadline timer", async () => {
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "command.get_result", "example.test/do"],
      {
        "example.test/do": () => {
          const until = Date.now() + 60;
          while (Date.now() < until) {
            // Deliberately occupy the event loop past the command deadline.
          }
          return { value: "late" };
        },
      },
    );
    const connection = await connectServer(server);
    const command: Command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "starved-deadline-command-123",
      capability: "example.test/do",
      idempotency_key: "starved-deadline-idempotency-123",
      cancellation_token: "starved-deadline-cancellation-123",
      deadline: new Date(Date.now() + 20).toISOString(),
      delivery_class: "provider_idempotent",
      payload: {},
    };
    await expect(connection.client.mutate(command)).rejects.toMatchObject({
      code: "outcome_unknown",
    });
    await expect(connection.client.query("command.get_result", {
      command_id: command.command_id,
    })).resolves.toMatchObject({ status: "outcome_unknown" });
    await closeConnection(connection);
  });

  test("does not start a cached mutation acknowledgement after its deadline", async () => {
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "example.test/do"],
      { "example.test/do": () => ({ value: "known" }) },
      { maximumOutboundQueue: 1 },
    );
    const toProvider = new PassThrough();
    const fromProvider = new PassThrough();
    let holdWrites = false;
    let releaseWrite: (() => void) | undefined;
    const gated = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        if (!holdWrites) {
          fromProvider.write(chunk);
          callback();
          return;
        }
        releaseWrite = () => {
          fromProvider.write(chunk);
          callback();
        };
      },
    });
    const serverTask = server.serve({ readable: toProvider, writable: gated });
    const client = new ProviderClient(
      { readable: fromProvider, writable: toProvider },
      { maximumMessageBytes: 64 << 10 },
    );
    await initializeTestClient(client);
    const deadline = Date.now() + 400;
    const command: Command = {
      protocol_version: PROTOCOL_VERSION,
      command_id: "cached-deadline-command-123",
      capability: "example.test/do",
      idempotency_key: "cached-deadline-idempotency-123",
      cancellation_token: "cached-deadline-cancellation-123",
      deadline: new Date(deadline).toISOString(),
      delivery_class: "provider_idempotent",
      payload: {},
    };
    await expect(client.mutate(command)).resolves.toEqual({ value: "known" });

    holdWrites = true;
    const occupyingResponse = client.capabilities();
    while (releaseWrite === undefined) {
      await new Promise<void>((resolveValue) => setImmediate(resolveValue));
    }
    const retry = client.mutate(command);
    await new Promise<void>((resolveValue) => {
      setTimeout(resolveValue, Math.max(1, deadline - Date.now() + 30));
    });
    holdWrites = false;
    releaseWrite();
    await expect(occupyingResponse).resolves.toMatchObject({
      provider_id: "typescript-test-provider",
    });
    await expect(retry).rejects.toMatchObject({ code: "deadline_exceeded" });
    toProvider.end();
    await serverTask;
    await client.close();
    fromProvider.destroy();
  });

  test("bounds shutdown when a handler ignores cancellation", async () => {
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "provider.health"],
      { "provider.health": () => new Promise(() => undefined) },
      { shutdownTimeoutMs: 20 },
    );
    const connection = await connectServer(server);
    void connection.client.query("provider.health", {}).catch(() => undefined);
    await new Promise<void>((resolveValue) => setImmediate(resolveValue));
    connection.toProvider.end();
    await expect(connection.serverTask).rejects.toMatchObject({ code: "deadline_exceeded" });
    connection.fromProvider.destroy();
    await connection.client.close();
  });

  test("cleans up and permits reconnect when transport close throws", async () => {
    const server = testServer(["provider.initialize", "provider.capabilities"], {});
    const toProvider = new PassThrough();
    const fromProvider = new PassThrough();
    const serverTask = server.serve({
      readable: toProvider,
      writable: fromProvider,
      close() {
        throw new Error("native close detail");
      },
    });
    const client = new ProviderClient(
      { readable: fromProvider, writable: toProvider },
      { maximumMessageBytes: 64 << 10 },
    );
    await initializeTestClient(client);
    toProvider.end();
    await expect(serverTask).resolves.toBeUndefined();
    await client.close();
    fromProvider.destroy();

    const reconnected = await connectServer(server);
    await closeConnection(reconnected);
  });

  test("fails the connection and releases a subscription whose iterator acquisition throws", async () => {
    const brokenStream = {
      [Symbol.asyncIterator](): AsyncIterator<never> {
        throw new Error("native iterator detail");
      },
    };
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "terminal.subscribe"],
      {
        "terminal.subscribe": () => providerSubscription(
          { subscription_id: "broken-iterator-subscription", cursors: [] },
          [],
          brokenStream,
        ),
      },
      { maximumSubscriptions: 1 },
    );
    const connection = await connectServer(server);
    await connection.client.query("terminal.subscribe", {
      native_session_id: "native-session",
      stream_id: "stdout",
      after_offset: 0,
      window_bytes: 8,
    });
    await expect(withTimeout(connection.serverTask, 250, () => undefined)).resolves.toBeUndefined();
    await connection.client.close();
    connection.toProvider.destroy();
    connection.fromProvider.destroy();

    const reconnected = await connectServer(server);
    await closeConnection(reconnected);
  });

  test("ignores a synchronous iterator return failure during shutdown", async () => {
    const stalledStream = {
      [Symbol.asyncIterator](): AsyncIterator<never> {
        return {
          next: () => new Promise<IteratorResult<never>>(() => undefined),
          return: () => {
            throw new Error("native return detail");
          },
        };
      },
    };
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "terminal.subscribe"],
      {
        "terminal.subscribe": () => providerSubscription(
          { subscription_id: "stalled-iterator-subscription", cursors: [] },
          [],
          stalledStream,
        ),
      },
    );
    const connection = await connectServer(server);
    await connection.client.query("terminal.subscribe", {
      native_session_id: "native-session",
      stream_id: "stdout",
      after_offset: 0,
      window_bytes: 8,
    });
    connection.toProvider.end();
    await expect(connection.serverTask).resolves.toBeUndefined();
    await connection.client.close();
    connection.fromProvider.destroy();

    const reconnected = await connectServer(server);
    await closeConnection(reconnected);
  });

  test("ignores a throwing iterator return getter during shutdown", async () => {
    const iterator: AsyncIterator<never> = {
      next: () => new Promise<IteratorResult<never>>(() => undefined),
    };
    Object.defineProperty(iterator, "return", {
      get() {
        throw new Error("native return getter detail");
      },
    });
    const stalledStream = {
      [Symbol.asyncIterator](): AsyncIterator<never> {
        return iterator;
      },
    };
    const server = testServer(
      ["provider.initialize", "provider.capabilities", "terminal.subscribe"],
      {
        "terminal.subscribe": () => providerSubscription(
          { subscription_id: "return-getter-subscription", cursors: [] },
          [],
          stalledStream,
        ),
      },
    );
    const connection = await connectServer(server);
    await connection.client.query("terminal.subscribe", {
      native_session_id: "native-session",
      stream_id: "stdout",
      after_offset: 0,
      window_bytes: 8,
    });
    connection.toProvider.end();
    await expect(connection.serverTask).resolves.toBeUndefined();
    await connection.client.close();
    connection.fromProvider.destroy();
  });
});

async function runChecked(
  command: string,
  args: string[],
  cwd: string,
  extraEnvironment: Record<string, string> = {},
): Promise<void> {
  const child = spawn(command, args, {
    cwd,
    env: { ...process.env, ...extraEnvironment },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = collectBounded(child.stdout);
  const stderr = collectBounded(child.stderr);
  const exit = await waitForExit(child);
  if (exit !== 0) {
    throw new Error(`${command} failed (${exit}): ${(await stderr) || (await stdout)}`);
  }
}

function waitForExit(child: ReturnType<typeof spawn>): Promise<number> {
  return new Promise((resolveExit, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal !== null) {
        reject(new Error(`child terminated by ${signal}`));
        return;
      }
      resolveExit(code ?? 1);
    });
  });
}

function collectBounded(stream: NodeJS.ReadableStream, maximumBytes = 64 * 1024): Promise<string> {
  return new Promise((resolveValue, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    stream.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maximumBytes) {
        reject(new Error("child diagnostics exceeded their bound"));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    stream.once("error", reject);
    stream.once("end", () => resolveValue(Buffer.concat(chunks).toString("utf8")));
  });
}

async function withTimeout<Value>(promise: Promise<Value>, milliseconds: number, onTimeout: () => void): Promise<Value> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      onTimeout();
      reject(new Error("child process interoperability timed out"));
    }, milliseconds);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

type ServerConnection = {
  readonly client: ProviderClient;
  readonly serverTask: Promise<void>;
  readonly toProvider: PassThrough;
  readonly fromProvider: PassThrough;
};

function testServer(
  capabilities: readonly CapabilityDescriptor["name"][],
  handlers: Readonly<Record<string, ProviderHandler>>,
  limits: {
    shutdownTimeoutMs?: number;
    maximumOutboundQueue?: number;
    maximumSubscriptions?: number;
  } = {},
): ProviderServer {
  const manifest: ProviderManifest = {
    protocol_version: PROTOCOL_VERSION,
    id: "typescript-test-provider",
    roles: ["session-runtime"],
    name: "TypeScript Test Provider",
    version: "0.1.0",
    executable: "typescript-test-provider",
    platforms: [{ os: normalizedOS(), architecture: normalizedArchitecture() }],
    capabilities: capabilities.map(capabilityDescriptor),
    interaction_modes: ["json-rpc"],
    permissions: [],
    configuration_schema: "schema.json",
    extensions: {},
  };
  return new ProviderServer({
    manifest,
    handlers,
    authenticationModes: ["none"],
    replaySupported: true,
    limits: {
      maximumMessageBytes: 64 << 10,
      maximumChunkBytes: 64 << 10,
      maximumOutboundQueue: limits.maximumOutboundQueue ?? 16,
      maximumInFlightRequests: 16,
      maximumIdempotencyEntries: 64,
      maximumIdempotencyBytes: 4 << 20,
      maximumSubscriptions: limits.maximumSubscriptions ?? 4,
      shutdownTimeoutMs: limits.shutdownTimeoutMs ?? 1000,
    },
  });
}

async function connectServer(server: ProviderServer): Promise<ServerConnection> {
  const toProvider = new PassThrough();
  const fromProvider = new PassThrough();
  const serverTask = server.serve({ readable: toProvider, writable: fromProvider });
  const client = new ProviderClient(
    { readable: fromProvider, writable: toProvider },
    { maximumMessageBytes: 64 << 10 },
  );
  await initializeTestClient(client);
  return { client, serverTask, toProvider, fromProvider };
}

async function initializeTestClient(client: ProviderClient): Promise<void> {
  await client.initialize({
    supported_protocol_versions: [PROTOCOL_VERSION],
    gateway_version: "0.1.0",
    platform: { os: normalizedOS(), architecture: normalizedArchitecture() },
    required_capabilities: ["provider.initialize", "provider.capabilities"],
    maximum_message_bytes: 64 << 10,
    maximum_chunk_bytes: 64 << 10,
    replay_supported: true,
    authentication_modes: ["none"],
    experimental_features: [],
  });
}

async function closeConnection(connection: ServerConnection): Promise<void> {
  connection.toProvider.end();
  await connection.serverTask;
  await connection.client.close();
  connection.fromProvider.destroy();
}

function capabilityDescriptor(name: CapabilityDescriptor["name"]): CapabilityDescriptor {
  const descriptor = CAPABILITY_CATALOG.find((candidate) => candidate.name === name);
  if (descriptor === undefined) {
    return {
      name,
      role: "session-runtime",
      mutating: true,
      delivery_class: "provider_idempotent",
    };
  }
  return { ...descriptor };
}

function terminalChunk(
  sequence: number,
  offset: number,
  data: string,
  creditRemaining: number,
  replayed: boolean,
) {
  return terminalChunkFor("native-session", sequence, offset, data, creditRemaining, replayed);
}

function terminalChunkFor(
  nativeSessionId: string,
  sequence: number,
  offset: number,
  data: string,
  creditRemaining: number,
  replayed: boolean,
) {
  return {
    native_session_id: nativeSessionId,
    stream_id: "stdout",
    encoding: "utf-8" as const,
    sequence,
    offset,
    observed_at: new Date().toISOString(),
    data,
    replayed,
    truncated: false,
    redactions: [],
    credit_remaining: creditRemaining,
  };
}

function normalizedOS(): string {
  return process.platform === "win32" ? "windows" : process.platform;
}

function normalizedArchitecture(): string {
  return process.arch === "x64" ? "amd64" : process.arch;
}
