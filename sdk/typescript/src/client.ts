import { createHash, randomUUID } from "node:crypto";

import {
  isProtocolError,
  isProtocolErrorData,
  notSupported,
  protocolError,
  protocolErrorFrom,
  type ProtocolError,
} from "./errors.js";
import { decodeFrame, encodeFrame, FrameWriter, readFrames, type ProtocolTransport } from "./stdio.js";
import {
  MAX_MESSAGE_BYTES,
  MAX_TERMINAL_CHUNK_BYTES,
  parseProtocolJSON,
  NOTIFICATION_CANCEL,
  NOTIFICATION_EVENT,
  NOTIFICATION_HEARTBEAT,
  NOTIFICATION_TERMINAL_CHUNK,
  NOTIFICATION_TERMINAL_CREDIT,
  NOTIFICATION_TOPOLOGY_SNAPSHOT,
  validateCapabilityRequest,
  validateCapabilityResult,
  validateCommand,
  validateExtensionValue,
  validateNotification,
  validateProviderNegotiation,
  type CapabilityName,
  type Command,
  type EventsSubscribeResult,
  type JSONObject,
  type JSONValue,
  type ProviderCapabilitiesResult,
  type ProviderInitializeRequest,
  type ProviderInitializeResult,
  type ProviderManifest,
  type TerminalChunk,
  type TerminalCredit,
  type TerminalSubscribeRequest,
} from "./types.js";

const JSON_RPC_VERSION = "2.0";
const RPC_INVALID_PARAMS = -32602;
const RPC_METHOD_NOT_FOUND = -32601;
const RPC_SERVER_ERROR = -32000;
const MAX_AGGREGATE_BYTES = 256 << 20;

export type NotificationMethod =
  | typeof NOTIFICATION_EVENT
  | typeof NOTIFICATION_TERMINAL_CHUNK
  | typeof NOTIFICATION_TOPOLOGY_SNAPSHOT
  | typeof NOTIFICATION_HEARTBEAT
  | typeof NOTIFICATION_CANCEL
  | typeof NOTIFICATION_TERMINAL_CREDIT;

export interface ProviderNotification {
  readonly method: NotificationMethod;
  readonly value: JSONObject;
}

export interface ClientLimits {
  readonly maximumMessageBytes: number;
  readonly maxPendingRequests: number;
  readonly maxWriteQueue: number;
  readonly maxNotificationQueue: number;
  readonly maxSubscriptions: number;
}

export const DEFAULT_CLIENT_LIMITS: Readonly<ClientLimits> = Object.freeze({
  maximumMessageBytes: MAX_MESSAGE_BYTES,
  maxPendingRequests: 64,
  maxWriteQueue: 16,
  maxNotificationQueue: 16,
  maxSubscriptions: 256,
});

export interface CallOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

type PendingRequest = {
  readonly resolve: (value: JSONValue) => void;
  readonly reject: (error: ProtocolError) => void;
};

type RPCRequest = {
  readonly jsonrpc: typeof JSON_RPC_VERSION;
  readonly id?: string;
  readonly method: string;
  readonly params: readonly [JSONObject];
};

type TerminalFlow = {
  readonly nativeSessionID: string;
  readonly streamID: string;
  readonly window: number;
  subscriptionID?: string;
  remaining: number;
  throughOffset: number;
  sequence: number;
  attachDigest?: string;
  attachPending: number;
  established: boolean;
  unknown: boolean;
};

/** Provider-protocol JSON-RPC client with bounded transport and notification state. */
export class ProviderClient {
  readonly #transport: ProtocolTransport;
  readonly #limits: ClientLimits;
  readonly #writer: FrameWriter;
  readonly #readerAbort = new AbortController();
  readonly #pending = new Map<string, PendingRequest>();
  readonly #notificationQueue: AsyncBoundedQueue<ProviderNotification>;
  readonly #terminalFlows = new Map<string, TerminalFlow>();
  readonly #readerTask: Promise<void>;
  #state: "new" | "initializing" | "initialized" | "closed" = "new";
  #manifest: ProviderManifest | undefined;
  #maximumMessageBytes: number;
  #maximumChunkBytes = MAX_TERMINAL_CHUNK_BYTES;
  #replaySupported = false;

  constructor(transport: ProtocolTransport, limits: Partial<ClientLimits> = {}) {
    if (!isTransport(transport)) throw protocolError("invalid_argument");
    this.#limits = normalizeLimits(limits);
    this.#transport = transport;
    this.#maximumMessageBytes = this.#limits.maximumMessageBytes;
    this.#writer = new FrameWriter(
      transport.writable,
      this.#maximumMessageBytes,
      this.#limits.maxWriteQueue,
    );
    this.#notificationQueue = new AsyncBoundedQueue(this.#limits.maxNotificationQueue);
    this.#readerTask = this.#readLoop();
  }

  async initialize(
    request: ProviderInitializeRequest,
    options: CallOptions = {},
  ): Promise<ProviderInitializeResult> {
    if (this.#state !== "new") throw protocolError("conflict");
    if (!validateCapabilityRequest("provider.initialize", request)) {
      throw protocolError("invalid_argument");
    }
    this.#state = "initializing";
    try {
      const result = await this.#call("provider.initialize", request as unknown as JSONObject, options, true);
      if (
        !validateCapabilityResult("provider.initialize", result) ||
        !validateProviderNegotiation(request, result)
      ) {
        throw protocolError("invalid_argument");
      }
      const initialized = snapshotJSON(result) as unknown as ProviderInitializeResult;
      this.#manifest = snapshotJSON(initialized.manifest) as unknown as ProviderManifest;
      this.#maximumMessageBytes = Math.min(
        this.#limits.maximumMessageBytes,
        initialized.maximum_message_bytes,
      );
      this.#maximumChunkBytes = Math.min(
        MAX_TERMINAL_CHUNK_BYTES,
        initialized.maximum_chunk_bytes,
      );
      this.#replaySupported = initialized.replay_supported;
      this.#writer.setMaximumBytes(this.#maximumMessageBytes);
      this.#state = "initialized";
      return initialized;
    } catch (error) {
      if (this.#state === "initializing") this.#state = "new";
      throw normalizeError(error);
    }
  }

  capabilities(options: CallOptions = {}): Promise<ProviderCapabilitiesResult> {
    return this.query<ProviderCapabilitiesResult>("provider.capabilities", {}, options);
  }

  async query<Result = JSONValue>(
    capability: CapabilityName,
    request: unknown,
    options: CallOptions = {},
  ): Promise<Result> {
    const descriptor = this.#descriptor(capability, false);
    if (descriptor.mutating === true || !validateCapabilityRequest(capability, request)) {
      throw protocolError("invalid_argument");
    }
    this.#validateReplayRequest(capability, request);
    preflightCallOptions(options);

    let flow: TerminalFlow | undefined;
    let responseReceived = false;
    if (capability === "terminal.subscribe") {
      flow = this.#reserveTerminalFlow(request as unknown as TerminalSubscribeRequest);
    }
    try {
      const result = await this.#call(capability, request, options);
      responseReceived = true;
      if (!validateCapabilityResult(capability, result)) throw protocolError("invalid_argument");
      if (capability === "terminal.read") {
        this.#validateTerminalReadResult(
          request,
          result as unknown as TerminalChunk,
        );
      }
      if (flow !== undefined) this.#bindTerminalFlow(flow, result as unknown as EventsSubscribeResult);
      return result as Result;
    } catch (error) {
      const normalized = normalizeError(error);
      if (flow !== undefined) {
        this.#removeTerminalFlow(flow);
        if (responseReceived || isAmbiguousTerminalFlowError(normalized)) this.#fail(normalized);
      }
      throw normalized;
    }
  }

  async mutate<Result = JSONValue>(
    command: Command,
    options: CallOptions = {},
  ): Promise<Result> {
    const descriptor = this.#descriptor(command.capability, true);
    const extension = isExtensionCapability(command.capability);
    if (
      descriptor.mutating !== true ||
      descriptor.delivery_class !== command.delivery_class ||
      !validateCommand(command) ||
      (extension
        ? !validateExtensionValue(command.payload)
        : !validateCapabilityRequest(command.capability, command))
    ) {
      throw protocolError("invalid_argument");
    }
    if (!extension) {
      if (!isJSONObject(command.payload)) throw protocolError("invalid_argument");
      this.#validateReplayRequest(command.capability, command.payload);
      if (command.capability === "terminal.send_input") {
        const size = terminalDataLength(command.payload);
        if (size > this.#maximumChunkBytes) throw protocolError("message_too_large");
      }
    }
    preflightCallOptions(options);

    let flow: TerminalFlow | undefined;
    let responseReceived = false;
    if (command.capability === "terminal.attach") {
      flow = this.#reserveAttachedTerminalFlow(
        command.payload as unknown as TerminalSubscribeRequest,
        command,
      );
    }
    try {
      const result = await this.#call(command.capability, command as unknown as JSONObject, options);
      responseReceived = true;
      if (!validateCapabilityResult(command.capability, result)) throw protocolError("invalid_argument");
      if (flow !== undefined) {
        this.#completeAttachedTerminalFlow(
          flow,
          result as unknown as EventsSubscribeResult,
        );
      }
      if (command.capability === "terminal.detach" || command.capability === "events.unsubscribe") {
        this.#removeTerminalFlowBySubscription(
          isJSONObject(command.payload) ? command.payload.subscription_id : undefined,
        );
      }
      return result as Result;
    } catch (error) {
      const normalized = normalizeError(error);
      if (flow !== undefined) {
        this.#completeAttachedTerminalFlow(flow, undefined, normalized);
        if (responseReceived) this.#fail(normalized);
      }
      throw normalized;
    }
  }

  async sendTerminalCredit(credit: TerminalCredit, options: CallOptions = {}): Promise<void> {
    if (
      this.#state !== "initialized" ||
      !validateNotification(NOTIFICATION_TERMINAL_CREDIT, credit)
    ) {
      throw protocolError("invalid_argument");
    }
    const flow = this.#terminalFlows.get(terminalKey(credit.native_session_id, credit.stream_id));
    if (
      flow === undefined ||
      credit.through_offset !== flow.throughOffset ||
      credit.bytes > flow.window - flow.remaining
    ) {
      throw protocolError("invalid_argument");
    }
    flow.remaining += credit.bytes;
    try {
      await this.#sendNotification(NOTIFICATION_TERMINAL_CREDIT, credit as unknown as JSONObject, options);
    } catch (error) {
      this.#fail(normalizeError(error));
      throw normalizeError(error);
    }
  }

  notifications(): AsyncIterable<ProviderNotification> {
    return this.#notificationQueue;
  }

  async close(): Promise<void> {
    if (this.#state === "closed") return;
    this.#state = "closed";
    this.#readerAbort.abort();
    const reason = protocolError("cancelled");
    this.#writer.close(reason);
    this.#rejectPending(reason);
    this.#notificationQueue.end();
    this.#terminalFlows.clear();
    try {
      await this.#transport.close?.();
    } catch {
      // Closing is best effort and never exposes native transport diagnostics.
    }
    await this.#readerTask.catch(() => undefined);
  }

  async #call(
    method: CapabilityName,
    parameter: JSONObject,
    options: CallOptions,
    initialization = false,
  ): Promise<JSONValue> {
    if (this.#state === "closed") throw protocolError("unavailable");
    if (!initialization && this.#state !== "initialized") throw protocolError("conflict");
    const call = callContext(options);
    try {
      if (call.signal.aborted) throw protocolError(call.code());
      if (this.#pending.size >= this.#limits.maxPendingRequests) {
        throw protocolError("resource_exhausted");
      }

      const id = randomUUID();
      const envelope: RPCRequest = { jsonrpc: JSON_RPC_VERSION, id, method, params: [parameter] };
      const frame = encodeFrame(envelope, this.#maximumMessageBytes);
      let resolveOutcome!: (value: JSONValue) => void;
      let rejectOutcome!: (error: ProtocolError) => void;
      const outcome = new Promise<JSONValue>((resolve, reject) => {
        resolveOutcome = resolve;
        rejectOutcome = reject;
      });
      void outcome.catch(() => undefined);
      const pending: PendingRequest = { resolve: resolveOutcome, reject: rejectOutcome };
      this.#pending.set(id, pending);

      const aborted = (): void => {
        if (this.#pending.get(id) !== pending) return;
        this.#pending.delete(id);
        pending.reject(protocolError(call.code()));
        void this.#sendNotification(NOTIFICATION_CANCEL, { request_id: id }).catch((error: unknown) => {
          this.#fail(normalizeError(error));
        });
      };
      call.signal.addEventListener("abort", aborted, { once: true });
      try {
        const writing = this.#writer.write(frame, call.signal);
        void writing.catch(() => undefined);
        return await Promise.race([outcome, writing.then(() => outcome)]);
      } catch (error) {
        if (this.#pending.get(id) === pending) this.#pending.delete(id);
        if (call.signal.aborted) throw protocolError(call.code());
        throw normalizeError(error);
      } finally {
        call.signal.removeEventListener("abort", aborted);
      }
    } finally {
      call.dispose();
    }
  }

  async #sendNotification(
    method: NotificationMethod,
    value: JSONObject,
    options: CallOptions = {},
  ): Promise<void> {
    if (this.#state === "closed") throw protocolError("unavailable");
    const call = callContext(options);
    try {
      const frame = encodeFrame({ jsonrpc: JSON_RPC_VERSION, method, params: [value] }, this.#maximumMessageBytes);
      await this.#writer.write(frame, call.signal);
    } catch (error) {
      if (call.signal.aborted) throw protocolError(call.code());
      throw normalizeError(error);
    } finally {
      call.dispose();
    }
  }

  async #readLoop(): Promise<void> {
    try {
      for await (const frame of readFrames(
        this.#transport.readable,
        () => this.#maximumMessageBytes,
        this.#readerAbort.signal,
      )) {
        const envelope = decodeFrame(frame);
        if (Object.hasOwn(envelope, "method")) this.#acceptNotification(envelope);
        else this.#acceptResponse(envelope);
      }
      if (this.#state !== "closed") this.#fail(protocolError("unavailable"));
    } catch (error) {
      if (this.#state !== "closed") this.#fail(normalizeError(error));
    }
  }

  #acceptResponse(value: JSONObject): void {
    if (!hasOnlyKeys(value, ["jsonrpc", "id", "result", "error"])) {
      throw protocolError("invalid_argument");
    }
    if (value.jsonrpc !== JSON_RPC_VERSION || !isWireToken(value.id)) {
      throw protocolError("invalid_argument");
    }
    const hasResult = Object.hasOwn(value, "result");
    const hasError = Object.hasOwn(value, "error");
    if (hasResult === hasError || (hasResult && value.result === null)) {
      throw protocolError("invalid_argument");
    }
    const pending = this.#pending.get(value.id);
    if (hasError) {
      const error = decodeRPCError(value.error);
      if (pending === undefined) return;
      this.#pending.delete(value.id);
      pending.reject(error);
      return;
    }
    if (!isJSONValue(value.result)) throw protocolError("invalid_argument");
    if (pending === undefined) return;
    this.#pending.delete(value.id);
    pending.resolve(value.result);
  }

  #acceptNotification(value: JSONObject): void {
    if (!hasOnlyKeys(value, ["jsonrpc", "method", "params"])) throw protocolError("invalid_argument");
    if (
      value.jsonrpc !== JSON_RPC_VERSION ||
      !isNotificationMethod(value.method) ||
      !Array.isArray(value.params) ||
      value.params.length !== 1 ||
      !isJSONObject(value.params[0])
    ) {
      throw protocolError("invalid_argument");
    }
    const payload = value.params[0];
    if (!validateNotification(value.method, payload)) throw protocolError("invalid_argument");
    switch (value.method) {
      case NOTIFICATION_TERMINAL_CHUNK:
        this.#consumeTerminalChunk(payload as unknown as TerminalChunk);
        break;
    }
    if (!this.#notificationQueue.push({ method: value.method, value: payload })) {
      throw protocolError("resource_exhausted");
    }
  }

  #descriptor(capability: CapabilityName, mutating: boolean): ProviderManifest["capabilities"][number] {
    if (this.#state !== "initialized" || this.#manifest === undefined) throw protocolError("conflict");
    const descriptor = this.#manifest.capabilities.find((value) => value.name === capability);
    if (descriptor === undefined) {
      throw notSupported(
        capability,
        this.#manifest.capabilities.map((value) => value.name),
      );
    }
    if (descriptor.mutating === true !== mutating) throw protocolError("invalid_argument");
    return descriptor;
  }

  #validateReplayRequest(capability: CapabilityName, request: JSONObject): void {
    if (this.#replaySupported) return;
    if (
      (capability === "terminal.read" || capability === "terminal.subscribe" || capability === "terminal.attach") &&
      typeof request.after_offset === "number" &&
      request.after_offset > 0
    ) {
      throw protocolError("invalid_argument");
    }
    if (capability === "events.subscribe" && Array.isArray(request.cursors)) {
      for (const cursor of request.cursors) {
        if (isJSONObject(cursor) && typeof cursor.after_sequence === "number" && cursor.after_sequence > 0) {
          throw protocolError("invalid_argument");
        }
      }
    }
  }

  #reserveTerminalFlow(request: TerminalSubscribeRequest): TerminalFlow {
    const key = terminalKey(request.native_session_id, request.stream_id);
    if (this.#terminalFlows.has(key)) throw protocolError("conflict");
    if (this.#terminalFlows.size >= this.#limits.maxSubscriptions) {
      throw protocolError("resource_exhausted");
    }
    const flow: TerminalFlow = {
      nativeSessionID: request.native_session_id,
      streamID: request.stream_id,
      window: request.window_bytes,
      remaining: request.window_bytes,
      throughOffset: request.after_offset,
      sequence: 0,
      attachPending: 0,
      established: false,
      unknown: false,
    };
    this.#terminalFlows.set(key, flow);
    return flow;
  }

  #reserveAttachedTerminalFlow(request: TerminalSubscribeRequest, command: Command): TerminalFlow {
    const key = terminalKey(request.native_session_id, request.stream_id);
    const digest = createHash("sha256").update(JSON.stringify(command)).digest("hex");
    const existing = this.#terminalFlows.get(key);
    if (existing !== undefined) {
      if (existing.attachDigest !== digest) throw protocolError("conflict");
      existing.attachPending += 1;
      return existing;
    }
    const flow = this.#reserveTerminalFlow(request);
    flow.attachDigest = digest;
    flow.attachPending = 1;
    return flow;
  }

  #completeAttachedTerminalFlow(
    flow: TerminalFlow,
    result?: EventsSubscribeResult,
    error?: ProtocolError,
  ): void {
    if (result !== undefined) {
      this.#bindTerminalFlow(flow, result);
      flow.established = true;
    } else if (error !== undefined && isAmbiguousTerminalFlowError(error)) {
      flow.unknown = true;
    }
    if (flow.attachPending > 0) flow.attachPending -= 1;
    if (
      error !== undefined &&
      !isAmbiguousTerminalFlowError(error) &&
      flow.attachPending === 0 &&
      !flow.established &&
      !flow.unknown
    ) {
      this.#removeTerminalFlow(flow);
    }
  }

  #bindTerminalFlow(flow: TerminalFlow, result: EventsSubscribeResult): void {
    if (flow.subscriptionID !== undefined && flow.subscriptionID !== result.subscription_id) {
      throw protocolError("conflict");
    }
    flow.subscriptionID = result.subscription_id;
  }

  #consumeTerminalChunk(chunk: TerminalChunk): void {
    this.#validateTerminalChunk(chunk);
    const flow = this.#terminalFlows.get(terminalKey(chunk.native_session_id, chunk.stream_id));
    if (flow === undefined) throw protocolError("invalid_argument");
    const size = terminalDataLength(chunk as unknown as JSONObject);
    let nextOffset = flow.throughOffset;
    if (chunk.offset !== nextOffset) {
      if (!chunk.truncated || chunk.offset < nextOffset) throw protocolError("sequence_conflict");
      nextOffset = chunk.offset;
    }
    if (flow.sequence !== 0 && chunk.sequence !== flow.sequence + 1 && !chunk.truncated) {
      throw protocolError("sequence_conflict");
    }
    if (size > flow.remaining || chunk.credit_remaining !== flow.remaining - size) {
      throw protocolError("invalid_argument");
    }
    flow.remaining -= size;
    flow.throughOffset = nextOffset + size;
    flow.sequence = chunk.sequence;
  }

  #validateTerminalChunk(chunk: TerminalChunk): void {
    const size = terminalDataLength(chunk as unknown as JSONObject);
    if (size > this.#maximumChunkBytes) throw protocolError("message_too_large");
    if (chunk.replayed && !this.#replaySupported) throw protocolError("invalid_argument");
  }

  #validateTerminalReadResult(request: JSONObject, chunk: TerminalChunk): void {
    this.#validateTerminalChunk(chunk);
    const size = terminalDataLength(chunk as unknown as JSONObject);
    if (
      chunk.native_session_id !== request.native_session_id ||
      chunk.stream_id !== request.stream_id ||
      typeof request.maximum_bytes !== "number" ||
      size > request.maximum_bytes
    ) {
      throw protocolError(size > (request.maximum_bytes as number) ? "message_too_large" : "invalid_argument");
    }
    if (
      chunk.offset !== request.after_offset &&
      (!chunk.truncated ||
        typeof request.after_offset !== "number" ||
        chunk.offset < request.after_offset)
    ) {
      throw protocolError("sequence_conflict");
    }
  }

  #removeTerminalFlow(flow: TerminalFlow): void {
    const key = terminalKey(flow.nativeSessionID, flow.streamID);
    if (this.#terminalFlows.get(key) === flow) this.#terminalFlows.delete(key);
  }

  #removeTerminalFlowBySubscription(value: JSONValue | undefined): void {
    if (typeof value !== "string") return;
    for (const flow of this.#terminalFlows.values()) {
      if (flow.subscriptionID === value) {
        this.#removeTerminalFlow(flow);
        return;
      }
    }
  }

  #fail(error: ProtocolError): void {
    if (this.#state === "closed") return;
    this.#state = "closed";
    this.#readerAbort.abort();
    this.#writer.close(error);
    this.#rejectPending(error);
    this.#notificationQueue.fail(error);
    this.#terminalFlows.clear();
    try {
      const closed = this.#transport.close?.();
      if (closed instanceof Promise) void closed.catch(() => undefined);
    } catch {
      // Transport diagnostics are deliberately suppressed.
    }
  }

  #rejectPending(error: ProtocolError): void {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
  }
}

/** Short compatibility name for callers that prefer the Go SDK naming. */
export { ProviderClient as Client };

class AsyncBoundedQueue<Value> implements AsyncIterable<Value> {
  readonly #maximum: number;
  readonly #values: Value[] = [];
  readonly #waiters: Array<{
    resolve: (result: IteratorResult<Value>) => void;
    reject: (error: unknown) => void;
  }> = [];
  #ended = false;
  #error: unknown;

  constructor(maximum: number) {
    this.#maximum = maximum;
  }

  push(value: Value): boolean {
    if (this.#ended) return false;
    const waiter = this.#waiters.shift();
    if (waiter !== undefined) {
      waiter.resolve({ value, done: false });
      return true;
    }
    if (this.#values.length >= this.#maximum) return false;
    this.#values.push(value);
    return true;
  }

  end(): void {
    if (this.#ended) return;
    this.#ended = true;
    for (const waiter of this.#waiters.splice(0)) waiter.resolve({ value: undefined, done: true });
  }

  fail(error: unknown): void {
    if (this.#ended) return;
    this.#ended = true;
    this.#error = error;
    for (const waiter of this.#waiters.splice(0)) waiter.reject(error);
  }

  [Symbol.asyncIterator](): AsyncIterator<Value> {
    return { next: () => this.#next() };
  }

  #next(): Promise<IteratorResult<Value>> {
    const value = this.#values.shift();
    if (value !== undefined) return Promise.resolve({ value, done: false });
    if (this.#ended) {
      if (this.#error !== undefined) return Promise.reject(this.#error);
      return Promise.resolve({ value: undefined, done: true });
    }
    return new Promise((resolve, reject) => this.#waiters.push({ resolve, reject }));
  }
}

function normalizeLimits(overrides: Partial<ClientLimits>): ClientLimits {
  if (!isJSONObject(overrides)) throw protocolError("invalid_argument");
  const allowed = [
    "maximumMessageBytes",
    "maxPendingRequests",
    "maxWriteQueue",
    "maxNotificationQueue",
    "maxSubscriptions",
  ];
  if (!hasOnlyKeys(overrides, allowed)) throw protocolError("invalid_argument");
  const limits: ClientLimits = { ...DEFAULT_CLIENT_LIMITS, ...overrides };
  const boundedQueues = [limits.maxWriteQueue, limits.maxNotificationQueue];
  if (
    !Number.isSafeInteger(limits.maximumMessageBytes) ||
    limits.maximumMessageBytes < 1 ||
    limits.maximumMessageBytes > MAX_MESSAGE_BYTES ||
    (!Number.isSafeInteger(limits.maxPendingRequests) ||
      limits.maxPendingRequests < 1 ||
      limits.maxPendingRequests > 65_536) ||
    boundedQueues.some((value) => !Number.isSafeInteger(value) || value < 1 || value > 4096) ||
    !Number.isSafeInteger(limits.maxSubscriptions) ||
    limits.maxSubscriptions < 1 ||
    limits.maxSubscriptions > 65_536 ||
    limits.maxPendingRequests > Math.floor(MAX_AGGREGATE_BYTES / limits.maximumMessageBytes) ||
    limits.maxWriteQueue > Math.floor(MAX_AGGREGATE_BYTES / limits.maximumMessageBytes) ||
    limits.maxNotificationQueue > Math.floor(MAX_AGGREGATE_BYTES / limits.maximumMessageBytes)
  ) {
    throw protocolError("invalid_argument");
  }
  return limits;
}

function preflightCallOptions(options: CallOptions): void {
  const { externalSignal } = validateCallOptions(options);
  if (externalSignal?.aborted === true) throw protocolError("cancelled");
}

function validateCallOptions(options: CallOptions): {
  externalSignal: AbortSignal | undefined;
  timeoutMs: number | undefined;
} {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw protocolError("invalid_argument");
  }
  if (!hasOnlyKeys(options, ["signal", "timeoutMs"])) throw protocolError("invalid_argument");
  const timeoutMs = options.timeoutMs;
  if (
    timeoutMs !== undefined &&
    (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000)
  ) {
    throw protocolError("invalid_argument");
  }
  const externalSignal = options.signal;
  if (externalSignal !== undefined && !(externalSignal instanceof AbortSignal)) {
    throw protocolError("invalid_argument");
  }
  return { externalSignal, timeoutMs };
}

function callContext(options: CallOptions): {
  signal: AbortSignal;
  code: () => "cancelled" | "deadline_exceeded";
  dispose: () => void;
} {
  const { externalSignal, timeoutMs } = validateCallOptions(options);
  const controller = new AbortController();
  let deadline = false;
  const cancelled = (): void => controller.abort();
  externalSignal?.addEventListener("abort", cancelled, { once: true });
  if (externalSignal?.aborted === true) controller.abort();
  const timer = timeoutMs === undefined
    ? undefined
    : setTimeout(() => {
        deadline = true;
        controller.abort();
      }, timeoutMs);
  return {
    signal: controller.signal,
    code: () => (deadline ? "deadline_exceeded" : "cancelled"),
    dispose: () => {
      if (timer !== undefined) clearTimeout(timer);
      externalSignal?.removeEventListener("abort", cancelled);
    },
  };
}

function decodeRPCError(value: JSONValue | undefined): ProtocolError {
  if (!isJSONObject(value) || !hasOnlyKeys(value, ["code", "message", "data"])) {
    throw protocolError("invalid_argument");
  }
  if (!Number.isInteger(value.code) || typeof value.message !== "string" || !isProtocolErrorData(value.data)) {
    throw protocolError("invalid_argument");
  }
  const error = protocolErrorFrom(value.data);
  const expected = error.code === "not_supported"
    ? RPC_METHOD_NOT_FOUND
    : error.code === "invalid_argument" || error.code === "message_too_large"
      ? RPC_INVALID_PARAMS
      : RPC_SERVER_ERROR;
  if (value.code !== expected || value.message !== error.message) throw protocolError("invalid_argument");
  return error;
}

function normalizeError(value: unknown): ProtocolError {
  return isProtocolError(value) ? value : protocolError("unavailable");
}

function isWireToken(value: JSONValue | undefined): value is string {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > 256) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}

function isNotificationMethod(value: JSONValue | undefined): value is NotificationMethod {
  return (
    value === NOTIFICATION_EVENT ||
    value === NOTIFICATION_TERMINAL_CHUNK ||
    value === NOTIFICATION_TOPOLOGY_SNAPSHOT ||
    value === NOTIFICATION_HEARTBEAT ||
    value === NOTIFICATION_CANCEL ||
    value === NOTIFICATION_TERMINAL_CREDIT
  );
}

function isTransport(value: unknown): value is ProtocolTransport {
  return isJSONObject(value) && value.readable !== undefined && value.writable !== undefined;
}

function isJSONObject(value: unknown): value is JSONObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJSONValue(value: unknown): value is JSONValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJSONValue);
  if (isJSONObject(value)) return Object.values(value).every(isJSONValue);
  return false;
}

function snapshotJSON(value: unknown): JSONValue {
  let encoded: string | undefined;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw protocolError("invalid_argument");
  }
  if (encoded === undefined) throw protocolError("invalid_argument");
  return parseProtocolJSON(encoded);
}

function hasOnlyKeys(value: object, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function terminalKey(nativeSessionID: string, streamID: string): string {
  return `${nativeSessionID}\u0000${streamID}`;
}

function isAmbiguousTerminalFlowError(error: ProtocolError): boolean {
  return (
    error.code === "cancelled" ||
    error.code === "deadline_exceeded" ||
    error.code === "unavailable" ||
    error.code === "outcome_unknown"
  );
}

function isExtensionCapability(value: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\/[a-z][a-z0-9._-]{0,127}$/.test(
    value,
  );
}

function terminalDataLength(value: JSONObject): number {
  const encoding = value.encoding;
  const data = value.data;
  if (typeof data !== "string") throw protocolError("invalid_argument");
  if (encoding === "utf-8") {
    if (!isWellFormedUnicode(data)) throw protocolError("invalid_argument");
    return Buffer.byteLength(data, "utf8");
  }
  if (encoding === "base64" && isCanonicalBase64(data)) return Buffer.from(data, "base64").length;
  throw protocolError("invalid_argument");
}

function isCanonicalBase64(value: string): boolean {
  if (value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value;
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}
