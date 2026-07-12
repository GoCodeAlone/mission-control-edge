import { createHash } from "node:crypto";

import {
  ProtocolError,
  isProtocolError,
  notSupported,
  protocolError,
} from "./errors.js";
import {
  FrameWriter,
  createStdioTransport,
  decodeFrame,
  encodeFrame,
  readFrames,
  type ProtocolTransport,
} from "./stdio.js";
import {
  MAX_MESSAGE_BYTES,
  MAX_TERMINAL_CHUNK_BYTES,
  PROTOCOL_VERSION,
  validateCapabilityRequest,
  validateCapabilityResult,
  validateExtensionValue,
  validateNotification,
  parseProtocolJSON,
  validateProviderNegotiation,
  validateProtocolDocument,
  validateWireCapabilityRequest,
  type CapabilityName,
  type Command,
  type JSONObject,
  type JSONValue,
  type ProviderInitializeRequest,
  type ProviderInitializeResult,
  type ProviderManifest,
} from "./types.js";

const JSON_RPC_VERSION = "2.0";
const NOTIFICATION_CANCEL = "$mc/cancel";
const NOTIFICATION_HEARTBEAT = "$mc/heartbeat";
const NOTIFICATION_TERMINAL_CREDIT = "$mc/terminal.credit";
const providerSubscriptions = new WeakSet<object>();

export interface ProviderHandlerContext {
  readonly capability: CapabilityName;
  readonly requestId: string;
  readonly signal: AbortSignal;
  readonly command?: Command;
  readonly subscriptionSignal?: AbortSignal;
}

export type ProviderHandler = (
  request: JSONValue,
  context: ProviderHandlerContext,
) => unknown | Promise<unknown>;

export interface ProviderServerNotification {
  readonly method: string;
  readonly params: JSONObject;
}

export interface ProviderSubscription {
  readonly result: JSONValue;
  readonly notifications?: readonly ProviderServerNotification[];
  readonly replay?: readonly ProviderServerNotification[];
  readonly stream?: AsyncIterable<ProviderServerNotification>;
}

export interface ProviderServerLimits {
  readonly maximumMessageBytes?: number;
  readonly maximumChunkBytes?: number;
  readonly maximumOutboundQueue?: number;
  readonly maximumInFlightRequests?: number;
  readonly maximumIdempotencyEntries?: number;
  readonly maximumIdempotencyBytes?: number;
  readonly maximumSubscriptions?: number;
  readonly shutdownTimeoutMs?: number;
  readonly heartbeatIntervalMs?: number;
}

export interface ProviderServerConfig {
  readonly manifest: ProviderManifest;
  readonly authenticationModes: readonly string[];
  readonly replaySupported: boolean;
  readonly handlers?: Readonly<Record<string, ProviderHandler>>;
  readonly nativeRuntimeVersion?: string;
  readonly experimentalFeatures?: readonly string[];
  readonly limits?: ProviderServerLimits;
}

type RPCRequest = {
  readonly jsonrpc: "2.0";
  readonly id?: string;
  readonly method: string;
  readonly params: readonly [JSONObject];
  readonly rawParameter: Uint8Array;
};

type ResponsePlan = {
  readonly result: JSONValue;
  readonly notifications: readonly ProviderServerNotification[];
  readonly responseSignal?: AbortSignal;
  readonly responseDeadline?: number;
  readonly responseFailureAmbiguous?: boolean;
  readonly afterWrite?: () => void;
  readonly rollback?: () => void;
  readonly stream?: AsyncIterable<ProviderServerNotification>;
  subscription?: SubscriptionReservation;
  readonly cancelSubscriptionId?: string;
  readonly shutdown?: boolean;
};

type TerminalLedger = {
  readonly nativeSessionId: string;
  readonly streamId: string;
  readonly window: number;
  remaining: number;
  throughOffset: number;
  sequence: number;
  wake: Set<() => void>;
};

type SubscriptionReservation = {
  readonly capability: CapabilityName;
  readonly request: JSONObject;
  readonly lifetime: AbortController;
  readonly setupSignal: AbortSignal;
  readonly setupAbort: () => void;
  readonly terminalKey?: string;
  terminal?: TerminalLedger;
  subscriptionId?: string;
  stream?: AsyncIterable<ProviderServerNotification>;
  iterator?: AsyncIterator<ProviderServerNotification>;
  committed: boolean;
  released: boolean;
};

type MutationRecord = {
  readonly digest: string;
  readonly commandId: string;
  readonly completion: Promise<void>;
  resolve: () => void;
  status: "pending" | "succeeded" | "failed" | "outcome_unknown";
  reservedBytes: number;
  result: JSONValue | undefined;
  error: ProtocolError | undefined;
  readonly connectionId: string | undefined;
};

type ServerLimits = Required<ProviderServerLimits>;

/** Marks a response whose notifications must be emitted only after its RPC acknowledgement. */
export function providerSubscription(
  result: JSONValue,
  replay: readonly ProviderServerNotification[] = [],
  stream?: AsyncIterable<ProviderServerNotification>,
): ProviderSubscription {
  const subscription = Object.freeze({
    result,
    replay: Object.freeze([...replay]),
    ...(stream === undefined ? {} : { stream }),
  });
  providerSubscriptions.add(subscription);
  return subscription;
}

type AdmissionWaiter = {
  readonly resolve: (release: () => void) => void;
  readonly reject: (error: ProtocolError) => void;
  readonly signal?: AbortSignal;
  abort?: () => void;
  settled: boolean;
};

/** Applies asynchronous admission before writes reach FrameWriter's bounded queue. */
class ServerFrameWriter {
  readonly #writer: FrameWriter;
  readonly #writable: ProtocolTransport["writable"];
  readonly #maximumAdmissions: number;
  readonly #waiters: AdmissionWaiter[] = [];
  #admitted = 0;
  #closedError: ProtocolError | undefined;

  constructor(
    writable: ProtocolTransport["writable"],
    maximumBytes: number,
    maximumAdmissions: number,
  ) {
    this.#writable = writable;
    this.#maximumAdmissions = maximumAdmissions;
    this.#writer = new FrameWriter(
      writable,
      maximumBytes,
      maximumAdmissions,
      () => this.#abortActiveWrite(),
    );
  }

  async write(frame: Uint8Array, signal?: AbortSignal): Promise<void> {
    const release = await this.#acquire(signal);
    try {
      await this.#writer.write(frame, signal);
    } finally {
      release();
    }
  }

  setMaximumBytes(maximumBytes: number): void {
    this.#writer.setMaximumBytes(maximumBytes);
  }

  close(error: ProtocolError = protocolError("unavailable")): void {
    this.#close(error);
    this.#writer.close(error);
  }

  fail(error: ProtocolError = protocolError("unavailable")): void {
    this.#close(error);
    this.#writer.fail(error);
    this.#destroyWritable();
  }

  #acquire(signal?: AbortSignal): Promise<() => void> {
    if (this.#closedError !== undefined) return Promise.reject(this.#closedError);
    if (signal?.aborted === true) return Promise.reject(protocolError("cancelled"));
    if (this.#admitted < this.#maximumAdmissions) {
      this.#admitted += 1;
      return Promise.resolve(this.#releaseOnce());
    }
    return new Promise<() => void>((resolve, reject) => {
      const waiter: AdmissionWaiter = {
        resolve,
        reject,
        ...(signal === undefined ? {} : { signal }),
        settled: false,
      };
      if (signal !== undefined) {
        waiter.abort = () => {
          if (waiter.settled) return;
          waiter.settled = true;
          const index = this.#waiters.indexOf(waiter);
          if (index >= 0) this.#waiters.splice(index, 1);
          reject(protocolError("cancelled"));
        };
        signal.addEventListener("abort", waiter.abort, { once: true });
      }
      this.#waiters.push(waiter);
    });
  }

  #releaseOnce(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#admitted -= 1;
      this.#drain();
    };
  }

  #drain(): void {
    while (
      this.#closedError === undefined &&
      this.#admitted < this.#maximumAdmissions &&
      this.#waiters.length > 0
    ) {
      const waiter = this.#waiters.shift() as AdmissionWaiter;
      if (waiter.settled) continue;
      if (waiter.abort !== undefined && waiter.signal !== undefined) {
        waiter.signal.removeEventListener("abort", waiter.abort);
      }
      if (waiter.signal?.aborted === true) {
        waiter.settled = true;
        waiter.reject(protocolError("cancelled"));
        continue;
      }
      waiter.settled = true;
      this.#admitted += 1;
      waiter.resolve(this.#releaseOnce());
    }
  }

  #close(error: ProtocolError): void {
    if (this.#closedError !== undefined) return;
    this.#closedError = error;
    for (const waiter of this.#waiters.splice(0)) {
      if (waiter.abort !== undefined && waiter.signal !== undefined) {
        waiter.signal.removeEventListener("abort", waiter.abort);
      }
      if (waiter.settled) continue;
      waiter.settled = true;
      waiter.reject(error);
    }
  }

  #abortActiveWrite(): void {
    this.fail(protocolError("cancelled"));
  }

  #destroyWritable(): void {
    try {
      this.#writable.destroy();
    } catch {
      // The writer is already failed; native destroy details remain local.
    }
  }
}

/** A bounded JSON-RPC provider server over stdio or another stream transport. */
export class ProviderServer {
  readonly #config: ProviderServerConfig;
  readonly #limits: ServerLimits;
  readonly #capabilities: ReadonlyMap<string, ProviderManifest["capabilities"][number]>;
  readonly #handlers: Readonly<Record<string, ProviderHandler>>;
  readonly #idempotency = new Map<string, MutationRecord>();
  readonly #commandIds = new Map<string, MutationRecord>();
  readonly #active = new Map<string, AbortController>();
  readonly #subscriptions = new Map<string, SubscriptionReservation>();
  readonly #terminalSubscriptions = new Map<string, SubscriptionReservation>();
  readonly #streamTasks = new Set<Promise<void>>();
  #subscriptionCount = 0;
  #idempotencyBytes = 0;
  #initialized = false;
  #initializingRequestId: string | undefined;
  #maximumMessageBytes: number;
  #maximumChunkBytes: number;
  #replaySupported = false;
  #serving = false;
  #nextConnectionId = 0;

  constructor(config: ProviderServerConfig) {
    let manifest: ProviderManifest;
    try {
      manifest = snapshotJSONObject(config.manifest) as unknown as ProviderManifest;
    } catch {
      throw protocolError("invalid_argument");
    }
    if (!validateProtocolDocument("provider_manifest", manifest)) {
      throw protocolError("invalid_argument");
    }
    if (!validTokenSet(config.authenticationModes, 1, 16)) {
      throw protocolError("invalid_argument");
    }
    if (!validTokenSet(config.experimentalFeatures ?? [], 0, 64)) {
      throw protocolError("invalid_argument");
    }
    const handlers = Object.freeze({ ...(config.handlers ?? {}) });
    const advertised = new Set(manifest.capabilities.map(({ name }) => name));
    for (const required of ["provider.initialize", "provider.capabilities"] as const) {
      if (!advertised.has(required)) throw protocolError("invalid_argument");
    }
    const builtIns = new Set<CapabilityName>([
      "provider.initialize",
      "provider.capabilities",
      "command.get_result",
    ]);
    for (const capability of advertised) {
      if (!builtIns.has(capability) && typeof handlers[capability] !== "function") {
        throw protocolError("invalid_argument");
      }
    }
    for (const [capability, handler] of Object.entries(handlers)) {
      if (
        !advertised.has(capability) ||
        typeof handler !== "function" ||
        capability === "provider.initialize" ||
        capability === "provider.capabilities"
      ) {
        throw protocolError("invalid_argument");
      }
    }
    this.#limits = normalizeLimits(config.limits);
    this.#maximumMessageBytes = this.#limits.maximumMessageBytes;
    this.#maximumChunkBytes = this.#limits.maximumChunkBytes;
    this.#config = Object.freeze({
      ...config,
      manifest,
      authenticationModes: Object.freeze([...config.authenticationModes]),
      experimentalFeatures: Object.freeze([...(config.experimentalFeatures ?? [])]),
      handlers,
    });
    this.#handlers = handlers;
    this.#capabilities = new Map(
      manifest.capabilities.map((capability) => [capability.name, capability]),
    );
  }

  async serve(
    transport: ProtocolTransport = createStdioTransport(),
    signal?: AbortSignal,
  ): Promise<void> {
    if (this.#serving) throw protocolError("conflict");
    this.#serving = true;
    this.#nextConnectionId += 1;
    const connectionId = `connection-${this.#nextConnectionId}`;
    this.#abortConnectionInitialization();
    const service = new AbortController();
    const abortService = (): void => service.abort();
    signal?.addEventListener("abort", abortService, { once: true });
    const writer = new ServerFrameWriter(
      transport.writable,
      this.#limits.maximumMessageBytes,
      this.#limits.maximumOutboundQueue,
    );
    const heartbeatTask = this.#heartbeatLoop(writer, service.signal).catch(() => service.abort());
    const requests = new Set<Promise<void>>();
    try {
      for await (const frame of readFrames(
        transport.readable,
        () => this.#maximumMessageBytes,
        service.signal,
      )) {
        let request: RPCRequest;
        try {
          request = decodeRequest(decodeFrame(frame), extractSingleParameter(frame));
        } catch (error) {
          throw normalizeError(error);
        }
        if (request.id === undefined) {
          this.#handleNotification(request);
          continue;
        }
        if (requests.size >= this.#limits.maximumInFlightRequests) {
          await this.#writeError(writer, request.id, protocolError("resource_exhausted"));
          continue;
        }
        if (this.#active.has(request.id)) {
          await this.#writeError(writer, request.id, protocolError("conflict"));
          continue;
        }
        const controller = new AbortController();
        this.#active.set(request.id, controller);
        const identifiedRequest = { ...request, id: request.id };
        const task = this.#processRequest(
          writer,
          identifiedRequest,
          controller,
          connectionId,
          () => service.abort(),
        )
          .catch(() => {
            // A failed response write makes the connection unusable. The read loop
            // will observe the transport failure or EOF; no native detail is logged.
            service.abort();
          })
          .finally(() => {
            this.#active.delete(request.id as string);
            requests.delete(task);
          });
        requests.add(task);
      }
    } catch (error) {
      if (!(service.signal.aborted || signal?.aborted === true)) {
        throw normalizeError(error);
      }
    } finally {
      service.abort();
      signal?.removeEventListener("abort", abortService);
      for (const controller of this.#active.values()) controller.abort();
      this.#releaseAllSubscriptions();
      const drained = await settleWithin(
        [...requests, ...this.#streamTasks, heartbeatTask],
        this.#limits.shutdownTimeoutMs,
      );
      if (drained) writer.close();
      else writer.fail(protocolError("deadline_exceeded"));
      try {
        const closeResult = transport.close?.();
        if (closeResult !== undefined) {
          await settleWithin([Promise.resolve(closeResult)], this.#limits.shutdownTimeoutMs);
        }
      } catch {
        // Transport closure is best-effort; connection state cleanup must continue.
      }
      this.#releaseConnectionMutations(connectionId);
      if (drained) {
        this.#abortConnectionInitialization();
        this.#serving = false;
      }
      if (!drained) throw protocolError("deadline_exceeded");
    }
  }

  async #processRequest(
    writer: ServerFrameWriter,
    request: RPCRequest & { readonly id: string },
    controller: AbortController,
    connectionId: string,
    failConnection: () => void,
  ): Promise<void> {
    let plan: ResponsePlan | undefined;
    let responsePublished = false;
    try {
      plan = await this.#execute(request, controller.signal, connectionId);
      const beforeWriteExpiry = responseExpiryError(plan);
      if (beforeWriteExpiry !== undefined) {
        plan.rollback?.();
        plan = undefined;
        throw beforeWriteExpiry;
      }
      await this.#writeResult(
        writer,
        request.id,
        plan.result,
        plan.responseSignal ?? controller.signal,
      );
      responsePublished = true;
      const afterWriteExpiry = responseExpiryError(plan);
      if (afterWriteExpiry !== undefined) {
        plan.rollback?.();
        plan = undefined;
        throw afterWriteExpiry;
      }
      plan.afterWrite?.();
      if (request.method === "provider.initialize") {
        writer.setMaximumBytes(this.#maximumMessageBytes);
      }
      for (const notification of plan.notifications) {
        if (plan.subscription !== undefined) {
          await this.#consumeTerminalNotification(plan.subscription, notification);
        }
        await this.#writeNotification(
          writer,
          notification,
          plan.subscription?.lifetime.signal ?? controller.signal,
        );
      }
      if (plan.subscription !== undefined) {
        if (plan.stream === undefined) this.#releaseSubscription(plan.subscription);
        else this.#startSubscriptionStream(plan.subscription, writer, failConnection);
      }
      if (plan.cancelSubscriptionId !== undefined) {
        this.#cancelSubscription(plan.cancelSubscriptionId);
      }
      if (plan.shutdown === true) failConnection();
    } catch (error) {
      if (responsePublished) {
        if (plan?.subscription !== undefined) this.#releaseSubscription(plan.subscription);
        throw normalizeError(error);
      }
      const responseError = plan?.responseFailureAmbiguous === true
        ? protocolError("outcome_unknown")
        : responseExpiryError(plan) ?? normalizeError(error);
      plan?.rollback?.();
      if (request.method === "provider.initialize") this.#abortInitialization(request.id);
      await this.#writeError(writer, request.id, responseError);
    }
  }

  async #execute(
    request: RPCRequest,
    requestSignal: AbortSignal,
    connectionId: string,
  ): Promise<ResponsePlan> {
    const capability = request.method as CapabilityName;
    const parameter = request.params[0];
    if (capability === "provider.initialize") {
      return this.#initialize(parameter, request.id as string);
    }
    if (!this.#initialized) throw protocolError("unauthenticated");
    const descriptor = this.#capabilities.get(capability);
    if (descriptor === undefined) {
      throw notSupported(capability, this.#advertisedCapabilities());
    }
    if (descriptor.mutating === true) {
      if (!isExtensionCapability(capability) && !validateWireCapabilityRequest(capability, parameter)) {
        throw protocolError("invalid_argument");
      }
      return this.#executeMutation(
        capability,
        parameter as unknown as Command,
        request.id as string,
        requestSignal,
        connectionId,
        request.rawParameter,
      );
    }
    if (!validateWireCapabilityRequest(capability, parameter)) {
      throw protocolError("invalid_argument");
    }
    this.#validateReplayRequest(capability, parameter);
    if (capability === "provider.capabilities") {
      const result: JSONObject = {
        provider_id: this.#config.manifest.id,
        roles: [...this.#config.manifest.roles],
        capabilities: this.#config.manifest.capabilities.map((value) => ({ ...value })),
      };
      return { result, notifications: [] };
    }
    if (capability === "command.get_result" && this.#handlers[capability] === undefined) {
      return { result: this.#commandResult(parameter), notifications: [] };
    }
    const reservation = isSubscriptionCapability(capability)
      ? this.#reserveSubscription(capability, parameter, requestSignal)
      : undefined;
    try {
      const value = await this.#invoke(
        capability,
        parameter,
        request.id as string,
        requestSignal,
        undefined,
        reservation?.lifetime.signal,
      );
      const plan = this.#validateHandlerResult(capability, value, false, parameter);
      return reservation === undefined ? plan : this.#prepareSubscription(plan, reservation);
    } catch (error) {
      if (reservation !== undefined) this.#releaseSubscription(reservation);
      throw error;
    }
  }

  #initialize(parameter: JSONObject, requestId: string): ResponsePlan {
    if (this.#initialized || this.#initializingRequestId !== undefined) {
      throw protocolError("conflict");
    }
    if (!validateWireCapabilityRequest("provider.initialize", parameter)) {
      throw protocolError("invalid_argument");
    }
    this.#initializingRequestId = requestId;
    const request = parameter as unknown as ProviderInitializeRequest;
    const authenticationMode = this.#config.authenticationModes.find((mode) =>
      request.authentication_modes.includes(mode),
    );
    if (authenticationMode === undefined) throw protocolError("unauthenticated");
    if (!request.supported_protocol_versions.includes(PROTOCOL_VERSION)) {
      throw notSupported("provider.initialize", this.#advertisedCapabilities());
    }
    const experimentalFeatures = (this.#config.experimentalFeatures ?? []).filter((feature) =>
      request.experimental_features.includes(feature),
    );
    const maximumMessageBytes = Math.min(
      request.maximum_message_bytes,
      this.#limits.maximumMessageBytes,
    );
    const maximumChunkBytes = Math.min(
      request.maximum_chunk_bytes,
      this.#limits.maximumChunkBytes,
      maximumMessageBytes,
    );
    const result: ProviderInitializeResult = {
      protocol_version: PROTOCOL_VERSION,
      manifest: this.#config.manifest,
      maximum_message_bytes: maximumMessageBytes,
      maximum_chunk_bytes: maximumChunkBytes,
      replay_supported: request.replay_supported && this.#config.replaySupported,
      authentication_mode: authenticationMode,
      experimental_features: experimentalFeatures,
    };
    if (this.#config.nativeRuntimeVersion !== undefined) {
      result.native_runtime_version = this.#config.nativeRuntimeVersion;
    }
    if (
      !validateCapabilityResult("provider.initialize", result) ||
      !validateProviderNegotiation(request, result)
    ) {
      throw protocolError("invalid_argument");
    }
    return {
      result: result as unknown as JSONObject,
      notifications: [],
      afterWrite: () => {
        this.#maximumMessageBytes = maximumMessageBytes;
        this.#maximumChunkBytes = maximumChunkBytes;
        this.#replaySupported = result.replay_supported;
        this.#initialized = true;
        this.#initializingRequestId = undefined;
      },
      rollback: () => this.#abortInitialization(requestId),
    };
  }

  async #executeMutation(
    capability: CapabilityName,
    command: Command,
    requestId: string,
    requestSignal: AbortSignal,
    connectionId: string,
    rawCommand: Uint8Array,
  ): Promise<ResponsePlan> {
    const descriptor = this.#capabilities.get(capability);
    if (
      descriptor?.mutating !== true ||
      !validateProtocolDocument("command", command) ||
      command.capability !== capability ||
      command.delivery_class !== descriptor.delivery_class
    ) {
      throw protocolError("invalid_argument");
    }
    const extension = isExtensionCapability(capability);
    if (extension) {
      if (!validateExtensionValue(command.payload)) throw protocolError("invalid_argument");
    } else if (!isJSONObject(command.payload)) {
      throw protocolError("invalid_argument");
    }
    if (!extension) {
      const corePayload = command.payload as JSONObject;
      this.#validateReplayRequest(capability, corePayload);
      if (
        capability === "terminal.send_input" &&
        terminalDataLength(corePayload) > this.#maximumChunkBytes
      ) {
        throw protocolError("message_too_large");
      }
    }
    const deadline = Date.parse(command.deadline);
    if (!Number.isFinite(deadline) || deadline <= Date.now()) {
      throw protocolError("deadline_exceeded");
    }
    const digest = createHash("sha256").update(rawCommand).digest("hex");
    const scopedConnection = capability === "terminal.attach" ? connectionId : undefined;
    const key = scopedConnection === undefined
      ? `${capability}\0${command.idempotency_key}`
      : `${capability}\0${scopedConnection}\0${command.idempotency_key}`;
    const prior = this.#idempotency.get(key);
    if (prior !== undefined) {
      if (prior.digest !== digest || prior.commandId !== command.command_id) {
        throw protocolError("conflict");
      }
      const operation = new AbortController();
      const cancelled = (): void => operation.abort();
      requestSignal.addEventListener("abort", cancelled, { once: true });
      if (requestSignal.aborted) operation.abort();
      const cancelDeadline = scheduleDeadline(deadline, operation);
      let cleaned = false;
      const cleanup = (): void => {
        if (cleaned) return;
        cleaned = true;
        cancelDeadline();
        requestSignal.removeEventListener("abort", cancelled);
      };
      try {
        await raceWithSignal(prior.completion, operation.signal);
        if (operation.signal.aborted || Date.now() >= deadline) {
          throw protocolError(Date.now() >= deadline ? "deadline_exceeded" : "cancelled");
        }
        const plan = mutationRecordPlan(prior);
        const priorAfterWrite = plan.afterWrite;
        const priorRollback = plan.rollback;
        return {
          ...plan,
          responseSignal: operation.signal,
          responseDeadline: deadline,
          afterWrite: () => {
            try {
              priorAfterWrite?.();
            } finally {
              cleanup();
            }
          },
          rollback: () => {
            try {
              priorRollback?.();
            } finally {
              cleanup();
            }
          },
        };
      } catch (error) {
        cleanup();
        if (operation.signal.aborted) {
          throw protocolError(Date.now() >= deadline ? "deadline_exceeded" : "cancelled");
        }
        throw error;
      }
    }
    const reservation = isSubscriptionCapability(capability) && isJSONObject(command.payload)
      ? this.#reserveSubscription(capability, command.payload, requestSignal)
      : undefined;
    if (this.#commandIds.has(command.command_id)) {
      if (reservation !== undefined) this.#releaseSubscription(reservation);
      throw protocolError("conflict");
    }
    if (this.#idempotency.size >= this.#limits.maximumIdempotencyEntries) {
      if (reservation !== undefined) this.#releaseSubscription(reservation);
      throw protocolError("resource_exhausted");
    }
    if (
      this.#limits.maximumMessageBytes >
      this.#limits.maximumIdempotencyBytes - this.#idempotencyBytes
    ) {
      if (reservation !== undefined) this.#releaseSubscription(reservation);
      throw protocolError("resource_exhausted");
    }
    const record = createMutationRecord(
      digest,
      command.command_id,
      this.#limits.maximumMessageBytes,
      scopedConnection,
    );
    this.#idempotency.set(key, record);
    this.#commandIds.set(command.command_id, record);
    this.#idempotencyBytes += record.reservedBytes;

    const operation = new AbortController();
    const cancelled = (): void => operation.abort();
    requestSignal.addEventListener("abort", cancelled, { once: true });
    if (requestSignal.aborted) operation.abort();
    const cancelDeadline = scheduleDeadline(deadline, operation);
    let handedOff = false;
    const cleanup = (): void => {
      cancelDeadline();
      requestSignal.removeEventListener("abort", cancelled);
    };
    try {
      const value = await this.#invoke(
        capability,
        command.payload,
        requestId,
        operation.signal,
        command,
        reservation?.lifetime.signal,
      );
      if (operation.signal.aborted || Date.now() >= deadline) {
        this.#finishMutation(record, "outcome_unknown");
        throw protocolError("outcome_unknown");
      }
      let plan: ResponsePlan;
      try {
        plan = this.#validateHandlerResult(capability, value, true, command.payload);
        if (operation.signal.aborted || Date.now() >= deadline) {
          this.#finishMutation(record, "outcome_unknown");
          throw protocolError("outcome_unknown");
        }
        if (reservation !== undefined) plan = this.#prepareSubscription(plan, reservation);
        if (
          (capability === "events.unsubscribe" || capability === "terminal.detach") &&
          isJSONObject(command.payload) &&
          typeof command.payload.subscription_id === "string"
        ) {
          plan = { ...plan, cancelSubscriptionId: command.payload.subscription_id };
        }
        if (capability === "provider.shutdown") plan = { ...plan, shutdown: true };
      } catch {
        this.#finishMutation(record, "outcome_unknown");
        throw protocolError("outcome_unknown");
      }
      const priorAfterWrite = plan.afterWrite;
      const priorRollback = plan.rollback;
      handedOff = true;
      return {
        ...plan,
        responseSignal: operation.signal,
        responseDeadline: deadline,
        responseFailureAmbiguous: true,
        afterWrite: () => {
          try {
            if (operation.signal.aborted || Date.now() >= deadline) {
              priorRollback?.();
              this.#finishMutation(record, "outcome_unknown");
              throw protocolError("outcome_unknown");
            }
            priorAfterWrite?.();
            this.#finishMutation(record, "succeeded", plan.result);
          } finally {
            cleanup();
          }
        },
        rollback: () => {
          try {
            priorRollback?.();
            this.#finishMutation(record, "outcome_unknown");
          } finally {
            cleanup();
          }
        },
      };
    } catch (error) {
      if (!handedOff && reservation !== undefined) this.#releaseSubscription(reservation);
      if (record.status === "outcome_unknown") throw protocolError("outcome_unknown");
      const normalized = operation.signal.aborted
        ? protocolError(Date.now() >= deadline ? "deadline_exceeded" : "cancelled")
        : normalizeError(error);
      this.#failMutation(record, normalized);
      throw normalized;
    } finally {
      if (!handedOff) cleanup();
    }
  }

  async #invoke(
    capability: CapabilityName,
    parameter: JSONValue,
    requestId: string,
    signal: AbortSignal,
    command?: Command,
    subscriptionSignal?: AbortSignal,
  ): Promise<unknown> {
    const handler = this.#handlers[capability];
    if (handler === undefined) throw protocolError("not_supported", capability, this.#advertisedCapabilities());
    if (signal.aborted) throw protocolError("cancelled");
    return handler(parameter, {
      capability,
      requestId,
      signal,
      ...(command === undefined ? {} : { command }),
      ...(subscriptionSignal === undefined ? {} : { subscriptionSignal }),
    });
  }

  #validateHandlerResult(
    capability: CapabilityName,
    value: unknown,
    mutated: boolean,
    request: JSONValue,
  ): ResponsePlan {
    const subscription = isProviderSubscription(value) ? value : undefined;
    if (isSubscriptionCapability(capability) !== (subscription !== undefined)) {
      throw protocolError(mutated ? "outcome_unknown" : "unavailable");
    }
    const result = subscription?.result ?? value;
    if (!validateCapabilityResult(capability, result)) {
      throw protocolError(mutated ? "outcome_unknown" : "unavailable");
    }
    let resultSnapshot: JSONValue;
    try {
      resultSnapshot = snapshotJSON(result);
    } catch {
      throw protocolError(mutated ? "outcome_unknown" : "unavailable");
    }
    if (!validateCapabilityResult(capability, resultSnapshot)) {
      throw protocolError(mutated ? "outcome_unknown" : "unavailable");
    }
    if (isJSONObject(request) && isJSONObject(resultSnapshot)) {
      this.#validateCorrelatedResult(capability, request, resultSnapshot);
    }
    if (
      subscription?.notifications !== undefined &&
      subscription.replay !== undefined
    ) {
      throw protocolError(mutated ? "outcome_unknown" : "unavailable");
    }
    const notifications = (subscription?.replay ?? subscription?.notifications ?? []).map((notification) => ({
      method: notification.method,
      params: snapshotJSONObject(notification.params),
    }));
    for (const notification of notifications) this.#validateNotification(notification);
    if (isJSONObject(request)) {
      this.#validateSubscriptionNotifications(capability, request, notifications);
    }
    return {
      result: resultSnapshot,
      notifications,
      ...(subscription?.stream === undefined ? {} : { stream: subscription.stream }),
    };
  }

  #reserveSubscription(
    capability: CapabilityName,
    request: JSONObject,
    setupSignal: AbortSignal,
  ): SubscriptionReservation {
    if (this.#subscriptionCount >= this.#limits.maximumSubscriptions) {
      throw protocolError("resource_exhausted");
    }
    const lifetime = new AbortController();
    const setupAbort = (): void => lifetime.abort();
    setupSignal.addEventListener("abort", setupAbort, { once: true });
    if (setupSignal.aborted) lifetime.abort();
    let terminalKey: string | undefined;
    let terminal: TerminalLedger | undefined;
    if (capability === "terminal.subscribe" || capability === "terminal.attach") {
      const nativeSessionId = request.native_session_id as string;
      const streamId = request.stream_id as string;
      terminalKey = terminalStreamKey(nativeSessionId, streamId);
      if (this.#terminalSubscriptions.has(terminalKey)) {
        setupSignal.removeEventListener("abort", setupAbort);
        throw protocolError("conflict");
      }
      terminal = {
        nativeSessionId,
        streamId,
        window: request.window_bytes as number,
        remaining: request.window_bytes as number,
        throughOffset: request.after_offset as number,
        sequence: 0,
        wake: new Set(),
      };
    }
    const reservation: SubscriptionReservation = {
      capability,
      request,
      lifetime,
      setupSignal,
      setupAbort,
      ...(terminalKey === undefined ? {} : { terminalKey }),
      ...(terminal === undefined ? {} : { terminal }),
      committed: false,
      released: false,
    };
    this.#subscriptionCount += 1;
    if (terminalKey !== undefined) this.#terminalSubscriptions.set(terminalKey, reservation);
    return reservation;
  }

  #prepareSubscription(
    plan: ResponsePlan,
    reservation: SubscriptionReservation,
  ): ResponsePlan {
    if (!isJSONObject(plan.result) || typeof plan.result.subscription_id !== "string") {
      this.#releaseSubscription(reservation);
      throw protocolError("invalid_argument");
    }
    const subscriptionId = plan.result.subscription_id;
    if (this.#subscriptions.has(subscriptionId)) {
      this.#releaseSubscription(reservation);
      throw protocolError("conflict");
    }
    reservation.subscriptionId = subscriptionId;
    if (plan.stream !== undefined) reservation.stream = plan.stream;
    this.#subscriptions.set(subscriptionId, reservation);
    const priorAfterWrite = plan.afterWrite;
    const priorRollback = plan.rollback;
    return {
      ...plan,
      subscription: reservation,
      afterWrite: () => {
        priorAfterWrite?.();
        reservation.setupSignal.removeEventListener("abort", reservation.setupAbort);
        reservation.committed = true;
      },
      rollback: () => {
        priorRollback?.();
        this.#releaseSubscription(reservation);
      },
    };
  }

  async #consumeTerminalNotification(
    reservation: SubscriptionReservation,
    notification: ProviderServerNotification,
  ): Promise<void> {
    this.#validateSubscriptionNotificationKind(reservation.capability, notification);
    const terminal = reservation.terminal;
    if (terminal === undefined) return;
    const chunk = notification.params;
    const size = terminalDataLength(chunk);
    if (size > terminal.window) throw protocolError("resource_exhausted");
    while (size > terminal.remaining) {
      await waitForTerminalCredit(terminal, reservation.lifetime.signal);
    }
    if (
      chunk.native_session_id !== terminal.nativeSessionId ||
      chunk.stream_id !== terminal.streamId ||
      (chunk.replayed === true && !this.#replaySupported)
    ) {
      throw protocolError("invalid_argument");
    }
    if (chunk.offset !== terminal.throughOffset) {
      if (
        chunk.truncated !== true ||
        typeof chunk.offset !== "number" ||
        chunk.offset < terminal.throughOffset
      ) {
        throw protocolError("sequence_conflict");
      }
      terminal.throughOffset = chunk.offset;
    }
    if (
      terminal.sequence !== 0 &&
      chunk.sequence !== terminal.sequence + 1 &&
      chunk.truncated !== true
    ) {
      throw protocolError("sequence_conflict");
    }
    terminal.remaining -= size;
    terminal.throughOffset += size;
    terminal.sequence = chunk.sequence as number;
    if (chunk.credit_remaining !== terminal.remaining) throw protocolError("invalid_argument");
  }

  #startSubscriptionStream(
    reservation: SubscriptionReservation,
    writer: ServerFrameWriter,
    failConnection: () => void,
  ): void {
    const stream = reservation.stream;
    if (stream === undefined) {
      this.#releaseSubscription(reservation);
      return;
    }
    const task = (async (): Promise<void> => {
      try {
        const iterator = stream[Symbol.asyncIterator]();
        reservation.iterator = iterator;
        while (!reservation.lifetime.signal.aborted) {
          if (reservation.terminal?.remaining === 0) {
            await waitForTerminalCredit(reservation.terminal, reservation.lifetime.signal);
          }
          const next = await nextWithAbort(iterator, reservation.lifetime.signal);
          if (next.done) return;
          const notification: ProviderServerNotification = {
            method: next.value.method,
            params: snapshotJSONObject(next.value.params),
          };
          this.#validateNotification(notification);
          await this.#consumeTerminalNotification(reservation, notification);
          await this.#writeNotification(writer, notification, reservation.lifetime.signal);
        }
      } catch (error) {
        if (!reservation.lifetime.signal.aborted) {
          failConnection();
          throw normalizeError(error);
        }
      } finally {
        this.#releaseSubscription(reservation);
      }
    })();
    this.#streamTasks.add(task);
    void task.finally(() => this.#streamTasks.delete(task)).catch(() => undefined);
  }

  #validateSubscriptionNotificationKind(
    capability: CapabilityName,
    notification: ProviderServerNotification,
  ): void {
    const expected = capability === "events.subscribe"
      ? "$mc/event"
      : capability === "topology.subscribe"
        ? "$mc/topology.snapshot"
        : "$mc/terminal.chunk";
    if (notification.method !== expected) throw protocolError("invalid_argument");
  }

  #applyTerminalCredit(value: JSONObject): void {
    const key = terminalStreamKey(
      value.native_session_id as string,
      value.stream_id as string,
    );
    const reservation = this.#terminalSubscriptions.get(key);
    const terminal = reservation?.terminal;
    if (reservation === undefined || terminal === undefined || !reservation.committed) {
      throw protocolError("invalid_argument");
    }
    if (
      value.through_offset !== terminal.throughOffset ||
      typeof value.bytes !== "number" ||
      value.bytes > terminal.window - terminal.remaining
    ) {
      throw protocolError("invalid_argument");
    }
    terminal.remaining += value.bytes;
    for (const wake of terminal.wake) wake();
    terminal.wake.clear();
  }

  #cancelSubscription(subscriptionId: string): void {
    const reservation = this.#subscriptions.get(subscriptionId);
    if (reservation !== undefined) this.#releaseSubscription(reservation);
  }

  #releaseSubscription(reservation: SubscriptionReservation): void {
    if (reservation.released) return;
    reservation.released = true;
    reservation.setupSignal.removeEventListener("abort", reservation.setupAbort);
    reservation.lifetime.abort();
    if (
      reservation.subscriptionId !== undefined &&
      this.#subscriptions.get(reservation.subscriptionId) === reservation
    ) {
      this.#subscriptions.delete(reservation.subscriptionId);
    }
    if (
      reservation.terminalKey !== undefined &&
      this.#terminalSubscriptions.get(reservation.terminalKey) === reservation
    ) {
      this.#terminalSubscriptions.delete(reservation.terminalKey);
    }
    for (const wake of reservation.terminal?.wake ?? []) wake();
    reservation.terminal?.wake.clear();
    try {
      const iteratorReturn = reservation.iterator?.return;
      if (iteratorReturn !== undefined) {
        void Promise.resolve(iteratorReturn.call(reservation.iterator)).catch(() => undefined);
      }
    } catch {
      // Iterator cleanup is best-effort and cannot block server teardown.
    }
    if (this.#subscriptionCount > 0) this.#subscriptionCount -= 1;
  }

  #releaseAllSubscriptions(): void {
    const subscriptions = new Set([
      ...this.#subscriptions.values(),
      ...this.#terminalSubscriptions.values(),
    ]);
    for (const reservation of subscriptions) this.#releaseSubscription(reservation);
  }

  #validateCorrelatedResult(
    capability: CapabilityName,
    request: JSONObject,
    result: JSONObject,
  ): void {
    if (capability !== "terminal.read") return;
    if (
      result.native_session_id !== request.native_session_id ||
      result.stream_id !== request.stream_id ||
      (result.replayed === true && !this.#replaySupported)
    ) {
      throw protocolError("invalid_argument");
    }
    const size = terminalDataLength(result);
    if (
      size > this.#maximumChunkBytes ||
      typeof request.maximum_bytes !== "number" ||
      size > request.maximum_bytes
    ) {
      throw protocolError("message_too_large");
    }
    if (
      result.offset !== request.after_offset &&
      (result.truncated !== true ||
        typeof result.offset !== "number" ||
        typeof request.after_offset !== "number" ||
        result.offset < request.after_offset)
    ) {
      throw protocolError("sequence_conflict");
    }
  }

  #validateNotification(notification: ProviderServerNotification): void {
    if (
      !validWireToken(notification.method) ||
      !isJSONObject(notification.params) ||
      !validateNotification(notification.method, notification.params)
    ) {
      throw protocolError("invalid_argument");
    }
    if (notification.method === "$mc/terminal.chunk") {
      if (!validateCapabilityResult("terminal.read", notification.params)) {
        throw protocolError("invalid_argument");
      }
      const byteLength = terminalDataLength(notification.params);
      if (byteLength < 1 || byteLength > this.#maximumChunkBytes) {
        throw protocolError("message_too_large");
      }
    }
  }

  #validateReplayRequest(capability: CapabilityName, request: JSONObject): void {
    if (this.#replaySupported) return;
    if (
      (capability === "terminal.read" ||
        capability === "terminal.subscribe" ||
        capability === "terminal.attach") &&
      typeof request.after_offset === "number" &&
      request.after_offset > 0
    ) {
      throw protocolError("invalid_argument");
    }
    if (capability === "events.subscribe" && Array.isArray(request.cursors)) {
      for (const cursor of request.cursors) {
        if (
          isJSONObject(cursor) &&
          typeof cursor.after_sequence === "number" &&
          cursor.after_sequence > 0
        ) {
          throw protocolError("invalid_argument");
        }
      }
    }
  }

  #validateSubscriptionNotifications(
    capability: CapabilityName,
    request: JSONObject,
    notifications: readonly ProviderServerNotification[],
  ): void {
    if (!isSubscriptionCapability(capability)) return;
    for (const notification of notifications) {
      this.#validateSubscriptionNotificationKind(capability, notification);
    }
    if (capability !== "terminal.subscribe" && capability !== "terminal.attach") return;
    let throughOffset = request.after_offset as number;
    let sequence = 0;
    for (const notification of notifications) {
      const chunk = notification.params;
      if (
        chunk.native_session_id !== request.native_session_id ||
        chunk.stream_id !== request.stream_id ||
        (chunk.replayed === true && !this.#replaySupported)
      ) {
        throw protocolError("invalid_argument");
      }
      const size = terminalDataLength(chunk);
      if (size > (request.window_bytes as number)) throw protocolError("resource_exhausted");
      if (chunk.offset !== throughOffset) {
        if (chunk.truncated !== true || typeof chunk.offset !== "number" || chunk.offset < throughOffset) {
          throw protocolError("sequence_conflict");
        }
        throughOffset = chunk.offset;
      }
      if (
        sequence !== 0 &&
        chunk.sequence !== sequence + 1 &&
        chunk.truncated !== true
      ) {
        throw protocolError("sequence_conflict");
      }
      throughOffset += size;
      sequence = chunk.sequence as number;
    }
  }

  #handleNotification(request: RPCRequest): void {
    const parameter = request.params[0];
    if (!validateNotification(request.method, parameter)) {
      if (
        request.method === NOTIFICATION_CANCEL ||
        request.method === NOTIFICATION_HEARTBEAT ||
        request.method === NOTIFICATION_TERMINAL_CREDIT
      ) {
        throw protocolError("invalid_argument");
      }
      throw notSupported(request.method as CapabilityName, this.#advertisedCapabilities());
    }
    switch (request.method) {
      case NOTIFICATION_CANCEL: {
        this.#active.get(parameter.request_id as string)?.abort();
        return;
      }
      case NOTIFICATION_HEARTBEAT:
        return;
      case NOTIFICATION_TERMINAL_CREDIT:
        this.#applyTerminalCredit(parameter);
        return;
      default:
        throw notSupported(request.method as CapabilityName, this.#advertisedCapabilities());
    }
  }

  async #heartbeatLoop(writer: ServerFrameWriter, signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      await abortableDelay(this.#limits.heartbeatIntervalMs, signal);
      if (signal.aborted || !this.#initialized) continue;
      try {
        await this.#writeNotification(
          writer,
          { method: NOTIFICATION_HEARTBEAT, params: { observed_at: new Date().toISOString() } },
          signal,
        );
      } catch (error) {
        if (signal.aborted) return;
        if (isProtocolError(error, "resource_exhausted")) continue;
        throw error;
      }
    }
  }

  async #writeResult(
    writer: ServerFrameWriter,
    id: string,
    result: JSONValue,
    signal?: AbortSignal,
  ): Promise<void> {
    await writer.write(
      encodeFrame({ jsonrpc: JSON_RPC_VERSION, id, result }, this.#maximumMessageBytes),
      signal,
    );
  }

  async #writeError(writer: ServerFrameWriter, id: string, error: ProtocolError): Promise<void> {
    await writer.write(
      encodeFrame(
        {
          jsonrpc: JSON_RPC_VERSION,
          id,
          error: {
            code: jsonRPCErrorCode(error),
            message: error.message,
            data: error.data,
          },
        },
        this.#maximumMessageBytes,
      ),
    );
  }

  async #writeNotification(
    writer: ServerFrameWriter,
    notification: ProviderServerNotification,
    signal?: AbortSignal,
  ): Promise<void> {
    await writer.write(
      encodeFrame(
        { jsonrpc: JSON_RPC_VERSION, method: notification.method, params: [notification.params] },
        this.#maximumMessageBytes,
      ),
      signal,
    );
  }

  #failMutation(record: MutationRecord, error: ProtocolError): void {
    this.#finishMutation(record, "failed", undefined, error);
  }

  #commandResult(request: JSONObject): JSONObject {
    const commandId = request.command_id as string;
    const record = this.#commandIds.get(commandId);
    if (record === undefined) throw protocolError("unavailable");
    const result: Record<string, JSONValue> = {
      command_id: commandId,
      status: record.status,
      observed_at: new Date().toISOString(),
    };
    if (record.status === "succeeded" && record.result !== undefined) {
      result.result = record.result;
    } else if (record.status === "failed" && record.error !== undefined) {
      result.error = record.error.data as unknown as JSONObject;
    }
    if (!validateCapabilityResult("command.get_result", result)) {
      throw protocolError("unavailable");
    }
    return result;
  }

  #finishMutation(
    record: MutationRecord,
    status: Exclude<MutationRecord["status"], "pending">,
    result?: JSONValue,
    error?: ProtocolError,
  ): void {
    if (record.status !== "pending") return;
    let retainedBytes = 0;
    if (status === "succeeded" && result !== undefined) {
      retainedBytes = Buffer.byteLength(JSON.stringify(result), "utf8");
      if (retainedBytes > record.reservedBytes) {
        status = "outcome_unknown";
        result = undefined;
        retainedBytes = 0;
      }
    }
    this.#idempotencyBytes -= record.reservedBytes - retainedBytes;
    record.reservedBytes = retainedBytes;
    record.status = status;
    record.result = result;
    record.error = error;
    record.resolve();
  }

  #abortInitialization(requestId: string): void {
    if (this.#initializingRequestId !== requestId) return;
    this.#initialized = false;
    this.#initializingRequestId = undefined;
    this.#maximumMessageBytes = this.#limits.maximumMessageBytes;
    this.#maximumChunkBytes = this.#limits.maximumChunkBytes;
    this.#replaySupported = false;
  }

  #abortConnectionInitialization(): void {
    this.#initialized = false;
    this.#initializingRequestId = undefined;
    this.#maximumMessageBytes = this.#limits.maximumMessageBytes;
    this.#maximumChunkBytes = this.#limits.maximumChunkBytes;
    this.#replaySupported = false;
    this.#active.clear();
  }

  #releaseConnectionMutations(connectionId: string): void {
    for (const [key, record] of this.#idempotency) {
      if (record.connectionId !== connectionId) continue;
      if (record.status === "pending") this.#finishMutation(record, "outcome_unknown");
      this.#idempotency.delete(key);
      if (this.#commandIds.get(record.commandId) === record) {
        this.#commandIds.delete(record.commandId);
      }
      this.#idempotencyBytes = Math.max(0, this.#idempotencyBytes - record.reservedBytes);
      record.reservedBytes = 0;
    }
  }

  #advertisedCapabilities(): CapabilityName[] {
    return [...this.#capabilities.keys()].sort() as CapabilityName[];
  }
}

function normalizeLimits(limits: ProviderServerLimits | undefined): ServerLimits {
  const normalized: ServerLimits = {
    maximumMessageBytes: limits?.maximumMessageBytes ?? MAX_MESSAGE_BYTES,
    maximumChunkBytes: limits?.maximumChunkBytes ?? MAX_TERMINAL_CHUNK_BYTES,
    maximumOutboundQueue: limits?.maximumOutboundQueue ?? 16,
    maximumInFlightRequests: limits?.maximumInFlightRequests ?? 64,
    maximumIdempotencyEntries: limits?.maximumIdempotencyEntries ?? 4096,
    maximumIdempotencyBytes: limits?.maximumIdempotencyBytes ?? 64 << 20,
    maximumSubscriptions: limits?.maximumSubscriptions ?? 256,
    shutdownTimeoutMs: limits?.shutdownTimeoutMs ?? 5000,
    heartbeatIntervalMs: limits?.heartbeatIntervalMs ?? 30000,
  };
  if (
    !validBound(normalized.maximumMessageBytes, 1, MAX_MESSAGE_BYTES) ||
    !validBound(normalized.maximumChunkBytes, 1, MAX_TERMINAL_CHUNK_BYTES) ||
    normalized.maximumChunkBytes > normalized.maximumMessageBytes ||
    !validBound(normalized.maximumOutboundQueue, 1, 4096) ||
    normalized.maximumOutboundQueue > Math.floor((256 << 20) / normalized.maximumMessageBytes) ||
    !validBound(normalized.maximumInFlightRequests, 1, 65536) ||
    normalized.maximumInFlightRequests > Math.floor((256 << 20) / normalized.maximumMessageBytes) ||
    !validBound(normalized.maximumIdempotencyEntries, 1, 1 << 20) ||
    !validBound(normalized.maximumIdempotencyBytes, normalized.maximumMessageBytes, 1 << 30) ||
    !validBound(normalized.maximumSubscriptions, 1, 65536) ||
    !validBound(normalized.shutdownTimeoutMs, 1, 300000) ||
    !validBound(normalized.heartbeatIntervalMs, 1, 300000)
  ) {
    throw protocolError("invalid_argument");
  }
  return normalized;
}

function decodeRequest(value: JSONObject, rawParameter: Uint8Array): RPCRequest {
  if (!hasOnlyKeys(value, ["jsonrpc", "id", "method", "params"])) {
    throw protocolError("invalid_argument");
  }
  if (value.jsonrpc !== JSON_RPC_VERSION || !validWireToken(value.method)) {
    throw protocolError("invalid_argument");
  }
  if (value.id !== undefined && !validWireToken(value.id)) {
    throw protocolError("invalid_argument");
  }
  if (!Array.isArray(value.params) || value.params.length !== 1 || !isJSONObject(value.params[0])) {
    throw protocolError("invalid_argument");
  }
  return { ...(value as Omit<RPCRequest, "rawParameter">), rawParameter };
}

function extractSingleParameter(frame: Uint8Array): Uint8Array {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(frame);
  } catch {
    throw protocolError("invalid_argument");
  }
  let index = skipJSONWhitespace(text, 0);
  if (text[index] !== "{") throw protocolError("invalid_argument");
  index += 1;
  let parameter: string | undefined;
  while (true) {
    index = skipJSONWhitespace(text, index);
    if (text[index] === "}") break;
    if (text[index] !== '"') throw protocolError("invalid_argument");
    const keyEnd = scanJSONString(text, index);
    const key = JSON.parse(text.slice(index, keyEnd)) as unknown;
    index = skipJSONWhitespace(text, keyEnd);
    if (text[index] !== ":") throw protocolError("invalid_argument");
    index = skipJSONWhitespace(text, index + 1);
    if (key === "params") {
      if (text[index] !== "[") throw protocolError("invalid_argument");
      const valueStart = skipJSONWhitespace(text, index + 1);
      const valueEnd = scanJSONValue(text, valueStart);
      let arrayEnd = skipJSONWhitespace(text, valueEnd);
      if (text[arrayEnd] !== "]") throw protocolError("invalid_argument");
      arrayEnd += 1;
      parameter = text.slice(valueStart, valueEnd);
      index = arrayEnd;
    } else {
      index = scanJSONValue(text, index);
    }
    index = skipJSONWhitespace(text, index);
    if (text[index] === ",") {
      index += 1;
      continue;
    }
    if (text[index] === "}") break;
    throw protocolError("invalid_argument");
  }
  if (parameter === undefined) throw protocolError("invalid_argument");
  return Buffer.from(parameter, "utf8");
}

function scanJSONValue(text: string, start: number): number {
  const character = text[start];
  if (character === '"') return scanJSONString(text, start);
  if (character === "{") return scanJSONContainer(text, start, "}");
  if (character === "[") return scanJSONContainer(text, start, "]");
  let index = start;
  while (index < text.length && !/[\s,}\]]/.test(text[index] ?? "")) index += 1;
  if (index === start) throw protocolError("invalid_argument");
  return index;
}

function scanJSONContainer(text: string, start: number, closing: "}" | "]"): number {
  const opening = text[start];
  let index = start + 1;
  while (true) {
    index = skipJSONWhitespace(text, index);
    if (text[index] === closing) return index + 1;
    if (opening === "{") {
      if (text[index] !== '"') throw protocolError("invalid_argument");
      index = skipJSONWhitespace(text, scanJSONString(text, index));
      if (text[index] !== ":") throw protocolError("invalid_argument");
      index = skipJSONWhitespace(text, index + 1);
    }
    index = scanJSONValue(text, index);
    index = skipJSONWhitespace(text, index);
    if (text[index] === ",") {
      index += 1;
      continue;
    }
    if (text[index] === closing) return index + 1;
    throw protocolError("invalid_argument");
  }
}

function scanJSONString(text: string, start: number): number {
  let escaped = false;
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') return index + 1;
  }
  throw protocolError("invalid_argument");
}

function skipJSONWhitespace(text: string, start: number): number {
  let index = start;
  while (index < text.length && /[\t\n\r ]/.test(text[index] ?? "")) index += 1;
  return index;
}

function normalizeError(value: unknown): ProtocolError {
  if (isProtocolError(value)) return value;
  if (value instanceof DOMException && value.name === "AbortError") return protocolError("cancelled");
  return protocolError("unavailable");
}

function responseExpiryError(plan: ResponsePlan | undefined): ProtocolError | undefined {
  if (
    plan?.responseDeadline === undefined ||
    (plan.responseSignal?.aborted !== true && Date.now() < plan.responseDeadline)
  ) {
    return undefined;
  }
  if (plan.responseFailureAmbiguous === true) return protocolError("outcome_unknown");
  return protocolError(Date.now() >= plan.responseDeadline ? "deadline_exceeded" : "cancelled");
}

function jsonRPCErrorCode(error: ProtocolError): number {
  if (error.code === "not_supported") return -32601;
  if (error.code === "invalid_argument" || error.code === "message_too_large") return -32602;
  return -32000;
}

function createMutationRecord(
  digest: string,
  commandId: string,
  reservedBytes: number,
  connectionId: string | undefined,
): MutationRecord {
  let resolve = (): void => undefined;
  const completion = new Promise<void>((done) => {
    resolve = done;
  });
  return {
    digest,
    commandId,
    completion,
    resolve,
    status: "pending",
    reservedBytes,
    result: undefined,
    error: undefined,
    connectionId,
  };
}

function mutationRecordPlan(record: MutationRecord): ResponsePlan {
  switch (record.status) {
    case "succeeded":
      if (record.result === undefined) throw protocolError("unavailable");
      return { result: record.result, notifications: [] };
    case "failed":
      throw record.error ?? protocolError("unavailable");
    case "outcome_unknown":
      throw protocolError("outcome_unknown");
    default:
      throw protocolError("unavailable");
  }
}

function isProviderSubscription(value: unknown): value is ProviderSubscription {
  if (
    !isJSONObject(value) ||
    !providerSubscriptions.has(value) ||
    !Object.hasOwn(value, "result") ||
    value.result === null
  ) {
    return false;
  }
  for (const field of ["notifications", "replay"] as const) {
    const notifications = value[field];
    if (
      notifications !== undefined &&
      (!Array.isArray(notifications) ||
        !notifications.every(
          (item) =>
            isJSONObject(item) &&
            validWireToken(item.method) &&
            isJSONObject(item.params),
        ))
    ) {
      return false;
    }
  }
  return value.stream === undefined || isAsyncIterable(value.stream);
}

function isAsyncIterable(value: unknown): value is AsyncIterable<ProviderServerNotification> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function"
  );
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

function snapshotJSONObject(value: unknown): JSONObject {
  const snapshot = snapshotJSON(value);
  if (!isJSONObject(snapshot)) throw protocolError("invalid_argument");
  return snapshot;
}

function terminalDataLength(value: JSONObject): number {
  if (typeof value.data !== "string") return -1;
  if (value.encoding === "utf-8") return Buffer.byteLength(value.data, "utf8");
  if (value.encoding !== "base64") return -1;
  try {
    const bytes = Buffer.from(value.data, "base64");
    return bytes.toString("base64") === value.data ? bytes.length : -1;
  } catch {
    return -1;
  }
}

function validTokenSet(values: readonly string[], minimum: number, maximum: number): boolean {
  return (
    values.length >= minimum &&
    values.length <= maximum &&
    new Set(values).size === values.length &&
    values.every((value) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value))
  );
}

function isExtensionCapability(value: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\/[a-z][a-z0-9._-]{0,127}$/.test(
    value,
  );
}

function isSubscriptionCapability(value: CapabilityName): boolean {
  return (
    value === "events.subscribe" ||
    value === "terminal.subscribe" ||
    value === "terminal.attach" ||
    value === "topology.subscribe"
  );
}

function terminalStreamKey(nativeSessionId: string, streamId: string): string {
  return `${nativeSessionId}\u0000${streamId}`;
}

async function waitForTerminalCredit(
  terminal: TerminalLedger,
  signal: AbortSignal,
): Promise<void> {
  if (signal.aborted) throw protocolError("cancelled");
  await new Promise<void>((resolve, reject) => {
    const wake = (): void => {
      signal.removeEventListener("abort", abort);
      terminal.wake.delete(wake);
      resolve();
    };
    const abort = (): void => {
      terminal.wake.delete(wake);
      reject(protocolError("cancelled"));
    };
    terminal.wake.add(wake);
    signal.addEventListener("abort", abort, { once: true });
  });
}

async function nextWithAbort<Value>(
  iterator: AsyncIterator<Value>,
  signal: AbortSignal,
): Promise<IteratorResult<Value>> {
  if (signal.aborted) throw protocolError("cancelled");
  return new Promise<IteratorResult<Value>>((resolve, reject) => {
    const abort = (): void => reject(protocolError("cancelled"));
    signal.addEventListener("abort", abort, { once: true });
    void iterator.next().then(
      (result) => {
        signal.removeEventListener("abort", abort);
        resolve(result);
      },
      () => {
        signal.removeEventListener("abort", abort);
        reject(protocolError("unavailable"));
      },
    );
  });
}

function validWireToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 256 &&
    /^[\x21-\x7e]+$/.test(value)
  );
}

function validBound(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}

function isJSONObject(value: unknown): value is JSONObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: JSONObject, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

async function raceWithSignal(promise: Promise<void>, signal: AbortSignal): Promise<void> {
  if (signal.aborted) throw protocolError("cancelled");
  await new Promise<void>((resolve, reject) => {
    const abort = (): void => reject(protocolError("cancelled"));
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      () => {
        signal.removeEventListener("abort", abort);
        resolve();
      },
      () => {
        signal.removeEventListener("abort", abort);
        reject(protocolError("unavailable"));
      },
    );
  });
}

async function settleWithin(
  promises: readonly Promise<unknown>[],
  milliseconds: number,
): Promise<boolean> {
  if (promises.length === 0) return true;
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      Promise.allSettled(promises).then(() => true),
      new Promise<false>((resolve) => {
        timer = setTimeout(() => resolve(false), milliseconds);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function scheduleDeadline(deadline: number, controller: AbortController): () => void {
  let timer: NodeJS.Timeout | undefined;
  const arm = (): void => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      controller.abort();
      return;
    }
    timer = setTimeout(arm, Math.min(remaining, 2_147_483_647));
  };
  arm();
  return () => {
    if (timer !== undefined) clearTimeout(timer);
  };
}

async function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(done, milliseconds);
    const aborted = (): void => done();
    function done(): void {
      clearTimeout(timer);
      signal.removeEventListener("abort", aborted);
      resolve();
    }
    signal.addEventListener("abort", aborted, { once: true });
  });
}
