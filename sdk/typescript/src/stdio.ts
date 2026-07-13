import { stdin, stdout } from "node:process";
import type { Readable, Writable } from "node:stream";

import { isProtocolError, protocolError } from "./errors.js";
import { MAX_MESSAGE_BYTES, parseProtocolJSON, type JSONObject } from "./types.js";

const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;

export interface ProtocolTransport {
  readonly readable: Readable;
  readonly writable: Writable;
  close?(): void | Promise<void>;
}

/** Returns the non-owning process transport. Protocol data is written only to stdout. */
export function createStdioTransport(
  readable: Readable = stdin,
  writable: Writable = stdout,
): ProtocolTransport {
  return Object.freeze({ readable, writable });
}

export type FrameLimit = number | (() => number);

/** Reads strict, LF-only, bounded NDJSON frames without decoding their contents. */
export async function* readFrames(
  readable: Readable,
  maximumBytes: FrameLimit,
  signal?: AbortSignal,
): AsyncGenerator<Uint8Array, void, void> {
  const iterator = readable[Symbol.asyncIterator]();
  const fragments: Buffer[] = [];
  let length = 0;
  try {
    while (true) {
      const next = await nextWithAbort(iterator, signal);
      if (next.done) break;
      const chunk = toBuffer(next.value);
      let start = 0;
      for (let index = 0; index < chunk.length; index += 1) {
        const byte = chunk[index];
        if (byte === CARRIAGE_RETURN) throw protocolError("invalid_argument");
        if (byte !== LINE_FEED) continue;

        appendFragment(fragments, chunk.subarray(start, index), length, currentLimit(maximumBytes));
        length += index - start;
        if (length === 0) throw protocolError("invalid_argument");
        yield Buffer.concat(fragments, length);
        fragments.length = 0;
        length = 0;
        start = index + 1;
      }
      const tail = chunk.subarray(start);
      appendFragment(fragments, tail, length, currentLimit(maximumBytes));
      length += tail.length;
    }
    if (length !== 0) throw protocolError("invalid_argument");
  } catch (error) {
    if (isProtocolError(error)) throw error;
    if (signal?.aborted === true) throw protocolError("cancelled");
    throw protocolError("unavailable");
  } finally {
    if (signal?.aborted === true && iterator.return !== undefined) {
      void Promise.resolve(iterator.return()).catch(() => undefined);
    }
  }
}

/** Decodes a frame and rejects invalid UTF-8, duplicate keys, null, arrays, and primitives. */
export function decodeFrame(frame: Uint8Array): JSONObject {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(frame);
  } catch {
    throw protocolError("invalid_argument");
  }
  if (text.length === 0 || text.includes("\n") || text.includes("\r")) {
    throw protocolError("invalid_argument");
  }
  const value = parseProtocolJSON(text);
  if (!isJSONObject(value)) throw protocolError("invalid_argument");
  return value;
}

/** Encodes one bounded JSON object without its NDJSON delimiter. */
export function encodeFrame(value: unknown, maximumBytes: number): Uint8Array {
  assertMaximum(maximumBytes);
  if (!isJSONObject(value) || !isStrictJSONValue(value, new WeakSet())) {
    throw protocolError("invalid_argument");
  }
  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch {
    throw protocolError("invalid_argument");
  }
  if (text === undefined || text.includes("\n") || text.includes("\r")) {
    throw protocolError("invalid_argument");
  }
  const encoded = Buffer.from(text, "utf8");
  if (encoded.length > maximumBytes) throw protocolError("message_too_large");
  return encoded;
}

type WriteJob = {
  readonly frame: Uint8Array;
  signal?: AbortSignal;
  readonly resolve: () => void;
  readonly reject: (error: unknown) => void;
  settled: boolean;
  abort?: () => void;
};

/** A single-owner, bounded, serialized NDJSON writer. */
export class FrameWriter {
  readonly #writable: Writable;
  readonly #maximumQueue: number;
  readonly #activeAbort: (() => void) | undefined;
  readonly #queue: WriteJob[] = [];
  #maximumBytes: number;
  #active: WriteJob | undefined;
  #closed = false;
  readonly #transportError = (): void => this.#fail(protocolError("unavailable"));

  constructor(
    writable: Writable,
    maximumBytes: number,
    maximumQueue: number,
    activeAbort?: () => void,
  ) {
    assertMaximum(maximumBytes);
    if (!Number.isSafeInteger(maximumQueue) || maximumQueue < 1 || maximumQueue > 4096) {
      throw protocolError("invalid_argument");
    }
    if (maximumQueue > Math.floor((256 << 20) / maximumBytes)) {
      throw protocolError("invalid_argument");
    }
    if (activeAbort !== undefined && typeof activeAbort !== "function") {
      throw protocolError("invalid_argument");
    }
    this.#writable = writable;
    this.#maximumBytes = maximumBytes;
    this.#maximumQueue = maximumQueue;
    this.#activeAbort = activeAbort;
    this.#writable.on("error", this.#transportError);
  }

  setMaximumBytes(maximumBytes: number): void {
    assertMaximum(maximumBytes);
    if (this.#maximumQueue > Math.floor((256 << 20) / maximumBytes)) {
      throw protocolError("invalid_argument");
    }
    this.#maximumBytes = maximumBytes;
  }

  write(frame: Uint8Array, signal?: AbortSignal): Promise<void> {
    if (this.#closed) return Promise.reject(protocolError("unavailable"));
    if (signal?.aborted === true) return Promise.reject(protocolError("cancelled"));
    if (frame.length === 0 || frame.length > this.#maximumBytes) {
      return Promise.reject(protocolError(frame.length > this.#maximumBytes ? "message_too_large" : "invalid_argument"));
    }
    try {
      decodeFrame(frame);
    } catch (error) {
      return Promise.reject(error);
    }
    if (this.#queue.length + (this.#active === undefined ? 0 : 1) >= this.#maximumQueue) {
      return Promise.reject(protocolError("resource_exhausted"));
    }

    return new Promise<void>((resolve, reject) => {
      const job: WriteJob = { frame: Buffer.from(frame), resolve, reject, settled: false };
      if (signal !== undefined) {
        job.signal = signal;
        job.abort = () => this.#abort(job);
        signal.addEventListener("abort", job.abort, { once: true });
      }
      this.#queue.push(job);
      this.#pump();
    });
  }

  close(error: unknown = protocolError("unavailable")): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const job of this.#queue.splice(0)) this.#settle(job, error);
  }

  /** Fails queued and active writes when the underlying connection is no longer usable. */
  fail(error: unknown = protocolError("unavailable")): void {
    this.#fail(error);
  }

  #abort(job: WriteJob): void {
    if (job.settled) return;
    // Once Writable.write has started, only its callback can tell us whether
    // the bytes were published. Cancellation cannot safely rewrite history.
    if (this.#active === job) {
      try {
        this.#activeAbort?.();
      } catch {
        this.#fail(protocolError("unavailable"));
      }
      return;
    }
    const index = this.#queue.indexOf(job);
    if (index >= 0) this.#queue.splice(index, 1);
    this.#settle(job, protocolError("cancelled"));
  }

  #pump(): void {
    if (this.#active !== undefined || this.#closed) return;
    const job = this.#queue.shift();
    if (job === undefined) return;
    if (job.signal?.aborted === true) {
      this.#settle(job, protocolError("cancelled"));
      this.#pump();
      return;
    }
    this.#active = job;
    const wire = Buffer.allocUnsafe(job.frame.length + 1);
    wire.set(job.frame, 0);
    wire[job.frame.length] = LINE_FEED;
    try {
      this.#writable.write(wire, (error?: Error | null) => {
        this.#active = undefined;
        if (error !== undefined && error !== null) this.#settle(job, protocolError("unavailable"));
        else this.#settle(job);
        this.#pump();
      });
    } catch {
      this.#active = undefined;
      this.#fail(protocolError("unavailable"));
    }
  }

  #fail(error: unknown): void {
    this.#closed = true;
    for (const job of this.#queue.splice(0)) this.#settle(job, error);
    if (this.#active !== undefined) this.#settle(this.#active, error);
  }

  #settle(job: WriteJob, error?: unknown): void {
    if (job.abort !== undefined && job.signal !== undefined) {
      job.signal.removeEventListener("abort", job.abort);
    }
    if (job.settled) return;
    job.settled = true;
    if (error === undefined) job.resolve();
    else job.reject(error);
  }
}

function appendFragment(
  fragments: Buffer[],
  fragment: Buffer,
  priorLength: number,
  maximumBytes: number,
): void {
  if (fragment.length > maximumBytes - priorLength) throw protocolError("message_too_large");
  if (fragment.length !== 0) fragments.push(Buffer.from(fragment));
}

function currentLimit(source: FrameLimit): number {
  const maximum = typeof source === "function" ? source() : source;
  assertMaximum(maximum);
  return maximum;
}

function assertMaximum(maximumBytes: number): void {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > MAX_MESSAGE_BYTES) {
    throw protocolError("invalid_argument");
  }
}

function isJSONObject(value: unknown): value is JSONObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStrictJSONValue(value: unknown, ancestors: WeakSet<object>): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") {
    return Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
  }
  if (typeof value !== "object") return false;
  if (ancestors.has(value)) return false;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || "toJSON" in value) return false;
      if (Object.getOwnPropertySymbols(value).length !== 0) return false;
      if (Object.getOwnPropertyNames(value).length !== value.length + 1) return false;
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, index);
        if (
          descriptor === undefined ||
          descriptor.get !== undefined ||
          descriptor.set !== undefined ||
          !isStrictJSONValue(descriptor.value, ancestors)
        ) {
          return false;
        }
      }
      return Object.keys(value).every((key) => /^(?:0|[1-9]\d*)$/.test(key));
    }
    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) return false;
    if (Object.getOwnPropertySymbols(value).length !== 0) return false;
    const keys = Object.keys(value);
    if (Object.getOwnPropertyNames(value).length !== keys.length) return false;
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        descriptor.get !== undefined ||
        descriptor.set !== undefined ||
        !isStrictJSONValue(descriptor.value, ancestors)
      ) {
        return false;
      }
    }
    return true;
  } finally {
    ancestors.delete(value);
  }
}

function toBuffer(value: unknown): Buffer {
  if (typeof value === "string") return Buffer.from(value, "utf8");
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  throw protocolError("invalid_argument");
}

async function nextWithAbort(
  iterator: AsyncIterator<unknown>,
  signal: AbortSignal | undefined,
): Promise<IteratorResult<unknown>> {
  if (signal === undefined) return iterator.next();
  if (signal.aborted) throw protocolError("cancelled");
  return new Promise<IteratorResult<unknown>>((resolve, reject) => {
    const aborted = (): void => reject(protocolError("cancelled"));
    signal.addEventListener("abort", aborted, { once: true });
    void iterator.next().then(
      (value) => {
        signal.removeEventListener("abort", aborted);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", aborted);
        reject(error);
      },
    );
  });
}
