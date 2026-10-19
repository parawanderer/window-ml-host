// wmlhost-client.mjs — a dependency-free Node client for wmlhost's native messaging protocol (docs/PROTOCOL.md).

import { spawn } from "node:child_process";
import os from "node:os";

/** The largest message the host sends (`MAX_OUT`): Chrome's 1 MiB limit. */
export const MAX_OUT = 1024 * 1024;

const LE = os.endianness() === "LE";

/**
 * Encodes one JSON object as a native-messaging frame: a 4-byte native-endian length, then UTF-8 JSON.
 * @param {object} obj
 * @returns {Buffer}
 */
export function encodeFrame(obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const head = Buffer.alloc(4);
  if (LE) head.writeUInt32LE(body.length, 0);
  else head.writeUInt32BE(body.length, 0);
  return Buffer.concat([head, body]);
}

/** Reassembles native-messaging frames from arbitrary stdout chunks, whole or split. */
export class FrameDecoder {
  /** @param {number} [max] the largest accepted body, in bytes */
  constructor(max = MAX_OUT) {
    this.max = max;
    this.buf = Buffer.alloc(0);
  }

  /**
   * Feeds a chunk and returns every message completed by it. Throws on a length over the limit.
   * @param {Buffer} chunk
   * @returns {object[]}
   */
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out = [];
    for (;;) {
      if (this.buf.length < 4) break;
      const len = LE ? this.buf.readUInt32LE(0) : this.buf.readUInt32BE(0);
      if (len > this.max) throw new Error(`frame length ${len} exceeds limit ${this.max}`);
      if (this.buf.length < 4 + len) break;
      out.push(JSON.parse(this.buf.subarray(4, 4 + len).toString("utf8")));
      this.buf = this.buf.subarray(4 + len);
    }
    return out;
  }
}

/** Largest `length` the host accepts for one `read` (512 KiB). */
const READ_CHUNK = 524288;

/**
 * The call layer: sequence numbers, answers and `done` events, over any `{ send, onMessage }` transport.
 */
export class HostClient {
  /** @param {{ send(obj: object): void, onMessage(cb: (msg: object) => void): void }} transport */
  constructor(transport) {
    this.transport = transport;
    this.seq = 0;
    /** @type {Map<number, {resolve: Function, reject: Function}>} */
    this.pending = new Map();
    this.listeners = [];
    /** @type {Map<string, object>} */
    this.doneById = new Map();
    /** @type {Map<string, Function[]>} */
    this.doneWaiters = new Map();
    this.failure = null;
    transport.onMessage((msg) => this.#handle(msg));
  }

  #handle(msg) {
    if (!msg || typeof msg !== "object") return;
    if (msg.event === "done") {
      this.doneById.set(msg.id, msg);
      for (const w of this.doneWaiters.get(msg.id) ?? []) w(msg);
      this.doneWaiters.delete(msg.id);
      for (const cb of this.listeners) cb(msg);
      return;
    }
    const p = typeof msg.seq === "number" ? this.pending.get(msg.seq) : undefined;
    if (!p) return;
    this.pending.delete(msg.seq);
    if (msg.error) {
      const err = new Error(msg.error.message);
      err.code = msg.error.code;
      p.reject(err);
    } else p.resolve(msg.value);
  }

  /**
   * Rejects every pending call and waiter, for when the transport has closed.
   * @param {Error} err
   */
  fail(err) {
    this.failure = err;
    for (const p of this.pending.values()) p.reject(err);
    this.pending.clear();
    this.doneWaiters.clear();
  }

  /**
   * Sends one call and resolves with the host's value, or rejects with an Error carrying the host's `code`.
   * @param {string} name
   * @param {object} [args]
   * @returns {Promise<any>}
   */
  call(name, args = {}) {
    if (this.failure) return Promise.reject(this.failure);
    const seq = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(seq, { resolve, reject });
      try {
        this.transport.send({ seq, call: name, args });
      } catch (e) {
        this.pending.delete(seq);
        reject(e);
      }
    });
  }

  /**
   * Subscribes to the host's unsolicited events; only `done` exists in protocol v1.
   * @param {"done"} event
   * @param {(e: object) => void} cb
   */
  on(event, cb) {
    if (event !== "done") throw new Error(`unknown event ${event}`);
    this.listeners.push(cb);
  }

  /**
   * Resolves with the `done` event of a started call, including one that arrived before this call.
   * @param {string} id
   * @returns {Promise<object>}
   */
  waitDone(id) {
    const have = this.doneById.get(id);
    if (have) return Promise.resolve(have);
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve) => {
      const list = this.doneWaiters.get(id) ?? [];
      list.push(resolve);
      this.doneWaiters.set(id, list);
    });
  }

  /** Asks for the host's identity and capabilities. */
  hello() { return this.call("hello"); }
  /** Sends the session settings (roots, sandbox, path, limits). */
  configure(cfg) { return this.call("configure", cfg); }
  /** Resolves the facts of a call and starts nothing; args are `{ argv, cwd, env?, mode?, pathArgs?, timeoutMs? }`. */
  spawn(args) { return this.call("spawn", args); }
  /**
   * Runs a pending call after its verdict. `envelope` optionally narrows the sandbox to
   * `{ write: "roots"|"none", exec: "any"|"program-only" }` (both keys required; absent = today's floor).
   * `done` reports `write: "today"` for an absent envelope; a worker may not SEND `"today"` (malformed).
   * `done.protectedChanged` lists what changed among the roots' protected names during the call
   * (`[{ root, name, change: "created"|"modified"|"removed" }]`, `[]` when nothing; absent from an older host, or
   * dropped from a `done` past the 1 MiB limit: unknown). `protectedChangedTruncated: true` when cut at 256.
   * @param {string} id
   * @param {{ write: "roots"|"none", exec: "any"|"program-only" }} [envelope]
   */
  start(id, envelope) {
    return this.call("start", envelope === undefined ? { id } : { id, envelope });
  }
  /**
   * Runs 2 to 16 pending calls joined by OS pipes; each stage still ends with its own `done`.
   * `envelopes`, when present, is one entry per id: `null` (today's floor) or an envelope as in `start`.
   * Resolves `{ ids, pids }`.
   * @param {string[]} ids
   * @param {(null|{ write: "roots"|"none", exec: "any"|"program-only" })[]} [envelopes]
   */
  pipe(ids, envelopes) {
    return this.call("pipe", envelopes === undefined ? { ids } : { ids, envelopes });
  }
  /** Expands a pattern beneath `cwd` within the roots; resolves `{ matches, truncated }`. */
  glob(cwd, pattern, limit) { return this.call("glob", limit === undefined ? { cwd, pattern } : { cwd, pattern, limit }); }
  /** Forgets a pending call that was denied. */
  discard(id) { return this.call("discard", { id }); }
  /** Terminates a running call's process group. */
  cancel(id) { return this.call("cancel", { id }); }
  /** Deletes held output early. */
  release(ptr) { return this.call("release", { ptr }); }

  /**
   * Reads a held output pointer to its end, in ranges, and returns the bytes.
   * @param {string} ptr
   * @returns {Promise<Buffer>}
   */
  async readAll(ptr) {
    const parts = [];
    let offset = 0;
    for (;;) {
      const r = await this.call("read", { ptr, offset, length: READ_CHUNK });
      const bytes = Buffer.from(r.data.$bytes, "base64");
      parts.push(bytes);
      offset += bytes.length;
      if (r.eof || bytes.length === 0) break;
    }
    return Buffer.concat(parts);
  }
}

/**
 * Starts the host binary over stdio pipes and returns a client wired to it.
 * @param {string} binaryPath
 * @param {string[]} [args]
 * @returns {{ client: HostClient, child: import("node:child_process").ChildProcess, close(): Promise<void> }}
 */
export function spawnHost(binaryPath, args = []) {
  const child = spawn(binaryPath, args, { stdio: ["pipe", "pipe", "pipe"] });
  const decoder = new FrameDecoder();
  let handler = () => {};
  const client = new HostClient({
    send: (obj) => child.stdin.write(encodeFrame(obj)),
    onMessage: (cb) => { handler = cb; },
  });
  child.stdout.on("data", (chunk) => {
    try {
      for (const m of decoder.push(chunk)) handler(m);
    } catch (e) {
      client.fail(e);
      child.kill();
    }
  });
  child.stderr.on("data", (d) => {
    for (const line of d.toString("utf8").split("\n")) if (line) process.stderr.write(`[wmlhost] ${line}\n`);
  });
  const exited = new Promise((resolve) => child.on("close", resolve));
  exited.then(() => client.fail(new Error("host exited")));
  child.stdin.on("error", () => {});
  return {
    client,
    child,
    close() {
      child.stdin.end();
      return exited.then(() => {});
    },
  };
}
