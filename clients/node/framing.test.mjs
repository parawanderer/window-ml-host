// framing.test.mjs — tests for the Node client's framing and its done-event bookkeeping.

import assert from "node:assert/strict";
import os from "node:os";
import test from "node:test";
import { encodeFrame, FrameDecoder, HostClient, MAX_OUT } from "./wmlhost-client.mjs";

// --- framing ---

test("a frame round-trips", () => {
  const obj = { seq: 1, call: "hello", args: { s: "héllo" } };
  assert.deepEqual(new FrameDecoder().push(encodeFrame(obj)), [obj]);
});

test("two frames in one chunk decode as two", () => {
  const a = { a: 1 }, b = { b: 2 };
  const chunk = Buffer.concat([encodeFrame(a), encodeFrame(b)]);
  assert.deepEqual(new FrameDecoder().push(chunk), [a, b]);
});

test("one frame split across three chunks, inside the length prefix", () => {
  const obj = { seq: 9, value: "x".repeat(50) };
  const f = encodeFrame(obj);
  const d = new FrameDecoder();
  assert.deepEqual(d.push(f.subarray(0, 2)), []);
  assert.deepEqual(d.push(f.subarray(2, 10)), []);
  assert.deepEqual(d.push(f.subarray(10)), [obj]);
});

test("a length over the limit throws", () => {
  const bad = Buffer.alloc(4);
  if (os.endianness() === "LE") bad.writeUInt32LE(MAX_OUT + 1);
  else bad.writeUInt32BE(MAX_OUT + 1);
  assert.throws(() => new FrameDecoder().push(bad), /exceeds limit/);
});

test("waitDone resolves for a done event that arrived first", async () => {
  let cb;
  const client = new HostClient({ send() {}, onMessage: (c) => { cb = c; } });
  cb({ event: "done", id: "c1", code: 0 });
  assert.equal((await client.waitDone("c1")).code, 0);
});

test("call rejects with the host's code", async () => {
  let cb, sent;
  const client = new HostClient({ send: (o) => { sent = o; }, onMessage: (c) => { cb = c; } });
  const p = client.call("spawn", {});
  cb({ seq: sent.seq, error: { code: "NotConfigured", message: "nope" } });
  await assert.rejects(p, (e) => e.code === "NotConfigured" && e.message === "nope");
});
