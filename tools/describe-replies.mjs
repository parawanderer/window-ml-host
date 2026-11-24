#!/usr/bin/env node
// describe-replies.mjs — the BUILT describe.wasm answers exactly what the native describer answered, imports nothing,
// and ends every malformed or oversized request in an error rather than a trap. No dependencies.
// usage: node tools/describe-replies.mjs <describe.wasm>
//
// The pin it replays: describe-wasm/tests/replies.json, written by `WML_DESCRIBE_BLESS=1 cargo test -p describe-wasm
// --lib` from the NATIVE build (describe-wasm/src/replies.rs asserts the native side of it, entry by entry). This
// driver closes the other end: every recorded vector row, every hostile shape and every malformed or oversized request
// through the wasm ABI a caller uses (`alloc`, `describe`, `dealloc`), each answered with the pinned reply — by digest
// for the recorded rows and the megabyte-sized inputs, whole for the hostile and malformed ones, so a reader can see
// what a hostile shape was answered.
//
// The two properties only the artifact can show:
//   imports  the module imports NOTHING: no wasm import at all, so nothing of its embedder (no clock, no randomness, no
//            filesystem, no host function) can change an answer. Its exports are exactly alloc, dealloc, describe, memory.
//   no trap  every request, however malformed or oversized, returns a reply. A trap would reach the caller as a throw,
//            which an embedder could read as "no effects"; a reply is always one object, either {"error": <text>} or a
//            description carrying `described` and `effects`, never both and never neither.
//
// Exits 1 on the first differences it finds (all of them, not the first), and when a pinned entry or a rebuilt request
// is missing from the other side: the pin and this driver cover the same corpus or the run is red.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const wasmFile = process.argv[2];
if (!wasmFile) {
  console.error("usage: node tools/describe-replies.mjs <describe.wasm>");
  process.exit(2);
}
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PIN = path.join(HERE, "..", "describe-wasm", "tests", "replies.json");
const VECTORS = path.join(HERE, "..", "vectors", "program-manifests");
// The counts the Rust replay test asserts: a vector change moves them there and here together.
const COUNTS = { calls: 507, flavoured: 25, resolved: 324, shapes: 8 };

const fail = [];
const bad = (what) => fail.push(what);

/** JSON with object keys sorted and nothing between tokens, which is what serde_json's `to_string` writes. */
const canon = (v) =>
  JSON.stringify(v, (_, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// --- the module: nothing imported, four exports ---

const mod = await WebAssembly.compile(fs.readFileSync(wasmFile));
const imports = WebAssembly.Module.imports(mod);
if (imports.length !== 0) bad(`the wasm imports ${imports.length} thing(s) from its embedder: ${canon(imports)}`);
const exports = WebAssembly.Module.exports(mod).map((e) => e.name).sort();
const wanted = ["alloc", "dealloc", "describe", "memory"];
if (canon(exports) !== canon(wanted)) bad(`exports are ${canon(exports)}, not ${canon(wanted)}`);
const ex = (await WebAssembly.instantiate(mod, {})).exports;

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * One request through the ABI a caller uses. Returns the reply text, or throws what a trap throws.
 * @param {Uint8Array} bytes the request
 * @returns {string} the reply
 */
function call(bytes) {
  const p = ex.alloc(bytes.length);
  if (!p) throw new Error("alloc returned 0");
  new Uint8Array(ex.memory.buffer, p, bytes.length).set(bytes);
  const o = ex.describe(p, bytes.length);
  if (!o) throw new Error("describe returned 0");
  const view = new DataView(ex.memory.buffer);
  const len = view.getUint32(o, true);
  // The reply is [u32 LE length][JSON]; the length must name bytes that are in memory, or the ABI itself is broken.
  if (o + 4 + len > ex.memory.buffer.byteLength) throw new Error(`reply length ${len} runs past memory`);
  const text = dec.decode(new Uint8Array(ex.memory.buffer, o + 4, len));
  ex.dealloc(p, bytes.length);
  ex.dealloc(o, 4 + len);
  return text;
}

/**
 * The reply to one request, checked for the two shapes a reply may take.
 * @param {string} name the pin's name for it, for the failure message
 * @param {Uint8Array} bytes the request
 * @returns {any} the parsed reply
 */
function reply(name, bytes) {
  let text;
  try {
    text = call(bytes);
  } catch (e) {
    bad(`${name}: THREW ${e?.constructor?.name ?? "Error"}: ${e?.message ?? e} (a trap is not a reply)`);
    return null;
  }
  let v;
  try {
    v = JSON.parse(text);
  } catch {
    bad(`${name}: the reply is not JSON: ${text.slice(0, 200)}`);
    return null;
  }
  const isError = typeof v?.error === "string";
  const isDoc = v?.described !== undefined && v?.effects !== undefined;
  if (isError && (v.described !== undefined || v.effects !== undefined)) bad(`${name}: an error reply also carries a description: ${text.slice(0, 200)}`);
  if (!isError && !isDoc) bad(`${name}: neither {"error"} nor a description with described+effects: ${text.slice(0, 200)}`);
  return v;
}

// --- the requests the pin was written from, rebuilt ---

const read = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const manifest = (program) => read(path.join(VECTORS, "manifests", `${program}.json`));
const rows = (kind, program) => read(path.join(VECTORS, kind, `${program}.json`));
const PROGRAMS = fs
  .readdirSync(path.join(VECTORS, "manifests"))
  .filter((f) => f.endsWith(".json"))
  .map((f) => f.slice(0, -5))
  .sort();

/**
 * A request as the Rust `ask` builds it: the fields present when the caller has them, none of them reordered in a way
 * that matters (a reply depends on the JSON's content, not its key order).
 * @param {any[]} argv the program and its arguments
 * @param {any} m the manifest
 * @param {{version?: any, flavour?: string, envSet?: any[]}} [opt] the optional fields
 * @returns {Uint8Array} the request bytes
 */
function ask(argv, m, opt = {}) {
  const req = { argv, manifest: m };
  if (opt.version !== undefined) req.version = opt.version;
  if (opt.flavour !== undefined) req.flavour = opt.flavour;
  if (opt.envSet !== undefined) req.envSet = opt.envSet;
  return enc.encode(JSON.stringify(req));
}

/** Every recorded row, named as the Rust side names it. */
function recorded() {
  const out = new Map();
  const counts = Object.fromEntries(Object.keys(COUNTS).map((k) => [k, 0]));
  for (const program of PROGRAMS) {
    const m = manifest(program);
    for (const kind of ["calls", "resolved"]) {
      const file = rows(kind, program);
      file.calls.forEach((row, i) => {
        counts[kind]++;
        out.set(`${kind}/${program}/${i}`, ask(row.argv, m, { version: file.version }));
      });
    }
  }
  for (const program of ["awk", "sed"]) {
    const m = manifest(program);
    const file = rows("flavoured", program);
    file.calls.forEach((row, i) => {
      counts.flavoured++;
      out.set(`flavoured/${program}/${i}`, ask(row.argv, m, { version: file.version, flavour: row.flavour }));
    });
  }
  const shapes = read(path.join(VECTORS, "resolved", "shapes.json")).calls;
  if (shapes === undefined) throw new Error("resolved/shapes.json has no calls");
  shapes.forEach((row, i) => {
    counts.shapes++;
    out.set(`shapes/${i}`, ask(row.argv, row.manifest, { version: row.version }));
  });
  if (canon(counts) !== canon(COUNTS)) bad(`the vectors give ${canon(counts)} rows, not the pinned ${canon(COUNTS)}`);
  return out;
}

/** The oversized requests, byte for byte as `big()` builds them. */
function oversized() {
  const rm = canon(manifest("rm"));
  const big = new Map();
  big.set("big/nested-100000", enc.encode(`{"argv":["rm"],"manifest":${rm},"x":${"[".repeat(100_000)}${"]".repeat(100_000)}}`));
  const argv = JSON.stringify(["x", ...Array.from({ length: 100_000 }, () => "a")]);
  big.set("big/argv-100000", enc.encode(`{"argv":${argv},"manifest":${rm}}`));
  big.set("big/string-2000000", enc.encode(`{"argv":["x","${"a".repeat(2_000_000)}"],"manifest":${rm}}`));
  big.set("big/junk-4000000", enc.encode(`{"argv":["x"],"manifest":${rm}}${" ".repeat(4_000_000)}`));
  big.set("big/whitespace-4000000", enc.encode(" ".repeat(4_000_000)));
  big.set("big/invalid-utf8", Uint8Array.from([0x7b, 0x22, 0x61, 0x72, 0x67, 0x76, 0x22, 0x3a, 0x5b, 0x22, 0xff, 0xfe, 0x22, 0x5d, 0x7d]));
  return big;
}

const rebuilt = new Map([...recorded(), ...oversized()]);

// --- the pin, replayed ---

const pin = read(PIN);
if (!pin || !Array.isArray(pin.whole) || !Array.isArray(pin.digest)) {
  console.error(`${PIN}: not a pin with whole and digest arrays`);
  process.exit(2);
}
const whole = new Map(pin.whole.map((e) => [e.name, e]));
const digest = new Map(pin.digest.map((e) => [e.name, e]));
// A whole entry is pinned WITH its request: the hostile and malformed shapes are exact text (a duplicate key, a BOM, a
// NUL), which no rebuild from a JSON value can reproduce. The rest are rebuilt above.
for (const [name, e] of whole) rebuilt.set(name, e.requestHex !== undefined ? Uint8Array.from(Buffer.from(e.requestHex, "hex")) : enc.encode(e.request));
const pinned = new Set([...whole.keys(), ...digest.keys()]);
if (pin.whole.length + pin.digest.length !== pinned.size) bad("the pin names an entry twice");
for (const name of pinned) if (!rebuilt.has(name)) bad(`${name}: pinned, but this driver does not build its request`);
for (const name of rebuilt.keys()) if (!pinned.has(name)) bad(`${name}: built, but the pin does not hold it`);

let replayed = 0;
for (const name of [...pinned].sort()) {
  const bytes = rebuilt.get(name);
  if (!bytes) continue; // already reported
  const got = reply(name, bytes);
  if (got === null) continue;
  replayed++;
  if (whole.has(name)) {
    const want = whole.get(name).reply;
    if (canon(got) !== canon(want)) bad(`${name}: the wasm and the pin disagree:\n  wasm: ${canon(got).slice(0, 400)}\n  pin:  ${canon(want).slice(0, 400)}`);
  } else {
    const want = digest.get(name);
    const gotDigest = sha256(canon(got));
    if (want === undefined) bad(`${name}: pinned nothing`);
    else if (want.sha256 !== gotDigest) bad(`${name}: sha256 ${gotDigest} but the pin says ${want.sha256} (canonical reply: ${canon(got).slice(0, 300)}…)`);
  }
}

// A caller after all of that: the allocator and memory are still usable, so a malformed request does not poison the next.
const control = reply("control/<after the corpus>", ask(["ls", "-l"], manifest("ls"), {}));
if (control === null || control.error !== undefined || control.described === undefined) {
  bad(`a recorded request after the corpus did not describe: ${canon(control)}`);
}

if (replayed !== pinned.size) bad(`replayed ${replayed} of the pin's ${pinned.size} entries`);

if (fail.length > 0) {
  console.error(`describe-replies: ${fail.length} failure(s) in ${replayed} replayed requests:`);
  for (const f of fail) console.error(`  ${f}`);
  process.exit(1);
}
console.log(`describe-replies: ${replayed} requests, ${whole.size} whole and ${digest.size} by digest; nothing imported, no trap`);
