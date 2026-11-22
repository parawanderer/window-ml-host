#!/usr/bin/env node
// describe-replay.mjs — every shared vector row through the built describe.wasm, asserting what tests/manifest_vectors.rs
// asserts of the Rust describer. No dependencies. usage: node tools/describe-replay.mjs <describe.wasm>
//
// Replayed, per kind (vectors/program-manifests/):
//   calls      every row, the program's manifest, the file's version, no flavour: described, effects (unresolved),
//              pathArgs, actsOnDir, runner, okCodes, echoes, recursive, hardened.
//   flavoured  the same nine fields, under each row's flavour.
//   resolved   every row's `pre` (the description before resolution), byte for byte as JSON. The row's `resolve` and
//              resolved `effects` are window-ml's to check, as in the Rust test.
//   shapes     resolved/shapes.json: each row's own manifest, described and why and pre.
// Not replayed:
//   manifests  they are the INPUTS of the kinds above (each is parsed by every call it describes); the Rust tests that
//              mutate them (unknown keys must fail to parse) are not row replays.
//   scanners   regex-ends.json holds the sed delimiter scanners' answers (`gnu_regex_end`, `bsd_delimited_end`), which
//              the describe ABI does not expose; the Rust test (tests/script_grammar.rs) holds them.
// Exits 1 on the first 20 differences, and when a kind that it claims to cover replayed no rows or the row count is not
// the one the Rust test asserts.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const wasmFile = process.argv[2];
if (!wasmFile) {
  console.error("usage: node tools/describe-replay.mjs <describe.wasm>");
  process.exit(2);
}
const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "vectors", "program-manifests");
// Every program with a manifest: a new one is replayed without editing this file (and moves EXPECT with the Rust test).
const PROGRAMS = fs.readdirSync(path.join(DIR, "manifests")).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort();
// The counts tests/manifest_vectors.rs asserts: a vector change moves them there and here together.
const EXPECT = { calls: 507, flavoured: 25, resolved: 324, shapes: 8 };
const load = (kind, name) => JSON.parse(fs.readFileSync(path.join(DIR, kind, `${name}.json`), "utf8"));

const mod = await WebAssembly.compile(fs.readFileSync(wasmFile));
const ex = (await WebAssembly.instantiate(mod, {})).exports;
const enc = new TextEncoder();
const dec = new TextDecoder();
/** One request through the wasm; the parsed reply. */
function describe(req) {
  const b = enc.encode(JSON.stringify(req));
  const p = ex.alloc(b.length);
  new Uint8Array(ex.memory.buffer, p, b.length).set(b);
  const o = ex.describe(p, b.length);
  const len = new DataView(ex.memory.buffer).getUint32(o, true);
  const s = dec.decode(new Uint8Array(ex.memory.buffer, o + 4, len));
  ex.dealloc(p, b.length);
  ex.dealloc(o, 4 + len);
  return JSON.parse(s);
}

/** JSON with object keys sorted: serde_json's `==` on values ignores key order, and so does this. */
const canon = (v) => JSON.stringify(v, (_, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));

const NINE = ["described", "effects", "pathArgs", "actsOnDir", "runner", "okCodes", "echoes", "recursive", "hardened"];
const counts = Object.fromEntries(Object.keys(EXPECT).map((k) => [k, 0]));
const failures = [];
const fail = (kind, who, field, got, want) => failures.push({ kind, who, field, got: canon(got), want: canon(want) });

function check(kind, who, reply, row, fields) {
  if (reply.error !== undefined) return fail(kind, who, "error", reply.error, "a description");
  for (const f of fields) if (canon(reply[f]) !== canon(row[f])) fail(kind, who, f, reply[f], row[f]);
}

for (const program of PROGRAMS) {
  const manifest = load("manifests", program);
  const calls = load("calls", program);
  for (const c of calls.calls) {
    counts.calls++;
    check("calls", `${program} ${canon(c.argv)} (${c.note})`, describe({ argv: c.argv, manifest, version: calls.version }), c, NINE);
  }
  const resolved = load("resolved", program);
  for (const c of resolved.calls) {
    counts.resolved++;
    const who = `${program} ${canon(c.argv)}`;
    const r = describe({ argv: c.argv, manifest, version: resolved.version });
    if (r.error === undefined && r.described !== true) fail("resolved", who, "described", r.described, true);
    check("resolved", who, r, c, ["pre"]);
  }
}
for (const program of ["awk", "sed"]) {
  const manifest = load("manifests", program);
  const fx = load("flavoured", program);
  for (const c of fx.calls) {
    counts.flavoured++;
    check("flavoured", `${program} ${canon(c.argv)} as ${c.flavour} (${c.note})`, describe({ argv: c.argv, manifest, version: fx.version, flavour: c.flavour }), c, NINE);
  }
}
for (const c of load("resolved", "shapes").calls) {
  counts.shapes++;
  const req = { argv: c.argv, manifest: c.manifest };
  if (c.version !== undefined) req.version = c.version;
  check("shapes", `${c.shape}: ${canon(c.argv)}`, describe(req), c, ["described", "why", "pre"]);
}

for (const [kind, want] of Object.entries(EXPECT)) {
  console.log(`${kind}: ${counts[kind]} rows replayed`);
  if (counts[kind] === 0) failures.push({ kind, who: "(none)", field: "rows", got: "0", want: "more than 0" });
  else if (counts[kind] !== want) failures.push({ kind, who: "(count)", field: "rows", got: String(counts[kind]), want: String(want) });
}
if (failures.length) {
  console.error(`${failures.length} difference(s); the first ${Math.min(20, failures.length)}:`);
  for (const f of failures.slice(0, 20)) console.error(`  [${f.kind}] ${f.who}: ${f.field}\n    wasm:     ${f.got}\n    recorded: ${f.want}`);
  process.exit(1);
}
console.log("ok: every row replays as recorded");
