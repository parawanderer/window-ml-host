// smoke.mjs — runs the host binary through the client: configure, spawn, start, read, cancel and a refusal.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnHost } from "./wmlhost-client.mjs";

const bin = process.argv[2];
if (!bin) {
  console.error("usage: node clients/node/smoke.mjs <path to wmlhost>");
  process.exit(2);
}

const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "wmlhost-smoke-")));
execFileSync("git", ["init", "-q"], { cwd: root });
fs.writeFileSync(path.join(root, "hello-smoke.txt"), "hi\n");

const host = spawnHost(bin);
const { client } = host;
try {
  console.log("hello", await client.hello());
  console.log("configure", await client.configure({ roots: [root] }));

  const facts = await client.spawn({ argv: ["git", "status", "--short"], cwd: root });
  console.log("facts", facts);
  const started = await client.start(facts.id);
  console.log("started", started);
  const done = await client.waitDone(facts.id);
  console.log("done", done);
  assert.equal(done.ok, true);
  const out = (await client.readAll(done.stdout.ptr)).toString("utf8");
  console.log("stdout", JSON.stringify(out));
  assert.ok(out.includes("hello-smoke.txt"), "stdout names the file");

  const slow = await client.spawn({ argv: ["sleep", "30"], cwd: root });
  await client.start(slow.id);
  console.log("cancel", await client.cancel(slow.id));
  const slowDone = await client.waitDone(slow.id);
  console.log("done", slowDone);
  assert.equal(slowDone.cancelled, true);

  await assert.rejects(client.spawn({ argv: ["ls"], cwd: "/" }), (e) => e.code === "CwdOutsideRoots");

  console.log("smoke ok");
} finally {
  await host.close();
  fs.rmSync(root, { recursive: true, force: true });
}
