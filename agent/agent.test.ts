import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { createAgent } from "./agent.ts";
import { checkJob, READ_SCRIPT, runJob, type Transport } from "./jobs.ts";
import { createKeyring } from "./kek.ts";
import { SshError } from "./ssh.ts";
import { loadState } from "./state.ts";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFmXq7hWQvK1eF4s3n0q6X8b9mZ2nqJ8V7cJq3s1kR2x";
const CURSOR = "s=0a1b;i=1f;b=2c;m=3d;t=4e;x=5f";
const job = (over: Record<string, unknown> = {}) => ({
  id: "j1",
  hostId: "h1",
  action: "read",
  target: { address: "10.0.0.5", port: 22, user: "openasy", auth: "certificate", containers: false, hostKeys: [KEY] },
  cursor: { journal: null, docker: null },
  ...over,
});
const keys = { caPrivateKey: "ca", keyPrivateKey: "key" };
/** What read.sh prints for a host with one journal line and nothing else. */
const OUTPUT = [
  "",
  "@@meta",
  "format 1",
  "user openasy",
  "",
  "@@journal",
  JSON.stringify({ __CURSOR: CURSOR, __REALTIME_TIMESTAMP: "1761040000000000", MESSAGE: "login with password=hunter2", PRIORITY: "6", SYSLOG_IDENTIFIER: "sshd" }),
  "",
  "@@end",
  "",
].join("\n");

describe("jobs from Logs", () => {
  it.each([
    ["an address ssh would read as an option", { target: { ...job().target, address: "-oProxyCommand=sh -c id" } }],
    ["a user ssh would read as an option", { target: { ...job().target, user: "-oX" } }],
    ["a host key that is not a public key", { target: { ...job().target, hostKeys: ["ssh-ed25519 AAAA\nmalicious"] } }],
    ["an action the agent does not know", { action: "run", command: "rm -rf /" }],
    ["a port out of range", { target: { ...job().target, port: 70000 } }],
    ["a journal cursor that would end the quotes", { cursor: { journal: "s=1'; rm -rf / #", docker: null } }],
    ["a docker time that is not a time", { cursor: { journal: null, docker: "now; id" } }],
  ])("refuses %s", async (_name, over) => {
    expect(() => checkJob(job(over))).toThrow();
    const r = await runJob(job(over), keys, { runScript: () => Promise.reject(new Error("must not connect")), scanHostKey: () => Promise.reject(new Error("must not connect")) });
    expect(r).toMatchObject({ ok: false, error: { kind: "invalid-job" } });
  });

  it("runs only its own script from the cursor, and masks secrets before sending them", async () => {
    let script = "";
    const transport: Transport = {
      runScript: async (_e, cred, s) => {
        expect(cred).toEqual({ mode: "certificate", caPrivateKey: "ca" });
        script = s;
        return OUTPUT;
      },
      scanHostKey: async () => [KEY],
    };
    const r = await runJob(job({ cursor: { journal: CURSOR, docker: null }, script: "rm -rf /" }), keys, transport);
    expect(script.startsWith(`OPENASY_CURSOR='${CURSOR}'\n`)).toBe(true);
    expect(script.endsWith(READ_SCRIPT)).toBe(true);
    expect(script).not.toContain("rm -rf");
    expect(r).toMatchObject({ ok: true, cursor: { journal: CURSOR }, more: false, entries: [{ msg: "login with password=***", fields: { service: "sshd", level: "6" } }] });
    expect(JSON.stringify(r)).not.toContain("hunter2");
  });

  it("reports the key a host presents when it changed", async () => {
    const other = KEY.replace("Fm", "Gm");
    const r = await runJob(job(), keys, { runScript: async () => Promise.reject(new SshError("host-key-changed", "changed")), scanHostKey: async () => [other] });
    expect(r).toEqual({ jobId: "j1", hostId: "h1", ok: false, error: { kind: "host-key-changed", message: "changed" }, hostKeys: [other] });
  });
});

describe("the loop", () => {
  const servers: Array<{ close: () => void }> = [];
  afterEach(() => servers.splice(0).forEach((s) => s.close()));

  async function fakeLogs(opts: { jobs: unknown[]; version?: string }) {
    const seen: Array<{ path: string; auth: string | undefined; body: Record<string, any> }> = [];
    const server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = JSON.parse(gunzipSync(Buffer.concat(chunks)).toString());
      seen.push({ path: req.url!, auth: req.headers.authorization, body });
      const json = (status: number, data: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(data));
      if (req.url === "/api/v1/agent/enroll") return body.token === "enroll-1" ? json(200, { agentId: "a1", secret: "agent-secret" }) : json(401, { code: "invalid-token", detail: "used" });
      if (req.headers.authorization !== "Bearer agent-secret") return json(401, { code: "invalid-token" });
      if (req.url === "/api/v1/agent/work") return body.version === (opts.version ?? "1.0.0") ? json(200, { jobs: opts.jobs.splice(0) }) : json(409, { code: "version-mismatch", detail: "logs-agent 1.0.0 does not match logs 2.0.0" });
      if (req.url === "/api/v1/agent/results") return json(202, { status: "accepted" });
      json(404, {});
    });
    await new Promise<void>((r) => server.listen(0, r));
    servers.push(server);
    return { url: `http://localhost:${(server.address() as AddressInfo).port}`, seen };
  }

  async function agent(url: string, enrollToken?: string) {
    const dir = mkdtempSync(join(tmpdir(), "agent-"));
    const keyring = createKeyring(randomBytes(32));
    const statePath = join(dir, "agent.state");
    const state = await loadState(statePath, keyring);
    return {
      statePath,
      keyring,
      a: await createAgent({ url, version: "1.0.0", state, statePath, keyring, enrollToken, transport: { runScript: async () => OUTPUT, scanHostKey: async () => [KEY] } }),
    };
  }

  it("enrolls once, asks for work and sends results with its own secret", async () => {
    const logs = await fakeLogs({ jobs: [job(), job({ id: "j2", action: "host-key" })] });
    const { a, statePath, keyring } = await agent(logs.url, "enroll-1");
    await a.round();
    expect(a.status).toMatchObject({ enrolled: true, logsOk: true, jobs: 2, jobFailures: 0 });
    const enroll = logs.seen.find((s) => s.path === "/api/v1/agent/enroll")!;
    expect(enroll.body).toMatchObject({ token: "enroll-1", version: "1.0.0", caPublicKey: expect.stringMatching(/^ssh-ed25519 /) });
    // What Logs accepts: no sudoers, and the commands that let the account read the system journal.
    expect(Object.keys(enroll.body.setup).sort()).toEqual(["authorizedKey", "hostSetup", "sshdConfig"]);
    expect(enroll.body.setup.hostSetup).toContain("usermod -aG systemd-journal openasy");
    // No private key ever leaves the agent.
    expect(JSON.stringify(logs.seen)).not.toMatch(/PRIVATE KEY/);
    const results = logs.seen.filter((s) => s.path === "/api/v1/agent/results");
    expect(results.map((r) => r.auth)).toEqual(["Bearer agent-secret", "Bearer agent-secret"]);
    expect(results.find((r) => r.body.jobId === "j1")!.body).toMatchObject({ ok: true, cursor: { journal: CURSOR }, entries: [{ msg: "login with password=***" }] });
    expect(results.find((r) => r.body.jobId === "j2")!.body.hostKeys).toEqual([KEY]);
    // The secret is kept sealed: the file never holds it in clear.
    expect(readFileSync(statePath, "utf8")).not.toContain("agent-secret");
    expect(JSON.parse(keyring.open(readFileSync(statePath, "utf8")).toString()).secret).toBe("agent-secret");
  });

  it("waits without an enrolment token and says why", async () => {
    const logs = await fakeLogs({ jobs: [] });
    const { a } = await agent(logs.url);
    await a.round();
    expect(a.status).toMatchObject({ enrolled: false, lastError: expect.stringContaining("LOGS_ENROLL_TOKEN") });
    expect(logs.seen).toEqual([]);
  });

  it("keeps running when Logs is down or refuses its version", async () => {
    const { a } = await agent("http://127.0.0.1:1", "enroll-1");
    await a.round();
    expect(a.status).toMatchObject({ enrolled: false, logsOk: false, lastError: expect.stringContaining("unreachable") });
    const logs = await fakeLogs({ jobs: [job()], version: "2.0.0" });
    const b = await agent(logs.url, "enroll-1");
    await b.a.round();
    expect(b.a.status).toMatchObject({ enrolled: true, logsOk: false, lastError: expect.stringContaining("does not match"), jobs: 0 });
  });
});
