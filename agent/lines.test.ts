import { describe, expect, it } from "vitest";
import { mask, parseRead } from "./lines.ts";

const NONE = { journal: null, docker: null };
const out = (...sections: Array<[string, string[]]>) => sections.map(([name, lines]) => `\n@@${name}\n${lines.join("\n")}`).join("") + "\n@@end\n";
const meta: [string, string[]] = ["meta", ["format 1", "user openasy", "groups openasy"]];
const line = (cursor: string, msg: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    __CURSOR: cursor,
    __REALTIME_TIMESTAMP: "1761040000123456",
    MESSAGE: msg,
    PRIORITY: "3",
    _SYSTEMD_UNIT: "nginx.service",
    _PID: "812",
    ...extra,
  });

describe("reading the journal", () => {
  it("turns journal lines into entries, and keeps the last cursor", () => {
    const r = parseRead(
      out(meta, ["journal", [line("s=1;i=1", "upstream timed out"), line("s=1;i=2", "upstream back", { SYSLOG_IDENTIFIER: "nginx" })]]),
      100,
      NONE,
    );
    expect(r.entries).toEqual([
      { time: "2025-10-21T09:46:40.123Z", msg: "upstream timed out", fields: { level: "3", service: "nginx", "systemd.unit": "nginx.service", pid: "812" } },
      { time: "2025-10-21T09:46:40.123Z", msg: "upstream back", fields: { level: "3", service: "nginx", "systemd.unit": "nginx.service", pid: "812" } },
    ]);
    expect(r).toMatchObject({ cursor: { journal: "s=1;i=2", docker: null }, more: false, unreadable: [] });
  });

  it("stops at the limit, says more are waiting, and starts there next time", () => {
    const r = parseRead(out(meta, ["journal", [line("s=1;i=1", "a"), line("s=1;i=2", "b"), line("s=1;i=3", "c")]]), 2, NONE);
    expect(r.entries.map((e) => e.msg)).toEqual(["a", "b"]);
    expect(r).toMatchObject({ cursor: { journal: "s=1;i=2" }, more: true });
  });

  it("keeps the previous cursor when nothing new was written", () => {
    expect(parseRead(out(meta, ["journal", []]), 100, { journal: "s=1;i=9", docker: null }).cursor.journal).toBe("s=1;i=9");
  });

  it("says when the account sees only its own journal, or there is no journal", () => {
    const partial = parseRead(out(meta, ["journal", ["Hint: You are currently not seeing messages from other users and the system."]]), 100, NONE);
    expect(partial.unreadable).toEqual(["the system journal: add the openasy account to the systemd-journal group"]);
    const none = parseRead(out(meta, ["journal", ["No journal files were opened due to insufficient permissions."]]), 100, NONE);
    expect(none.unreadable).toEqual(["the system journal: add the openasy account to the systemd-journal group"]);
    expect(parseRead(out(meta, ["journal", ["@missing journalctl"]]), 100, NONE).unreadable).toEqual(["journald: journalctl is not on this host"]);
  });

  it("reads messages that are not valid UTF-8, sent as bytes", () => {
    const r = parseRead(out(meta, ["journal", [line("s=1;i=1", "", { MESSAGE: [104, 105] })]]), 100, NONE);
    expect(r.entries[0]!.msg).toBe("hi");
  });

  it("refuses output that did not finish", () => {
    expect(() => parseRead("\n@@meta\nformat 1\n@@journal\n", 100, NONE)).toThrow(/end marker/);
  });
});

describe("reading containers", () => {
  it("reads each container's lines, masks them, and starts the next read where this one stopped", () => {
    const r = parseRead(
      out(
        meta,
        ["journal", []],
        ["docker", ["@until 2026-10-21T10:00:00Z", "@container 3f2a api", "2026-10-21T09:59:00.5Z GET /health 200", "2026-10-21T09:59:01Z token=abcdef123"]],
      ),
      100,
      NONE,
    );
    expect(r.entries).toEqual([
      { time: "2026-10-21T09:59:00.500Z", msg: "GET /health 200", fields: { service: "api", "container.name": "api", "container.id": "3f2a" } },
      { time: "2026-10-21T09:59:01.000Z", msg: "token=***", fields: { service: "api", "container.name": "api", "container.id": "3f2a" } },
    ]);
    expect(r.cursor.docker).toBe("2026-10-21T10:00:00Z");
  });

  it("says when a container wrote more than one read takes", () => {
    const r = parseRead(
      out(meta, [
        "docker",
        ["@until 2026-10-21T10:00:00Z", "@container 3f2a api", "2026-10-21T09:59:00Z a", "2026-10-21T09:59:01Z b", "2026-10-21T09:59:02Z c"],
      ]),
      2,
      NONE,
    );
    expect(r.entries.map((e) => e.msg)).toEqual(["a", "b", expect.stringContaining("container api wrote more than 2 lines")]);
  });

  it("says what Docker does not allow", () => {
    expect(parseRead(out(meta, ["docker", ["@error permission denied while trying to connect to the Docker daemon socket"]]), 100, NONE).unreadable).toEqual([
      "containers: add the openasy account to the docker group",
    ]);
    expect(parseRead(out(meta, ["docker", ["@missing docker"]]), 100, NONE).unreadable).toEqual(["containers: docker is not on this host"]);
  });
});

describe("masking", () => {
  it.each([
    ["password=hunter2 ok", "password=*** ok"],
    ['{"api_key": "abc123xyz"}', '{"api_key": "***"}'],
    ["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc", "Authorization: Bearer ***"],
    ["key AKIAIOSFODNN7EXAMPLE used", "key AKIA**************** used"],
    ["token ghp_0123456789abcdefghijklmnopqrstuvwxyz", "token ghp_***"],
    ["postgres://app:s3cret@db:5432/app", "postgres://app:***@db:5432/app"],
    ["-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----", "[private key masked]"],
    ["nothing secret here", "nothing secret here"],
  ])("%s", (input, masked) => {
    expect(mask(input)).toBe(masked);
  });
});
