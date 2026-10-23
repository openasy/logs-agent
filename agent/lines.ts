// What read.sh prints, as lines for Logs, with where the next read starts. Values that look like passwords, tokens or
// keys are masked here, so they never leave the host's network (ADR 0031, 0035).

export interface Entry {
  time: string;
  msg: string;
  fields: Record<string, string>;
}

export interface Read {
  entries: Entry[];
  cursor: { journal: string | null; docker: string | null };
  /** The journal had more than one read takes: read again at once. */
  more: boolean;
  /** What the account may not read, in words for the screens. */
  unreadable: string[];
}

/** The same patterns as Logs' mask-secrets step (logs/server/pipeline.ts): change both together. */
export const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[private key masked]"],
  [/\b(authorization|proxy-authorization)(["']?\s*[:=]\s*["']?)(bearer|basic|token|apikey)?\s*[A-Za-z0-9._~+/=-]{8,}/gi, "$1$2$3 ***"],
  [/\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)(["']?\s*[:=]\s*["']?)[^\s"'&,;]{3,}/gi, "$1$2***"],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "$1****************"],
  [/\b(gh[pousr]_)[A-Za-z0-9]{30,}\b/g, "$1***"],
  [/\b(xox[abprs]-)[A-Za-z0-9-]{10,}/g, "$1***"],
  [/\b(sk_live_|rk_live_)[A-Za-z0-9]{10,}/g, "$1***"],
  [/(:\/\/[^:/\s@]+:)[^@/\s]{1,}@/g, "$1***@"],
];

export function mask(s: string): string {
  let out = s;
  for (const [re, repl] of SECRET_PATTERNS) out = out.replace(re, repl);
  return out;
}

const MAX_MSG = 64 * 1024;
/** journalctl's hint when the account sees only its own journal. */
const PARTIAL_JOURNAL = /^Hint: You are currently not seeing messages from other users and the system/;

/** journald fields kept, under the names Logs uses. */
const JOURNAL_FIELDS: Record<string, string> = {
  _SYSTEMD_UNIT: "systemd.unit",
  _PID: "pid",
  _COMM: "process",
  _UID: "uid",
  _TRANSPORT: "journal.transport",
  SYSLOG_FACILITY: "syslog.facility",
  _BOOT_ID: "boot_id",
  CONTAINER_NAME: "container.name",
};

/** MESSAGE is a string, or an array of bytes when it is not valid UTF-8. */
function text(v: unknown): string {
  if (typeof v === "string") return v;
  if (Array.isArray(v) && v.every((b) => typeof b === "number")) return Buffer.from(v as number[]).toString("utf8");
  return v === undefined || v === null ? "" : JSON.stringify(v);
}

function journalEntry(j: Record<string, unknown>): Entry {
  const us = Number(j.__REALTIME_TIMESTAMP);
  const fields: Record<string, string> = {};
  const priority = text(j.PRIORITY);
  // Syslog severities 0 to 7; Logs names them (error, warn, info...).
  if (/^[0-7]$/.test(priority)) fields.level = priority;
  const service = text(j.SYSLOG_IDENTIFIER) || text(j._COMM) || text(j._SYSTEMD_UNIT).replace(/\.service$/, "");
  if (service) fields.service = service;
  for (const [k, name] of Object.entries(JOURNAL_FIELDS)) {
    const v = text(j[k]);
    if (v) fields[name] = mask(v);
  }
  let msg = mask(text(j.MESSAGE));
  if (msg.length > MAX_MSG) msg = `${msg.slice(0, MAX_MSG)}…`;
  return { time: Number.isFinite(us) && us > 0 ? new Date(Math.floor(us / 1000)).toISOString() : new Date().toISOString(), msg, fields };
}

/** Parses read.sh's output. `max` is the OPENASY_MAX the script ran with. */
export function parseRead(out: string, max: number, previous: { journal: string | null; docker: string | null }): Read {
  const sections = new Map<string, string[]>();
  let current = "";
  for (const line of out.split("\n")) {
    if (line.startsWith("@@")) {
      current = line.slice(2).trim();
      sections.set(current, []);
    } else if (current) sections.get(current)!.push(line);
  }
  if (!sections.has("meta") || !sections.has("end")) throw new Error("the read did not finish: no end marker in its output");
  const unreadable: string[] = [];
  const entries: Entry[] = [];
  let journalCursor = previous.journal;
  let more = false;

  const journal = (sections.get("journal") ?? []).filter((l) => l.trim());
  if (journal[0]?.startsWith("@missing")) unreadable.push("journald: journalctl is not on this host");
  let n = 0;
  for (const line of journal) {
    if (!line.startsWith("{")) {
      if (PARTIAL_JOURNAL.test(line)) unreadable.push("the system journal: add the openasy account to the systemd-journal group");
      continue;
    }
    if (n === max) {
      more = true;
      break;
    }
    let j: Record<string, unknown>;
    try {
      j = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    entries.push(journalEntry(j));
    if (typeof j.__CURSOR === "string") journalCursor = j.__CURSOR;
    n++;
  }

  let dockerSince = previous.docker;
  const docker = sections.get("docker");
  if (docker) {
    let container: { id: string; name: string; lines: number } | undefined;
    const skipped = (c: typeof container) => {
      if (c && c.lines > max)
        entries.push({
          time: new Date().toISOString(),
          msg: `logs-agent: container ${c.name} wrote more than ${max} lines since the last read; the rest of them were skipped. Read the host more often.`,
          fields: { level: "warn", service: "logs-agent", "container.name": c.name },
        });
    };
    for (const line of docker) {
      if (!line) continue;
      if (line.startsWith("@missing")) unreadable.push("containers: docker is not on this host");
      else if (line.startsWith("@until ")) dockerSince = line.slice(7).trim();
      else if (line.startsWith("@error ")) {
        const why = line.slice(7);
        unreadable.push(/permission denied/i.test(why) ? "containers: add the openasy account to the docker group" : `containers: ${why.slice(0, 200)}`);
      } else if (line.startsWith("@container ")) {
        skipped(container);
        const [, id = "", ...name] = line.split(" ");
        container = { id, name: name.join(" ") || id, lines: 0 };
      } else if (container) {
        container.lines++;
        if (container.lines > max) continue;
        const m = /^(\d{4}-\d{2}-\d{2}T\S+Z) (.*)$/.exec(line);
        const msg = mask(m ? m[2]! : line);
        entries.push({
          time: m && !Number.isNaN(Date.parse(m[1]!)) ? new Date(m[1]!).toISOString() : new Date().toISOString(),
          msg: msg.length > MAX_MSG ? `${msg.slice(0, MAX_MSG)}…` : msg,
          fields: { service: container.name, "container.name": container.name, "container.id": container.id },
        });
      }
    }
    skipped(container);
  }
  return { entries, cursor: { journal: journalCursor, docker: dockerSince }, more, unreadable: [...new Set(unreadable)] };
}
