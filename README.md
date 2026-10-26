# logs-agent

[![CI](https://github.com/openasy/logs-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/logs-agent/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent of [OpenAsy Logs](https://github.com/openasy/logs). It is installed **once**, next to Logs or in the network
of the hosts, and reads the system journal and, where switched on, container logs of those hosts over SSH. **Nothing
is installed on the hosts** (ADR 0018, 0031, 0035). Hosts that already send their logs over Syslog, OpenTelemetry or a
shipper need no agent.

- **It keeps the keys.** On first start it makes its SSH certificate authority and a fixed key, and keeps them in
  `/data/agent.state`, sealed with its own key-encryption key. Logs never sees a private key.
- **It runs only its own script.** Logs says which host to read and where the last read stopped; the agent checks
  every job again (address, account, port, host keys, the journal cursor), runs the read-only script built into it
  (`agent/read.sh`: `journalctl --after-cursor -o json`, and `docker logs --since` for containers), and signs
  certificates for the `openasy` principal only, valid for 5 minutes. A compromised Logs cannot run commands on any
  host.
- **It masks secrets before they leave.** Values that look like passwords, tokens or keys become `***` on the agent,
  so they never leave the hosts' network.
- **It connects out, never in.** It asks Logs for work and sends lines; Logs never connects to it. It enrols once with
  a one-time token and then uses its own secret (ADR 0023). When Logs is down it keeps asking and says so in
  `/readyz`; the cursor stays with Logs, so no line is lost or read twice.

## Run

Add the agent in Logs under Agents. It shows a one-time enrolment token and this command:

```bash
openssl rand -hex 32 > openasy-agent-kek   # keep it with your backups
docker run -d --name logs-agent --restart unless-stopped --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -v logs-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \
  -e LOGS_URL=https://logs.example.com -e LOGS_ENROLL_TOKEN=olg_... \
  ghcr.io/openasy/logs-agent:0.7.0
```

The agent must be the same version as Logs (ADR 0019); another version is refused.

| Variable | Default | |
| --- | --- | --- |
| `LOGS_URL` | | Where Logs is, such as `http://logs:8080` or its https:// address |
| `LOGS_ENROLL_TOKEN` | | One-time, for the first start only |
| `LOGS_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key that seals the CA, keys and secret |
| `LOGS_AGENT_STATE` | `/data/agent.state` | The sealed state, on its volume |
| `POLL_SECONDS` | `10` | How often it asks for work |
| `CONCURRENCY` | `8` | Hosts read at the same time |
| `OPENASY_KEYS_DIR` | `/keys` | Private keys a host in the hosts file names with `keyFile`; mount it read-only |
| `PORT` | `9100` | `/healthz`, `/readyz` and `/metrics` |

## What a host needs

Logs prints the commands under Hosts with this agent's CA. They create the `openasy` account, trust the CA for that
account only, and add it to `systemd-journal` so it reads the system journal; without that group it reads only its own
journal, and Logs says so. Reading container logs needs the `docker` group, which is equivalent to root on that host,
so it is a separate, opt-in step. No sudo rule is needed.

A host Infrastructure already reads keeps its account and sshd drop-in: this agent's CA is added as a second line of
`/etc/ssh/openasy_ca.pub`, because sshd reads only one `TrustedUserCAKeys` file.

## Develop

```bash
npm install
npm test   # jobs, the read script's output, masking, host setup, the loop
```

## Licence

AGPL-3.0 (ADR 0008).
