# Read-only, run on the host as `sh -s` over SSH (ADR 0031, 0035). It writes nothing and starts nothing that keeps
# running. The agent puts these variables before it, each checked first, so none can carry a command:
#   OPENASY_CURSOR      where the last read of the journal stopped (a journalctl cursor), or empty
#   OPENASY_SINCE       Unix seconds to start from when there is no cursor yet
#   OPENASY_MAX         the most lines to read from each place in one go
#   OPENASY_CONTAINERS  1 to read container logs through Docker
#   OPENASY_DOCKER_SINCE  RFC 3339 time the last container read stopped at
# Sections start with "@@name"; the agent parses them (agent/lines.ts).
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
s() { printf '\n@@%s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
MORE=$((OPENASY_MAX + 1))

s meta
printf 'format 1\nuser %s\ngroups %s\nnow %s\n' "$(id -un)" "$(id -nG)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

s journal
if have journalctl; then
  # Oldest first, one more than the limit so the agent knows whether more are waiting. The hint journalctl prints
  # when the account may read only its own journal goes to the same stream, so the agent can say so.
  if [ -n "$OPENASY_CURSOR" ]; then
    journalctl --no-pager --output=json --after-cursor="$OPENASY_CURSOR" 2>&1 | head -n "$MORE"
  else
    journalctl --no-pager --output=json --since="@$OPENASY_SINCE" 2>&1 | head -n "$MORE"
  fi
else
  echo '@missing journalctl'
fi

if [ "$OPENASY_CONTAINERS" = 1 ]; then
  s docker
  if have docker; then
    # Everything up to now, and the next read starts here: no line is read twice or skipped.
    UNTIL=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "@until $UNTIL"
    docker ps --format '{{.ID}} {{.Names}}' 2>&1 | while read -r id name; do
      case "$id" in
        *[!0-9a-f]*) echo "@error $id $name" ;;
        *)
          echo "@container $id $name"
          docker logs --timestamps --since "$OPENASY_DOCKER_SINCE" --until "$UNTIL" "$id" 2>&1 | head -n "$MORE"
          ;;
      esac
    done
  else
    echo '@missing docker'
  fi
fi
s end
