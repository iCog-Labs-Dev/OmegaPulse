# Falco runtime sensor

Falco observes the native Linux kernel and reports outbound connections,
namespace/mount operations, shell/network tooling, Docker-socket open/connect
access, process tracing, and process environment access. Datagram sends without
a preceding connect are included. Signals describe attempts, not confirmed compromise. Expected provider
traffic needs profiling and reviewed allowlists before production alerting.

## Configured target

`oma_rules.yaml` is a template. Render it using the same `OMA_MONITOR_CONTAINER`
as the monitor; the default is `omega`. Container names are validated before
substitution, preventing rule/shell injection. Do not load the template directly.

```bash
export OMA_MONITOR_CONTAINER=my-oma
python3 -m monitor.render_rules monitor/falco/oma_rules.yaml \
  monitor/.local/falco-events/oma_rules.rendered.yaml
```

The Docker launcher renders automatically and mounts only the rendered rules:

```bash
bash monitor/scripts/falco.sh
```

The launcher validates the writer identity before starting the sensor. Run it
as the same non-root user as the monitor. If an administrator launches it as
root, explicitly set `OMA_MONITOR_WRITER_UID` and `OMA_MONITOR_WRITER_GID` to
that non-root account's numeric IDs, and prepare `OMA_MONITOR_EVENTS_DIR` owned
by those IDs first. UID/GID 0 and mismatched directory ownership fail before
Docker starts; the writer remains non-root. The launcher does not change host
ownership automatically.

Existing containers retain their launch configuration; changing the environment
requires creating a new sensor with a different `OMA_FALCO_CONTAINER`, after
stopping the previous sensor. Do not run duplicate sensors unnecessarily.

## Timestamped event rotation

The bundled writer receives Falco JSON through persistent `program_output`.
It writes complete JSON lines without buffering to `oma-events.jsonl`, and
renames completed files to `oma-events.<UTC-timestamp>.<unique-suffix>.jsonl`.
Rotation happens before the next record would cross the size threshold, or when
an interval has elapsed and the next record arrives. There is no idle empty-file
rotation. The active filename stays stable for the monitor's read-only reader.

| Variable | Default |
| --- | --- |
| `OMA_MONITOR_LOG_MAX_BYTES` | `20480` (20 KiB) |
| `OMA_MONITOR_LOG_INTERVAL_SECONDS` | `3600` (one hour) |
| `OMA_MONITOR_LOG_KEEP` | `100` archives, plus the active file |

Example:

```bash
OMA_MONITOR_LOG_MAX_BYTES=20480 OMA_MONITOR_LOG_INTERVAL_SECONDS=3600 \
  bash monitor/scripts/falco.sh
```

A single JSON record larger than the threshold is kept intact in its own file;
records are never split. The maximum accepted record is 1 MiB. Retention deletes
old archives; copy them elsewhere if durable evidence is required. Archives
removed before a reader catches up cannot be replayed. Use one writer
per directory. These event files contain raw command metadata and require private
storage. The Docker launcher runs the writer as the operator's UID/GID, while the
sensor keeps its previously reviewed kernel privileges.

## Host installation

1. Install Falco and Python 3 separately on the native Linux host.
2. Render the target template and load the result after Falco's default rules.
3. Install `monitor/event_writer.py` at `/writer/event_writer.py` (or adjust the
   program path), create a private writable event directory, and merge
   `falco-output.fragment.yaml` into the reviewed Falco configuration.
4. Configure the writer environment with `OMA_MONITOR_WRITER_FILE` (default
   `/events/oma-events.jsonl`) and the rotation variables above. Optionally set
   both `OMA_MONITOR_WRITER_UID` and `OMA_MONITOR_WRITER_GID` to drop the writer's
   privileges. Run Falco unbuffered, with native file output disabled so it does
   not compete with the rotating writer.
5. Give the monitor read-only directory access and set
   `OMA_MONITOR_SECURITY_EVENTS_FILE` to the active JSON-lines path. Check writer
   errors in Falco's service logs; file availability alone does not prove capture.

## Access

The Docker sensor image installs Python for the writer and preserves Falco's
modern eBPF driver. The launcher uses privileged kernel access and reviewed host
mounts. The monitor does not expose Falco's control surface. Validate capture,
false-positive volume, and dropped-event metrics on the native deployment host.

Reference: [Falco output channels](https://falco.org/docs/concepts/outputs/channels/).

The pathname rule also matches alternate directories with a `docker.sock`
basename. Arbitrarily renamed sockets and renamed shell binaries need additional
reviewed rules; the supplied rules are indicators, not comprehensive detection.
