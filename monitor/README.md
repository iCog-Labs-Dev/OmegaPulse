# Oma container monitor

An independent, authenticated monitor for one existing Oma Docker container.
It provides Start, Stop, and Restart, live Docker logs, and optional Falco runtime
signals. It does not change Oma's reasoning, providers, channels, or launch workflow.

## How it works

Three separate containers have different jobs:

| Component | Job |
| --- | --- |
| Oma (`omega`) | Runs the agent with its own provider/channel configuration |
| Falco (`oma-falco-live`) | Observes kernel syscalls and writes security events |
| Monitor (`oma-monitor-live`) | Provides browser authentication, Docker controls, logs, and the event display |

The monitor reads Docker status/logs through the Docker socket. Falco writes
JSON-lines events through a rotating writer to a shared host directory; the monitor reads that directory
read-only and streams matching, redacted events to the browser. Falco runs
separately because its eBPF sensor needs privileged kernel access, while the web
application does not need to run as a privileged container. Each can be restarted
independently. Docker controls and logs work without Falco; real syscall signals
require a working Falco sensor.

### What Falco watches and what access it has

The rule template is [falco/oma_rules.yaml](falco/oma_rules.yaml). The launcher
renders its target from `OMA_MONITOR_CONTAINER` (default `omega`), matching the
monitor configuration:

| Rule | Watched operation | Priority |
| --- | --- | --- |
| Outbound connection | IPv4/IPv6 `connect`, `sendto`, `sendmsg`, `sendmmsg` attempts | Notice |
| Namespace/mount manipulation | `setns`, `unshare`, `mount`, `umount`, `umount2` | Warning |
| Shell/network utility | `execve`/`execveat` for the listed shells and network tools | Warning |
| Docker-socket access | Open/connect attempts to paths with a `docker.sock` basename | Critical |
| Process tracing | `ptrace` attempts | Warning |
| Process environment access | Opening `/proc/*/environ` | Warning |

[scripts/falco.sh](scripts/falco.sh) is the complete sensor launch command. It
selects `engine.kind=modern_ebpf` and uses `--privileged`, which grants broad
host capabilities/device access to the sensor container. The read-only mounts
do not remove those privileges. Kernel observation happens at the host level;
the rules restrict which observed events are reported, not the sensor's access.

The tracing filesystem, host `/proc`, host `/etc`, and rule file are mounted
read-only. The host Docker socket is mounted for container identity lookup and
also grants Docker daemon control; it must be treated as privileged access.
The event directory is writable so Falco can emit JSON. Only the sensor gets
these kernel permissions; no such permission or socket is added to Oma by the
sensor launcher. The monitor itself has a separate Docker socket mount for its
authorized lifecycle controls.

These rules report attempts and metadata. They do not inspect packet contents,
classify every possible escape technique, or block syscalls. The monitor displays
the events; it does not automatically stop Oma in response to them.

## Quick start with real security signals

Prerequisites: native Linux, a running Docker Engine accessible through plain
`docker` commands, and an existing Oma container named `omega`. Both launchers
use the local `/var/run/docker.sock`; no `sudo` is used. The Falco launch uses
`--privileged` to observe this host's kernel and should be reviewed by its operator.

From the repository containing this `monitor/` folder, after starting Oma normally:

```bash
docker ps --filter name=omega
bash monitor/scripts/falco.sh
bash monitor/scripts/live.sh start
```

Create your individual operator account when prompted, then open `http://127.0.0.1:8765/`.
Check container status, live logs, and the security panel. Start/Stop/Restart
buttons act on Oma; the shell launcher's stop/resume commands act on the monitor.
Generate three controlled security indicators with:

```bash
bash monitor/scripts/live.sh signals
```

Find the printed marker in the security panel. The `signals` helper generates
attempts; Falco must already be running to capture them. The disposable native
test stops/removes its own sensor and does not leave a sensor running for the
browser. Both live launchers must use the same `OMA_MONITOR_CONTAINER` and
`OMA_MONITOR_EVENTS_DIR`. Connection refusal and `unshare` errno 1 are expected;
missing browser alerts mean the capture/file/stream path needs checking.

To inspect sensor startup or stop only the sensor:

```bash
docker logs --tail 50 oma-falco-live
docker stop oma-falco-live
```

Resume an existing stopped sensor with `docker start oma-falco-live`; the Falco
launcher deliberately refuses to overwrite an existing container. Set
`OMA_MONITOR_CONTAINER` before launching both components for a differently named
Oma container. The Falco launcher validates and renders this setting automatically.

## Start separately from Oma

Run Oma using its normal setup. The monitor needs Docker access and a browser
login; it does not need your OpenRouter key or Telegram token.

On native Linux, from the repository root:

```bash
bash monitor/scripts/live.sh start
```

This builds the small monitor image using only `monitor/`, prompts for the browser
individual operator account/password (at least 12 characters), and starts it at
`http://127.0.0.1:8765/`. It never starts, removes, renames, or recreates Oma.
The monitor container runs as your user with the Docker socket's group.

Accounts persist in the private `monitor/.local/auth/` directory. Rebuilding the
monitor preserves them. A replaced monitor is kept under a timestamped backup
name. Stop/resume affect only the monitor:

```bash
bash monitor/scripts/live.sh stop
bash monitor/scripts/live.sh resume
```

The launcher assumes native Linux and a local `/var/run/docker.sock`. For a
Python process instead, create a venv, install `monitor/requirements.txt`, set
`OMA_MONITOR_AUTH_DB`, run `python -m monitor.users add alice --role operator`,
then run `python -m monitor.app` from the repository root. For local HTTP only,
set `OMA_MONITOR_COOKIE_SECURE=false`; HTTPS uses the secure default. See
`.env.example` for configuration placeholders.

## Individual users, roles, and MFA

The login page uses individual accounts with scrypt password hashes. There is no
shared login, default password, or Basic Auth fallback. Roles are enforced on the
server: `viewer` can read status/logs/events; `operator` can also Start/Stop/Restart.
Account administration is a local CLI operation requiring access to the private
identity database; a web operator cannot create users or promote their role.

```bash
bash monitor/scripts/live.sh users add alice --role operator
bash monitor/scripts/live.sh users add bob --role viewer
bash monitor/scripts/live.sh users role bob --role operator
bash monitor/scripts/live.sh users password alice
bash monitor/scripts/live.sh users disable bob
bash monitor/scripts/live.sh users list
```

Passwords are entered through hidden prompts, never command arguments or Docker
credential environment variables. `OMA_MONITOR_AUTH_DIR` selects the Docker
identity directory; `OMA_MONITOR_AUTH_DB` selects the Python process database.
Protect the database and backups: they contain password hashes and MFA secrets.

Optional authenticator-app MFA is enabled per account:

```bash
bash monitor/scripts/live.sh users mfa alice
```

MFA adds a second check if someone steals a password; it does not replace the
password. To enroll:

1. Run the command above, replacing `alice` with your account name.
2. Add the printed private `otpauth://` URI to a TOTP authenticator app. For
   manual setup, use the value after `secret=` and before the next `&` as the
   key, choose time-based/TOTP, and use your username as the account label.
3. Enter the app's current six-digit code at the terminal prompt. An arbitrary
   six-digit number will not work. Each enrollment attempt generates a new
   secret; use the URI from the latest attempt. Invalid confirmation leaves
   the account's MFA configuration unchanged.
4. Sign in with **username, password, and the current authenticator code**.
   Do not leave the password empty. Accounts without MFA leave only the code
   field empty. Reused login codes are rejected; wait for the next code when
   signing in again. Keep phone/computer clocks synchronized if codes fail.

Keep the enrollment URI/key private; it can generate your account's codes.

### Account recovery and administration

Run these commands from this repository using the same `OMA_MONITOR_AUTH_DIR`
as the running Docker monitor. Replace `alice` with the account to manage:

| Task | Command |
| --- | --- |
| Reset a forgotten password | `bash monitor/scripts/live.sh users password alice` |
| Disable MFA after losing the authenticator | `bash monitor/scripts/live.sh users disable-mfa alice` |
| Enroll a replacement authenticator | `bash monitor/scripts/live.sh users mfa alice` |
| Disable an account | `bash monitor/scripts/live.sh users disable alice` |
| Restore a disabled account | `bash monitor/scripts/live.sh users enable alice` |
| Inspect account roles, enabled status, and MFA status | `bash monitor/scripts/live.sh users list` |

Password reset prompts for the new password twice and **does not disable MFA**.
Password, role, enabled-status, and MFA changes revoke existing sessions; sign
in again afterward. Recovery requires a host administrator with access to the
private database, not a browser user. No public registration or self-service
password reset is exposed. If login is temporarily rate-limited, wait for the
15-minute window to expire; resetting the password does not clear that limit.

Authenticated session cookies are opaque, HttpOnly, SameSite=Strict, and Secure by default.
The local launcher allows HTTP cookies only on loopback. Logout deletes the
server-side session, and account/password/role/MFA changes revoke all that user's
sessions. Sessions expire after 15 minutes without page navigation/control
requests or after eight hours absolutely. Background polling and SSE do not
extend idle lifetime. Event streams also check revocation while quiet. The server admits at most eight
streams total and four per account (two dashboards), reserving eight of its 16
workers for login, status, and controls. Additional streams get HTTP 429; close
extra dashboards to reconnect. This bounds streaming load, not arbitrary HTTP floods.

Login is limited to five failed attempts per username/source-IP pair and 20 total attempts per
source IP in a rolling 15-minute window; blocked requests return HTTP 429.
Limits persist across restarts and cannot be bypassed by `X-Forwarded-For`.
Failures from another source address do not lock the account globally. Clients
sharing one address (including a reverse proxy or local users) share its limit.
Pre-login CSRF cookies are signed, expire after five minutes, and create no
database sessions; repeated login-page requests cannot fill the session table.
Refresh the login page if it has been open for more than five minutes before
submitting credentials.
Behind a reverse proxy, the observed source is the proxy; configure trusted
proxy handling at the deployment boundary if per-client limits are needed.

## Optional real Falco signals

Falco must run on the same native Linux kernel as Oma. After approving privileged
sensor access on a local/staging host, start it separately:

```bash
bash monitor/scripts/falco.sh
```

The sensor and monitor launchers share `monitor/.local/falco-events/` by default.
This directory is Git-ignored. Both accept `OMA_MONITOR_EVENTS_DIR` to select an
existing event directory. For example, to keep using our original live sensor:

```bash
export OMA_MONITOR_EVENTS_DIR="$PWD/.oma-monitor-local/falco-events"
bash monitor/scripts/live.sh monitor
```

With the browser's security panel open, generate controlled indicators:

```bash
bash monitor/scripts/live.sh signals
```

Find the printed marker in three new events: shell execution, outbound connect,
and namespace/mount manipulation. The helper runs as nobody inside the configured
Oma container. Connection refusal and namespace permission denial are expected;
the rules detect attempts. It does not access or create a Docker socket file.
The raw file retains the demonstration token; the browser redacts it.

Frequent outbound Notices are expected: the prototype reports every IPv4/IPv6
connect attempt, including ordinary provider and Telegram requests. Signals are
not breach verdicts. Profile expected destinations/processes before introducing
reviewed allowlists. No automatic Stop or containment is enabled.
See [falco/README.md](falco/README.md) for the sensor integration contract.

The Docker-socket rule detects Oma opening `/var/run/docker.sock` or
`/run/docker.sock`. Access to a real Docker daemon socket can allow control of
other containers and the host, so this is a critical indicator. The native test
initially skipped this rule; a subsequently authorized disposable-container test
produced Critical syscall alerts by creating/opening an empty regular file at
that path inside `/run` tmpfs. It used `--rm`, user `nobody`, no host mounts,
no network, and no privileged access. The existing sensor's target macro briefly
included the disposable name, then was restored. This validates pathname-based
detection, not access to a Docker daemon or a successful escape. Evidence is in
[validation/docker-socket-2026-10-07.json](validation/docker-socket-2026-10-07.json).
Never mount the host Docker socket into Oma just to generate this indicator.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `OMA_MONITOR_AUTH_DB` | `monitor/.local/auth/users.sqlite3` | Private individual-account/session database |
| `OMA_MONITOR_COOKIE_SECURE` | `true` | HTTPS-only cookies; false allowed only on loopback |
| `OMA_MONITOR_CONTAINER` | `omega` | Fixed target container |
| `OMA_MONITOR_HOST` | `127.0.0.1` | Python server bind address |
| `OMA_MONITOR_PORT` | `8765` | Server port |
| `OMA_MONITOR_SECURITY_EVENTS_FILE` | disabled | Falco JSON-lines file for Python setup |

The Docker launcher fixes the server to localhost and maps its shared event file
to `/events/oma-events.jsonl`. `OMA_MONITOR_DOCKER_NAME` selects its own container
name; `OMA_FALCO_CONTAINER` selects the sensor container name. The sensor renders
the same `OMA_MONITOR_CONTAINER` into its rules. Set it before launching both.

## Authorization

The dashboard and monitoring APIs require an authenticated server-side session. Lifecycle
requests also require POST JSON, a CSRF header, browser confirmation, and serialized
Docker operations. Start only starts an existing container; it never recreates one.
Logs/events are rendered as text, redacted on a best-effort basis, and bounded to
1,000 log records and 500 security records in the browser. Falco JSON is filtered
to the configured container. Streams recover after stops, Docker failures, and
container/event-file replacement.

Docker socket access gives the monitor privileged host control. Restrict its
operator account and keep it on localhost, through SSH, or behind HTTPS.
Passwords are stored as hashes in the private identity database, not in the
repository or browser storage. Do not use `bash -x` when entering secrets.

## Major limitations and improvements

- **Detection tuning:** Falco signals describe attempts, not confirmed breaches.
  Outbound rules include normal traffic; production use needs reviewed allowlists
  and false-positive tuning. Automatic containment is not implemented.
- **Retention:** Falco files rotate by size/time with timestamped archives and
  bounded retention; archives removed before the reader catches up cannot be replayed.
  Central audit storage and off-host archival remain separate.
- **Health visibility:** Docker “running” does not establish agent health, and a
  readable event file does not establish sensor health. Explicit health checks
  remain future work.

Detailed test coverage and verification caveats are recorded in [TESTING.md](TESTING.md)
and [HANDOFF.md](HANDOFF.md).

## Validation

Install `monitor/requirements-dev.txt` in a test environment and run:

```bash
python -m pytest monitor/tests -q
```

Real Docker lifecycle tests are opt-in and must target a disposable container.
See [TESTING.md](TESTING.md) for mock services, combined acceptance, and native
Falco capture checks; [HANDOFF.md](HANDOFF.md) records executed results and limits.

## CI and required checks

`.github/workflows/monitor-tests.yml` runs the unit suite and shell syntax checks
on every pull request, without path filters or continue-on-error. Real Docker
integration tests are explicitly excluded from this unprivileged unit job.
The repository maintainer must enable branch protection/rulesets on `main` and
require the `monitor-unit-tests` status check. A workflow file alone cannot
prevent merges or configure that repository-level setting.

## Migration from Basic Auth

Old `OMA_MONITOR_USERNAME` / `OMA_MONITOR_PASSWORD` values are no longer used.
Run the updated launcher to create individual accounts; old browser-cached
credentials do not grant access. Preserve the existing event directory using
`OMA_MONITOR_EVENTS_DIR` if needed. Existing old sensor containers still use
unrotated native file output; adopting the writer requires a newly built sensor.
Review kernel privileges before switching, and avoid running duplicate sensors.


### Reviewing operational gaps

Successful logins and lifecycle actions are emitted at INFO to the monitor's
stderr with timestamps and usernames; inspect them with `docker logs` on the
monitor container. Passwords, MFA codes, and session tokens are never audited.
Container output is redacted before display, including prefixed environment
secrets, authorization headers, provider keys, and Telegram URL tokens. This is
best-effort filtering; raw Docker/Falco files still require private storage.

A new security stream loads up to 100 recent records across the active file and
retained archives, bounded to 1 MiB of input. Default retention is 100 archives
of 20 KiB plus the active file (about 2 MiB); configure `OMA_MONITOR_LOG_KEEP`
for your traffic volume. This is a size bound, not a guaranteed time window.
Log streams resume using Docker timestamps after restart; records at the resume
boundary are deduplicated. Extremely busy boundaries exceeding 2,000 distinct
lines may replay duplicates, and deleted Docker history cannot be recovered.

Falco covers IP connect/datagram-send attempts, namespace operations, selected
shell/tool names, Docker-socket open/connect paths ending in `docker.sock`,
ptrace, and opening `/proc/*/environ`. It cannot identify every renamed executable
or a Docker socket mounted under an arbitrary filename. Tune additional rules
against the application before treating these signals as confirmed compromise.


If no CI checks appear on a fork PR, the upstream maintainer should check
**Actions** is enabled and look for **Approve workflows to run** on the PR.
The workflow uses `pull_request` and read-only permissions. Both Python 3.12
and 3.14 must pass before the aggregate `monitor-unit-tests` check passes.
`workflow_dispatch` also permits manual runs once the workflow is available on
the repository's default branch. Enabling Actions, approving a fork run, and
requiring the check are repository settings; code alone cannot perform them.
