# Monitor validation

Keep three claims separate: Docker status/logs/controls, Falco JSON display, and
real kernel syscall capture. Mock JSON validates the reader/UI contract; only a
sensor on Oma's native Linux kernel validates capture. No test establishes that
a signal represents a successful breach or escape.

## Regression checks

From the repository root, in an isolated Python environment with
`monitor/requirements-dev.txt` installed:

```bash
python -m pytest monitor/tests -q
```

The real Docker and combined acceptance tests are skipped unless explicitly
configured. They stop/start/restart their target, so use a disposable container.
Do not point them at a live Telegram/provider bot.

## Disposable Docker acceptance

These tests exercise real Docker status/logs/controls and authenticated HTTP with
mandatory MFA. They need no Oma source checkout, provider key, or Telegram token.
Check that `oma-monitor-acceptance` is unused; never point lifecycle tests at the
live bot. Build the standalone image and create a small non-root fixture:

```bash
docker build -t oma-monitor:acceptance monitor
docker run -d --name oma-monitor-acceptance --network none \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges:true \
  --entrypoint python oma-monitor:acceptance -u -c \
  'import time; print("Disposable acceptance target", flush=True); time.sleep(3600)'

OMA_MONITOR_INTEGRATION_CONTAINER=oma-monitor-acceptance \
OMA_MONITOR_ACCEPTANCE_CONTAINER=oma-monitor-acceptance \
  python -m pytest monitor/tests -q -m integration
```

Expected: three tests pass. Do not add `--rm` to this particular fixture: a Stop
would remove it before the tests could Start/Restart it. It has no host mounts or
socket and is removed explicitly afterward. The combined test uses a private
throwaway account database, verifies password-stage API denial, completes MFA,
then checks status/logs, controlled Falco JSON filtering/redaction, and controls.
This is separate from native kernel capture.

For browser acceptance, configure the monitor to select the disposable target:

```bash
OMA_MONITOR_CONTAINER=oma-monitor-acceptance bash monitor/scripts/live.sh start
```

Complete first-login MFA setup in the browser. After stopping that monitor,
remove only the fixture created for this check:

```bash
docker rm -f oma-monitor-acceptance
```

## Real native-Linux Falco test

Oma and Falco must share the native Linux kernel. Render the rules using
`OMA_MONITOR_CONTAINER` for the disposable target; rules and event-file
configuration must agree with the monitor's configured target. Do not run multiple test sensors unnecessarily.

First render and validate the actual rules without kernel privileges:

```bash
python3 -m monitor.render_rules monitor/falco/oma_rules.yaml \
  monitor/.local/falco-events/oma_rules.rendered.yaml
docker run --rm \
  --mount "type=bind,src=$PWD/monitor/.local/falco-events/oma_rules.rendered.yaml,dst=/rules/oma_rules.yaml,readonly" \
  falcosecurity/falco:0.45.0 falco -V /rules/oma_rules.yaml
```

Expected: `/rules/oma_rules.yaml: Ok`. After approval for privileged sensor access,
start the sensor and independent monitor as described in [README.md](README.md).
If they already run, reuse them. Check `docker logs oma-falco-live` for successful
modern BPF probe startup and check that the container remains running.

With the authenticated browser security panel open:

```bash
bash monitor/scripts/live.sh signals
```

The command runs a shell, attempts a localhost TCP connect, and calls
`unshare(CLONE_NEWNS)` as nobody. Expect connection refusal and namespace denial.
Find its unique printed marker in all three corresponding Falco rule events:

- `Unexpected shell or network utility in Oma`
- `Oma outbound connection attempt`
- `Oma namespace or mount manipulation`

Check raw JSON for `source: syscall`, the configured container name, and its ID;
compare the ID with `docker inspect --format '{{.Id}}' omega`. The same marked
events should appear through the authenticated monitor, with `token=[REDACTED]`.
The raw file contains the harmless demonstration token. This helper does not
execute the Docker-socket indicator; its native capture requires a separate,
explicitly approved check.

The separately authorized socket check passed on 2026-10-07. It reused the
existing sensor, temporarily included a unique disposable container name in
the target macro, and restored the original rules afterward. The target used
`--rm`, `--read-only`, `--network none`, `--cap-drop ALL`, user `65534:65534`,
and only a writable `/run` tmpfs. It created/opened an empty regular file at
`/var/run/docker.sock` (resolved to `/run/docker.sock`); it had no host bind
mounts or privileged access. Two Critical alerts matched its actual container
ID and `source: syscall`. The container was removed. This validates the same
socket-path condition with an adapted target selector; it does not test the
live Oma identity, monitor display, Docker daemon control, or escape. See
[validation/docker-socket-2026-10-07.json](validation/docker-socket-2026-10-07.json).

Normal provider/Telegram connections trigger outbound Notices too. High counts
are expected with the current alert-all prototype. Profile and review allowlists;
do not automate containment based on these rules. Keep production sensor tuning,
dropped-event metrics, and log retention separate from this short integration test.

## PR review regression coverage

Unit tests cover individual login, password hashing, viewer/operator permissions,
login/action/logout CSRF, cookie flags, session fixation prevention, server-side
revocation, idle/absolute expiration, quiet-stream shutdown, persistent username
lockout and IP limits, mandatory two-step TOTP/replay rejection, size/time rotation,
timestamped archive retention, reader follow after rotation, and target injection
rejection. CI runs `python -m pytest monitor/tests -q -m 'not integration'` on every
PR. Require its `monitor-unit-tests` status in repository branch protection.

Authentication changed: tests now create temporary individual-account databases
and log in using the CSRF-protected login route rather than Basic Auth headers.
Historical validation records describe the old implementation and are not evidence
for the new login flow. New executed results are recorded separately in HANDOFF.md.


## Review hardening regression checks (2026-10-09)

Run `python -m pytest monitor/tests -q -m 'not integration'`. The expanded suite
covers prefixed/URL/header credentials, stateless pre-login flood resistance,
existing database upgrades, source-scoped login limits, successful audit output,
archive history, timestamp resume, and Falco writer-identity preflight. It also
starts an actual Waitress HTTP server: eight streams remain open, eight additional
requests return 429, and status, another login, and Stop remain responsive.
This test uses a fake Docker backend and does not control real containers.

For an explicitly approved native integration check, first build both images:

```bash
docker build -t oma-monitor:review-hardening monitor
docker build -t oma-falco:review-hardening -f monitor/falco/Dockerfile monitor
python3 monitor/tests/native_falco_check.py --allow-privileged-sensor
```

The flag authorizes a temporary privileged sensor with tracing/proc/etc and Docker
identity mounts. Review that access before running. The `--rm` target is non-root,
unprivileged, network-isolated, has no host mounts or Docker socket, and creates
fake Unix sockets only in its `/run` tmpfs. The harness checks IP connect,
unconnected UDP sendto/sendmsg, socket open/connect (including an alternate
directory), ptrace, process environment access, namespace manipulation, and shell
execution. Sensor and target are stopped/removed in cleanup. Private raw events
remain under `monitor/.local/oma-review-check-*`; a JSON summary is printed.
`sendmmsg` is included in the rule and semantic validation, but this runtime
harness exercises sendto/sendmsg rather than sendmmsg.

Recorded evidence is in `validation/review-hardening-2026-10-09.json`. GitHub
Actions runs need independent verification in the upstream PR; local passing
checks do not prove that upstream Actions settings or protection are enabled.


## Mandatory MFA and Profile acceptance

Run the full unprivileged suite on Python 3.12 and 3.14. New coverage in
`test_profile_mfa.py` exercises first-login enrollment, existing-account MFA,
password-stage access denial, five-minute expiry, cross-stage throttling, atomic
challenge consumption, token replay, migration, and authenticated password/MFA
changes. The HTTP-server test performs both login steps while streams are loaded.

For manual browser acceptance, use a test identity directory and localhost port:

1. Create one operator and one viewer with the host CLI. Neither needs CLI MFA
   enrollment. Start the updated monitor against a disposable target.
2. Sign in with a password. Confirm that a second screen requires QR/manual-key
   setup, and that dashboard/API access is denied until a valid code is confirmed.
3. Sign out. Sign in again: password is followed by a code-only second screen.
   Reused codes must fail; wait for a fresh code. Both roles must complete MFA.
4. Open Profile. A wrong current password/code or missing CSRF must reject changes.
   A successful password change signs out every session; only the new password
   works. Username and role cannot be changed through the profile form.
5. Start authenticator replacement using the old password/code. The session token
   changes before the replacement key is shown. Cancel or let five minutes expire:
   the original factor still works. Confirm the new factor: all sessions close,
   and subsequent sign-in requires the new authenticator.
6. As host administrator run `users disable-mfa USER`. Existing full/pending
   sessions must fail and the next password sign-in must require enrollment again.
7. Verify viewer controls still return 403 and security signals/logs require a
   completed MFA session. Inspect audit output without publishing setup keys/codes.

For migration, back up and stop the old monitor first. Test both an enrolled and
an unenrolled legacy account. Both old cookies must fail after the upgrade; stored
passwords/roles/TOTP keys must remain valid. Restart the new monitor again and
verify its completed MFA sessions are preserved (the migration runs only once).
