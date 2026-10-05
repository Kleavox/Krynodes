# Krynodes

Krynodes is a small, self-hosted monitoring console on Cloudflare Workers. A Go
agent on each server reports metrics and runs HTTP, TCP and systemd checks; the
Worker stores history in D1, opens and resolves incidents, and mails the
operator. The dashboard sits behind Cloudflare Zero Trust; one login can be
shared by a small team, and every open tab sees what the others do as it
happens.

```text
Browser ── Cloudflare Access ── kry Worker ── D1
                                     ▲    │
                      kry (agent) ┘    └── send_email → operator
```

## Layout

| Path                | What                                                                                                           |
| ------------------- | -------------------------------------------------------------------------------------------------------------- |
| `worker/`           | Hono Worker: dashboard API, agent API, D1 migrations, daily retention cron; the `stats` Worker in `src/stats/` |
| `app/`              | React dashboard (Tailwind v4, shadcn/ui, Recharts, TanStack Query)                                             |
| `agent/`            | Go agent: metrics, checks, enrollment, systemd install                                                         |
| `packages/protocol` | Zod schemas for the agent ↔ Worker contract, with a fixture the Go tests read too                              |
| `tooling/`          | TypeScript presets, Vite config, lint scripts                                                                  |

## Develop

```sh
pnpm install
pnpm turbo run build --filter=@krynodes/worker^...
pnpm exec wrangler dev --config worker/wrangler.jsonc --port 8790
```

With no Access variables set, the Worker runs as a local standalone operator,
so the dashboard opens without signing in. Production refuses to serve at all
without Access (see below). Emails are simulated locally and written under
`worker/.wrangler/tmp/email/`.

Rebuild the app and restart `wrangler dev` after every app change; it serves the
built assets from `app/dist`.

## Check

```sh
pnpm check         # format, knip, lint scripts, typecheck, tests, build
pnpm native:check  # go test, vet, build, deadcode
```

CI (`.github/workflows/ci.yml`) runs the same steps on every push to `main`, then
its `deploy` job ships the Worker to `kry.kleavox.xyz` when the app or Worker
changed. **Run workflow** on the Validate workflow deploys by hand.

## Production

- **Access.** Put the dashboard hostname behind a Cloudflare Access application.
  The Worker verifies the Access token itself and answers 401 without one.
- **Agents** report to the Worker's `workers.dev` address (`AGENT_ORIGIN`),
  outside the zone, so zone bot protection cannot challenge them.
- **Configuration.** `env.production` in `worker/wrangler.jsonc` holds the
  public values. The GitHub environment `production` supplies the rest:
  secrets `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `KRY_D1_ID`,
  `ALERT_EMAIL`, and variables `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`.
- **Bindings.** D1 `DB`, `send_email` `EMAIL` (the operator's address verified
  in Email Routing), static assets `ASSETS`.

## Agent

The agent is a single binary, `kry`. **Enroll node** in the dashboard gives one
command to paste on the server:

```sh
curl -fsSL https://<agent-host>/install.sh | sudo sh -s -- https://<agent-host> <token>
```

It downloads the latest release for the server's architecture, checks its
SHA-256, installs `/usr/local/bin/kry`, enrolls the node, and starts the
`krynodes` systemd service (config in `/etc/kry/config.json`). The node takes
the server's hostname as its name (**Rename node** changes it) and reports every
minute. The script is
`app/public/install.sh`, served as a static asset. Afterwards:

```sh
sudo systemctl status krynodes
sudo kry status
```

Releases are cut by `.github/workflows/agent-release.yml` whenever
`agent/VERSION` changes on `main`, as `agent-v<version>` with `krynodes-linux-amd64`
and `krynodes-linux-arm64`, their checksums, ed25519 signatures and build
provenance. The workflow signs with the repository secret `AGENT_SIGNING_KEY`
and refuses to publish if it does not match `agent/internal/update/release.pub`.

### Checks

Checks run on the agent of the server they belong to: HTTP (down on errors,
timeouts and 5xx answers), TCP (down when the connection fails) and systemd
(up while the unit is active). From agent 0.3.4 a failing check is tried twice
more, 5 seconds apart, before the agent reports it down, and an incident opens
only at the second such report in a row. A check's menu on the Checks page or the node
page has **Edit** (name, server, kind, target, timeout), **Pause** / **Resume**,
**Status page** and **Remove**, which asks first. Changing what is checked (kind,
target or server) or pausing starts the status fresh and closes an open
incident; the history stays. A server with a live connection (below) runs the
changed check within seconds; others at their next report.

From agent 0.4.0 a SERVICE check's menu has **Restart automatically**: one
switch. When the check turns red (an incident opens; never while it is yellow
or during planned work) the Worker queues a restart of its unit, once per
incident. The server only restarts a unit it was told to with a fingerprint,
that is not running, that you did not stop from Krynodes, and at most 3 times
an hour. Turning it on needs a fingerprint, turning it off does not; the row
shows `AUTO`, and the failure mail says the unit is being restarted. Removing
the check or pointing it at another unit turns it off.

Removing a check, pausing it or changing its kind, target or server asks for
a trusted device's fingerprint (see Deploy), like deleting a server or creating
an install command. One fingerprint covers 5 minutes of such work. An owner
with no trusted device yet is not asked.

Incident mail goes out the moment a failure is confirmed, one mail per server
for that report ("pivox: 2 checks down — Health, API"). A server that stops
reporting mails at once too ("pivox: offline"), at the moment the dashboard
turns it Offline: no report for three intervals, at least 90 seconds. Each
check and each server mails its first failure in an hour; later failures in
that hour, recoveries and "back online" never mail. While an action runs on a
server and for 2 minutes after it (10 minutes after a restart, until the agent
is back), failing checks there open no incident, a silent server is not called
offline, and the bars read "maintenance"; anything still down afterwards mails
then. Actions and deploys never mail. Mail shows times in UTC; the dashboard
and the status page use the browser's time zone.

### Live connection

Each server keeps one WebSocket open to the Worker (`/api/agent/stream`), held
by a Durable Object (`FleetHub`, one per owner, SQLite class, Free plan). From
agent 0.3.1 everything travels over it: reports, config and action results.
The dashboard can wake a server at once: queued actions, check changes, update
and refresh requests, and applied trust changes reach it in seconds instead of
up to a minute.

- History is one D1 row per server per 5-minute window (`node_windows`), with
  the averaged metrics and every check's result; the hub writes it when the
  window ends or the connection closes. Failures keep their message.
- The server row is written when the connection opens, once per window and
  when it closes; between those the dashboard asks the hub, so a server still
  shows offline after about 3 minutes of silence.
- There is no HTTP fallback. The agent sends a `ping` every 25 seconds, drops
  a connection that stays silent for 75 seconds and reconnects after 1 second,
  doubling to 1 minute (with jitter). Cloudflare closes every connection on a
  deploy or restart; agents are back within seconds and report at once.
- Agents before 0.3.1 are not supported. The live connection refuses them
  (426) and the old HTTP report routes answer 410 `AGENT_UPDATE_REQUIRED`; the
  node page shows the command to update such a server by hand.
- At a 60-second interval a server costs about 870 D1 writes a day on a live
  connection and about 2,000 on HTTP (was about 4,900).

Dashboards use the same hub: each tab opens `GET /api/live`, a WebSocket that
only says what changed (servers, checks, actions, services). The tab then
refetches those lists, so when one person restarts a service everybody's
screen shows it within a second or two. Tabs keep their usual polling as the
fallback and reconnect on their own.

### Usage and quota shares

The fleet page's **Krynodes quota** tile opens **Usage today**: Krynodes'
requests, D1 writes and D1 reads against its share of the account's free
quotas (editable there; other projects may share the account), and the whole
account against the Free plan. Quotas reset at 00:00 UTC.

Without setup the numbers are estimates. For Cloudflare's real counts, create
an API token with one permission (Account, Account Analytics, Read) and save it
as the GitHub production secret `CF_ANALYTICS_TOKEN`; the next deploy hands it
to the Worker together with the account and database ids it already has. The
Worker asks Cloudflare at most every 15 minutes while someone looks.

### Updating the agent

The Worker checks GitHub for the latest `agent-v*` release once a day (or on
**Check now**); agents never poll GitHub. Each server shows its agent version,
with an arrow when it is behind, and the **Updates** filter lists them.

- **Update agent** (node detail) or **Update N** (Fleet) asks the agent to update
  on its next report. The agent drops the request in
  `/var/lib/kry/update-request`; the root unit `krynodes-update.path` starts
  `kry self-update`, which downloads the release from this repository, checks
  the SHA-256 and the signature against the key built into the agent, refuses
  downgrades, keeps the old binary as `kry.previous` and restarts.
- From agent 0.3.1 the download suits slow links: it fetches the gzip asset
  (about 2.6 MB instead of 6.5 MB), gives up on an attempt only after a minute
  without data, resumes where it stopped, and tries five times. The new binary
  must print its version before it is installed, and if the agent does not stay
  up after the restart the old binary comes back. Why an attempt failed shows
  on the node page.
- A stalled update is asked for again after 15 minutes, three attempts in all,
  before the dashboard calls it failed. Releases are published only once every
  file is uploaded.
- **Update automatically** (per node) requests every new release as soon as the
  Worker sees it.
- **By hand**, on the server:

```sh
curl -fsSL https://<agent-host>/install.sh | sudo sh -s -- --update
```

### Service actions

The dashboard's **Services** page lists each server's systemd units and Docker
containers, grouped by server, and starts, stops or restarts them. The node
page and Ctrl K offer the same actions, and a SERVICE check's menu has
**Restart service**. From agent 0.2.1 every one of them needs a fingerprint,
like a deploy (see below): a server that trusts no device refuses them.

From agent 0.2.2 the node page's **Actions** menu (and Ctrl K) also has
**Restart server**: after a confirmation and the same fingerprint, `kry exec`
reports "restarting the server" and then runs `systemctl reboot --no-block`.
Each server on the Services page carries the same menu.

Everything in flight is visible to everyone: the server reads
"Restarting · owner · 1:12" on every page until its agent reports again, its
services wait with their buttons hidden, a service being restarted shows who
asked and for how long, and the hourglass button in the top bar lists what
runs or waits now. **History** (its own tab) lists the actions of the last 90
days by day, with who asked, from which device, the outcome and how long it
took, and filters by server; trust updates stay in **Recent changes**. There
are no pop-up toasts for other people's work.

From agent 0.3.3 a service's or stack's menu has **Logs**: the last 300 lines
(`journalctl -u`, `docker logs`, `docker compose logs`), at most 64 KiB, signed
like any action and allowed for protected units because it only reads.

The agent never runs anything itself:

- It drops each request in `/var/lib/kry/actions`.
- The root oneshot `kry exec` does the work. The units `krynodes-exec.path` and
  `krynodes-exec.timer` start it, the timer every 5 minutes to refresh the list of
  services.
- `kry exec` refuses anything but a signed start, stop, restart or log read of
  a service that is present on the server; from agent 0.4.0 also a signed stack
  start, stop, restart or removal, a container removal, a new stack (checked
  first, see below) and the auto-restart list. The only unsigned requests it
  takes are turning auto-restart off and restarting a listed unit that is down.
- It never starts, stops or restarts ssh, the network, Docker itself, systemd
  internals, cloudflared or Krynodes; it only reads their logs.
- It keeps its state in `/var/lib/kry-exec`.

`kry uninstall-service` removes these units and that directory.

### Deploy

From agent 0.2.0 the **Stacks** view of the Services page deploys Docker
Compose stacks: `docker compose pull`, then `up -d`, in the stack's own
directory, with its own compose files. A failed deploy keeps the images that
ran before it, and **Roll back** starts them again.

Servers with Docker and Compose show the Docker logo on Fleet, Services and the
node page (faded when Compose is missing; agent 0.4.0 reports it). From agent
0.4.0 a stack's menu also has **Start**, **Stop**, **Restart**, **Remove** and
**Delete permanently**, and a container's menu has **Remove**. A removed
container leaves the list as soon as its server confirms.

**Remove** takes a stack's containers and networks down and moves it to
**Removed**, under the stack list. It waits there for 7 days with its volumes
and compose files: **Restore** starts it again (with a fingerprint), and
**Delete permanently** deletes it at once. After 7 days the server deletes it
by itself. **Delete permanently**, on a running or a removed stack, deletes its
containers, networks and volumes, and the folder Krynodes made for it; a folder
elsewhere (a stack you started yourself) stays. Type the name to confirm.
Images stay. A stack started again outside Krynodes leaves Removed with nothing
deleted, and New stack refuses a name that waits there.

**New stack** (Stacks view) runs a pasted `compose.yml` on a server, also a
project that is not yours. The text is signed into the command. The server
writes it to `/var/lib/kry-exec/compose/<name>`, resolves it with
`docker compose config` and refuses, naming the service and the reason, a file
that builds from source, asks for privileged mode, extra capabilities or
devices, shares the server's network, processes or namespaces, turns off
confinement, mounts anything outside its own folder (also through a symlink),
uses an external or host network or volume, or includes other files. Published
ports are bound to `127.0.0.1`; reach them through a Cloudflare Tunnel. Then
it pulls, starts and health-checks the stack like a deploy. Do not paste
passwords you use elsewhere: the text is kept with the action in History.

Deploys, like start, stop and restart, need a fingerprint. On **Trusted
devices** (account menu) you register a passkey on your laptop or phone; each
server keeps the public keys in `/var/lib/kry-exec/trust.json`, and the root
executor checks every action against them, so nothing on Cloudflare can run one
on its own. One fingerprint opens a 5-minute session, like sudo. It ends at
once when the page is hidden (another tab or app in front, the screen locked, a
phone screen off) and is checked against the clock before every signature, so
a laptop that slept needs a new fingerprint. Nothing on screen shows whether a
session is open. Agents and the Worker accept sessions of at most 15 minutes.

From agent 0.3.0 one admin login can be shared safely by several people, and
from agent 0.3.5 the rules are these:

- **Trusted devices** are the passkeys every server knows. Each one reaches
  (may run actions on) only the servers it is given. A device someone
  registers waits until it is approved, and you get an email.
- The first device trusts itself on your servers (**Trust on servers**). The
  second one, such as your phone, is approved by the first and reaches every
  server enrolled then.
- With one or two trusted devices, one approval adds or removes a device.
  With more than two, two approvals from two different devices.
- A device's ⋯ **Servers** chooses the servers it reaches; a server's ⋯
  **Devices** shows who reaches it, and **Remove every device** takes them all
  away. A server is given to a device only by another device that already
  reaches it, never by the device itself; when nobody else reaches it, by one
  other trusted device (two when there are more than two). Servers enrolled
  later start with the devices and nobody reaching them.
- A passkey already registered, under any name, cannot be set up again.
- Servers below agent 0.3.5 still take server changes, but adding or removing
  devices waits until every server runs it.
- Changes wait under **Waiting for approval** for up to 24 hours. Each approval
  signs the exact change; the dialog shows new devices' key fingerprints for
  you to compare with the new device's screen.
- **Recent changes**, under the devices and servers, lists every closed change
  newest first ("Give Budi access to pivox"): its outcome, who opened and
  approved it and when, and any server that has not taken it yet.
- Every approval, session and confirmation needs a passkey that verifies you:
  the fingerprint by default, a face on Windows Hello, a Mac or an iPhone, or a
  security key such as a YubiKey. A touch alone ("a finger is there") is
  refused by the browser, the Worker and every server (agent 0.3.5); a passkey
  that only takes a touch (such as Microsoft Password Manager) cannot join, and
  one trusted earlier reads **Cannot sign** until it is removed and set up
  again. There is no passphrase and no setting to turn this off.
- On a computer without a fingerprint reader, choose **Use a phone** in the
  passkey window: the phone's own passkey signs, so the phone is the trusted
  device. It joins as "Phone"; a security key joins as "Security key".
- WebAuthn only reports that the person was verified, not how, so a device or
  security key PIN counts the same as a fingerprint. Keep those PINs private.
- Keep two fingerprint devices or more: with one, losing it needs SSH to
  recover. With two, the other removes a lost one alone.

To start over on a server:

```sh
sudo kry trust --reset
```

## Data retention

A daily cron (03:17 UTC) keeps the database small enough for the Free plan's
500 MB and its daily write quota. **Usage** shows the database size.

| Data                               | Kept                               |
| ---------------------------------- | ---------------------------------- |
| Server metrics (5-minute windows)  | 8 days                             |
| Check results                      | latest per check only              |
| Incidents                          | while open, then 180 days          |
| Actions (**History**)              | 90 days                            |
| Log text fetched with **Logs**     | 1 day; the action stays            |
| Trust changes (**Recent changes**) | open up to 24 hours, closed 1 year |
| Removed devices                    | 1 year after removal               |
| Removed stacks (on each server)    | 7 days, then deleted there         |
| Enrollment tokens                  | 1 day after they expire            |
| Mail throttle (Durable Object)     | 1 hour                             |

With 5 servers and about 50 actions a day this settles near 10 MB, and the
cleanup writes about 3,500 rows a day.

## Status page

A second Worker, `stats` (`worker/wrangler.stats.jsonc`), serves a public page at
`stats.kleavox.xyz` from the same D1 database. It lists only the checks turned
on under **Status page** in a check's menu: name, optional public note, current
state, 90 days of incident-based uptime, and recent incidents. It never shows a
check's kind, target, server or error messages. The page is plain HTML, cached
for 10 minutes and rate limited per IP. One small inline script, allowed by its
hash in the CSP, rewrites times into the visitor's time zone; without script
they read UTC. CI deploys it after the dashboard.

## Why there is no ESLint

`typescript-eslint` does not load against TypeScript 7, so no parser-based rule
can run here. `tooling/lint/unhandled-async.mjs` stands in for
`no-floating-promises` and `no-misused-promises` until it does.
