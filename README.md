# Krynodes

Krynodes is a small, self-hosted monitoring console on Cloudflare Workers. A Go
agent on each server reports metrics and runs HTTP, TCP, systemd and Docker checks; the
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

CI (`.github/workflows/ci.yml`) runs the same steps on every push to any
branch. Only on `main` does its `deploy` job then ship the Worker to
`kry.kleavox.xyz` when the app or Worker changed, and only `main` releases the
agent. **Run workflow** on the Validate workflow deploys by hand.

## Production

- **Access.** Put the dashboard hostname behind a Cloudflare Access application.
  The Worker verifies the Access token itself and answers 401 without one.
- **Agents** report to the Worker's `workers.dev` address (`AGENT_ORIGIN`),
  outside the zone, so zone bot protection cannot challenge them. The install
  command uses the same address once (`/i/<code>`), so Bot Fight Mode can stay
  on for the zone.
- **Configuration.** `env.production` in `worker/wrangler.jsonc` holds the
  public values. The GitHub environment `production` supplies the rest:
  secrets `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `KRY_D1_ID`,
  `ALERT_EMAIL`, and variables `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`.
- **Bindings.** D1 `DB`, `send_email` `EMAIL` (the operator's address verified
  in Email Routing), static assets `ASSETS`.
- **HTTPS.** Both Workers send `Strict-Transport-Security: max-age=31536000` on
  their own hostnames. Set the zone's minimum TLS version to 1.2 in Cloudflare.
- **GitHub.** CI's token is read-only; only the release workflow may write.

## Agent

The agent is a single binary, `kry`. **Enroll node** in the dashboard gives one
command to paste on the server:

```sh
curl -fsSL https://<agent-host>/i/<code> | sudo sh
```

The code is the one-time enrollment token (30 minutes). The Worker serves
`app/public/install.sh` with its last line replaced by the arguments that
token carries: the address, the token, the trusted passkeys' keys and the
setup chosen in the dialog. They sit in one `{ … }` block, so a download cut
anywhere runs nothing. A used or expired code prints why and stops.

The script downloads the latest release for the server's architecture, checks
its SHA-256 and its signature against the release key written into the script
(`openssl`, 1.1.1 or newer), installs `/usr/local/bin/kry`, enrolls the node, and starts the
`krynodes` systemd service (config in `/etc/kry/config.json`), then runs the
security check once so the dashboard shows it at once. The node takes the
server's hostname as its name (**Rename node** changes it) and reports every
minute. A server that is already enrolled is left alone; to enroll it again,
run `sudo kry uninstall-service` first. With two or more trusted passkeys, the
passkey that confirmed the command can reach the new server right away
(`kry trust --access`); the others are added through **Change access** as
before. Afterwards:

```sh
sudo systemctl status krynodes
sudo kry status
```

The Enroll dialog can also set the server up in the same command: **Install
Docker**, **Join Private Network** and **Add Admin User** (with this server's
user name). They start from **Settings → Enroll defaults**, and Docker and the
private network can change until the server enrolls. **Apply recommended
protections** (with a restart hour in your time) is set only in Enroll
defaults and applies to every new server. After enrolling, the script runs
`kry setup`, which prints what it found and did:

```text
Detected: Rocky Linux 9.4 (Blue Onyx) (dnf, firewalld)
✓ Automatic security updates
✓ Restart when needed · 20:00 UTC
– SSH keys only skipped: first let root or a sudo user log in over SSH with a key
✓ Block repeated login failures
Keep 80/tcp (nginx) open to everyone? [y/N] y
✓ Firewall · also open: 80/tcp
✓ Docker 28.4.0 with Compose
```

The firewall keeps SSH open and asks about every other port that listens on a
public address. The DHCP client (68, 546/udp), mDNS (5353/udp) and LLMNR
(5355) need no rule and are not asked about. Without a terminal to ask on, the
open ports stay open. A firewall that is already on is left as it is.

A step that fails is printed and the next one runs; the server is enrolled
either way, and the dashboard can turn the rest on later. `sudo kry setup
--recommended --docker --reboot-hour 20` runs it again by hand.

Supported systems:

| System                                     | Tools                |
| ------------------------------------------ | -------------------- |
| Debian                                     | apt, ufw             |
| Ubuntu (and systems based on it)           | apt, ufw             |
| RHEL, Rocky Linux, AlmaLinux, Oracle Linux | dnf, firewalld, EPEL |
| CentOS Stream                              | dnf, firewalld, EPEL |

Each protection checks what it needs before it changes anything, and checks
that it took effect after. When either says no, it puts back what it wrote and
says why; there is no way around it. apt must really run unattended upgrades,
with its daily timer on. dnf must find security notices; CentOS Stream
publishes none, so Security updates stay off there. Restart when needed wants
something that marks a needed restart: unattended-upgrades' kernel hook,
update-notifier, or `dnf needs-restarting`. `sshd -T` must show passwords or
root login off for every user with a key. fail2ban's SSH jail must answer. The
firewall must list SSH as allowed after Krynodes turns it on. Docker must have
published packages for the system's codename and architecture. Turning a
protection off never asks. Other systems (Fedora among them) run the agent, the
checks and the Security check, but not Protections or Docker setup.

Releases are cut by `.github/workflows/agent-release.yml` whenever
`agent/VERSION` changes on `main`, as `agent-v<version>` with `krynodes-linux-amd64`
and `krynodes-linux-arm64`, their checksums, ed25519 signatures and build
provenance. The workflow signs with the repository secret `AGENT_SIGNING_KEY`
and refuses to publish if it does not match `agent/internal/update/release.pub`.
The signing job runs in the GitHub environment `release`, which holds the key
and waits for the owner's approval; a push that does not bump the version never
reaches it. Every action in the workflows is pinned to a commit SHA
(`pnpm lint:actions` refuses a tag), and Dependabot proposes updates weekly.

The agent accepts only TLS 1.3 when it talks to Krynodes or
downloads a release, and so does the install script (`curl --proto =https
--tlsv1.3`). HTTP checks still accept whatever the checked site offers.

### Checks

Checks run on the agent of the server they belong to: HTTP (down on errors,
timeouts and 5xx answers), TCP (down when the connection fails), systemd
(up while the unit is active) and Docker (up while the container runs and is
not unhealthy). A systemd or Docker target is picked
from a searchable list of what the server reports on the Services page, never
typed, so protected units such as ssh or docker itself are not offered. A
Docker check reads the state `krynodes-containers.service` keeps (below), so a
container that stops shows within one check cycle; if that state is more than
3 minutes old the check is down with "Container status is stale". Reading that
state times nothing, so a Docker check shows how long the container has run
instead of a response time (`running 4m`), and a systemd check how long the
unit has been active (`active 37d`); HTTP and TCP checks show their latency
(`130ms`), and every check that is down says for how long its incident has
been open (`down 36m`). `--` is left only for a check with no result yet. The
durations come from `kry watch-containers` reads each running
container's `State.StartedAt` (one `docker inspect` per snapshot, only when
containers change) and its compose project, and systemd checks read
`ActiveEnterTimestamp` with the state in one `systemctl show` per cycle. Older
agents send none, so their rows say `running` or `active` alone. For a
container's response time, add an HTTP or TCP check on its port. A failing check is tried twice
more, 5 seconds apart, before the agent reports it down, and an incident opens
only at the second such report in a row. A check's menu on the Checks page or the server
page has **Edit** (name, server, kind, target, timeout), **Pause** / **Resume**,
**Status page** and **Remove**, which asks first. Changing what is checked (kind,
target or server) or pausing starts the status fresh and closes an open
incident; the history stays. A server with a live connection (below) runs the
changed check within seconds; others at their next report.

A SERVICE check's menu has **Restart automatically**: one
switch. When the check turns red (an incident opens; never while it is yellow
or during planned work) the Worker queues a restart of its unit, once per
incident. The server only restarts a unit it was told to with a passkey,
that is not running, that you did not stop from Krynodes, and at most 3 times
an hour. Turning it on needs your passkey, turning it off does not; the row
shows `AUTO`, and the failure mail says the unit is being restarted. Removing
the check or pointing it at another unit turns it off.

Removing a check, pausing it or changing its kind, target or server asks for
a trusted passkey (see Deploy), like deleting a server or creating an install
command. One passkey confirmation covers 5 minutes of such work. An owner with
no trusted passkey yet is not asked.

Incident mail goes out the moment a failure is confirmed, one mail per server
for that report ("pivox: 2 checks down — Health, API"). A server that stops
reporting mails at once too ("pivox: offline"), at the moment the dashboard
turns it Offline: nothing heard for three intervals, at least 90 seconds. The
agent's keepalive ping counts, so a report Krynodes fails to store does not
make a live server offline. A disk that reaches 95% mails once ("pivox: disk
96% full"), and again only after it went below 90%; the disk is the fullest of
`/` and Docker's data folder (`/var/lib/docker`, or its `data-root`), so
Docker on its own volume counts. Each
check and each server mails its first failure in an hour; later failures in
that hour, recoveries and "back online" never mail. When more than five
servers need a mail at the same moment (a provider or network outage), one
mail lists them all ("7 servers offline"). While an action runs on a
server and for 2 minutes after it (10 minutes after a restart, until the agent
is back), failing checks there open no incident, a silent server is not called
offline, and the bars read "maintenance"; anything still down afterwards mails
then. A restart by **Restart when needed** gets the same 10 minutes when the
server's last check said a restart was waiting. Actions and deploys never mail. Mail shows times in UTC; the dashboard
and the status page use the browser's time zone. When an alert mail cannot be
sent (or mail is not set up), the Fleet page says so and why until one goes
out again.

Anyone who can open Krynodes can post an update on an open incident, from the
one-line box on its page: a status (Investigating, Identified, Monitoring or
Update) and what is going on, up to 1,000 characters. Updates need no
passkey and never mail. The incident page tells everything as one
timeline, newest first: the check's results folded into runs (`Still down
09:30 – 10:25 · 12 checks in a row · HTTP 502`), the updates with their
author (only the author can delete one, ⋯ **Delete**), Opened and Resolved,
the last good check before it opened, and the actions on what the check
watches (and the server's restarts) from an hour before it opened. Above it,
the strip runs from an hour before it opened until now. An incident still
resolves only by itself, when its check passes. When the check is on the
status page, its updates show there too, without the author.

### Live connection

Each server keeps one WebSocket open to the Worker (`/api/agent/stream`), held
by a Durable Object (`FleetHub`, one per owner, SQLite class, Free plan).
Everything travels over it: reports, config and action results.
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
- Agents before 0.7.0 are not supported: they are refused (426), the Worker
  refuses every action for them, and the server page's agent dialog shows the
  command to update such a server by hand.
- At a 60-second interval a server costs about 870 D1 writes a day.

Dashboards use the same hub: each tab opens `GET /api/live`, a WebSocket that
only says what changed (servers, checks, actions, services). The tab then
refetches those lists, so when one person restarts a service everybody's
screen shows it within a second or two. Tabs keep their usual polling as the
fallback and reconnect on their own.

### Usage and quota shares

The fleet page's **Krynodes quota** tile opens **Settings → Usage**: today's
Krynodes requests, D1 writes and D1 reads against its share of the account's free
quotas (editable there; other projects may share the account), and the whole
account against the Free plan. Quotas reset at 00:00 UTC.

Without setup the numbers are estimates. For Cloudflare's real counts, create
an API token with one permission (Account, Account Analytics, Read) and save it
as the GitHub production secret `CF_ANALYTICS_TOKEN`; the next deploy hands it
to the Worker together with the account and database ids it already has. The
Worker asks Cloudflare at most every 15 minutes while someone looks.

### Server addresses

A server card on Fleet has a button (**2 addresses**) that opens its
addresses, and the server page lists them under This server, for SSH and the
like. The agent calls `/api/agent/address` once over IPv4 and once over IPv6
when it starts and every 6 hours, and the Worker keeps the address Cloudflare
saw the call come from, with the network it belongs to (`PT Telkom
Indonesia`). A family the newest probe did not reach within an hour is left
out, so an address the server lost does not linger.

The agent sends the addresses its own interfaces hold with
that call (`POST`; older Krynodes answer `GET`). A seen address the server
does not hold is a router's: a home server behind NAT shows its router's
address marked **Router**, a VPS with its own address shows none. The server
page's ⋯ beside IPv4 or IPv6 says **Its own address** or **A router's
address** when the guess is wrong, and **Detect automatically** goes back.

Interface addresses inside **Private addresses** are listed under their
interface's name (`tailscale0 100.101.102.7`), so a VPN address shows once its
range is on that list; nothing is listed by default.

Only an account with a passkey that reaches that server (the server page's
**Reached by**) sees its addresses; any other account gets a blurred
stand-in, and the addresses never leave the Worker. Copy copies the whole
address.

### Updating the agent

The Worker checks GitHub for the latest `agent-v*` release once a day (or on
**Check for releases** in a server's agent dialog); agents never poll GitHub. Each server shows its agent version,
with an arrow when it is behind, and the **Updates** filter lists them.

- **Update agent** (the agent dialog, from the ⋯ beside Agent under This server
  on the server page) or **Update N** (Fleet) asks the agent to update
  on its next report. The agent drops the request in
  `/var/lib/kry/update-request`; the root unit `krynodes-update.path` starts
  `kry self-update`, which downloads the release from this repository, checks
  the SHA-256 and the signature against the key built into the agent, refuses
  downgrades, keeps the old binary as `kry.previous` and restarts.
- The download suits slow links: it fetches the gzip asset
  (about 2.6 MB instead of 6.5 MB), gives up on an attempt only after a minute
  without data, resumes where it stopped, and tries five times. The new binary
  must print its version before it is installed, and if the agent does not stay
  up after the restart the old binary comes back. Why an attempt failed shows
  in the agent dialog.
- A stalled update is asked for again after 15 minutes, three attempts in all,
  before the dashboard calls it failed. Releases are published only once every
  file is uploaded.
- **Update automatically** (per node) requests every new release as soon as the
  Worker sees it.
- **By hand**, on the server:

```sh
curl -fsSL https://<agent-host>/install.sh | sudo sh -s -- --update
```

### Pages

Every page puts what is wrong first, says it once and says why.

- **Services**: **Needs attention** lists each stack with fewer containers
  running than it has, each container or unit that failed, and each thing
  whose last action is not fixed (below), with the reason (`Restart failed 30
min ago: port 53 is already allocated`), Logs and the button that fits (Roll
  back after a failed deploy that can roll back, Start when it is down,
  Restart otherwise). Below, one box per server (`4 running · 1 stopped`,
  `Open server →`) with compact rows; their ⋯ holds every action. Search and
  a kind picker replace the old tabs, system units fold into `+ 3 system
services` until **System services** is on, and **Removed n** lists removed
  stacks. An enabled unit that is not running is **Ran at Boot** when it is a
  one-shot that finished well, **Not Needed Here** when its condition is not met
  on this server (agent 0.7.1), else **Stopped**; the first two are grey, sorted
  last and left out of the counts and Needs attention.
- **Checks** (incidents included): **Down** first, each with its reason, how
  long, failures in a row, its incident and its latest line, the newest of the
  last update and the last action on what the check watches (`09:58
Auto-restart failed: port 53 is already allocated`), and Logs and Restart
  (containers and units) or Open incident; then a search over checks and
  incidents, `All · Down · Up`, and one box per server with the 4-hour strip,
  uptime, the last column above and `Last incident 21 Oct · 12m · timed out`.
  Beside them, **Incidents · last 30 days**: `5 incidents · 2h 25m down`, the
  open ones counted up to now, and one row per incident (`Today 15:30 · open ·
36m`). `/incidents` opens Checks; `/incidents/:id` is still the incident page.
- **History** (the account menu, above Passkeys; the hourglass in the
  header shows `2 failed` and lists them under **Failed, not fixed**):
  **Failed, not fixed** cards, each with its output (last lines
  first) and one tab per container of the stack it touched, read from the
  server only when opened, the incident it caused, Try again, Roll back and ⋯
  **Hide**; then **Everything** in one box with days as separators, actions
  and incident events, Everything / Actions / Incidents / Failed, a server
  picker and a search over the 90 days (verbs, names, servers, outputs, check
  names, incident causes). Reads of logs and secrets show only under Actions.
- **The server page**: a line of facts (`Debian 12 · amd64 · up 37 days ·
reports every minute · agent 0.7.1`), then **What runs**: one card per
  stack, per container outside a stack and per unit that is not running, each
  holding its not fixed action, its checks and its open or last incident;
  running units fold into one card. **Other checks** holds the checks that
  watch nothing listed, then **Recent actions**. Beside them: **Machine**
  (four tiles; one opens its chart), **Security** (findings, one Protections
  line, Apply, the list in a dialog) and **This server** (addresses, Reached
  by, Enrolled, the agent; its ⋯ opens the agent's update controls). On a
  phone the order is the same, the machine after Other checks.

A check watches a stack, a container or a unit (`ownerOf` in
`packages/protocol`, shared by the Worker and the app), by exact names only:
a Docker check watches its container, or the container's stack when the
agent lists that container in it; a systemd check watches its unit (`ssh` and
`ssh.service` are one); an HTTP check watches the stack whose web address has
exactly the URL's hostname; a TCP check watches nothing.

A failed or expired action that changes something is **not fixed** until a
later action on the same thing finishes, the thing is running again or gone,
or someone hides it (⋯ **Hide**, for everyone, no passkey, recorded on the
action). The Worker works it out over the 90 days (`/api/history/attention`).

### Service actions

The **Services** page starts, stops or restarts stacks, containers and units
(above). The server page, Ctrl K and a SERVICE check's menu offer the same
actions; a SERVICE check's menu has
**Restart service**. Every one of them needs your passkey, like a deploy
(see below): a server that trusts no passkey refuses them.

The server page's **Actions** menu (and Ctrl K) also has
**Restart server**: after a confirmation and the same passkey, `kry exec`
reports "restarting the server" and then runs `systemctl reboot --no-block`.
It refuses while a protection or a Docker install is still running there, since
a restart in the middle of a package install leaves the package manager broken.

Everything in flight is visible to everyone, named by the device that signed
it (or by the person, when no device did): the server reads
"Restarting · Owner laptop · 1:12" on every page until its agent reports
again, its services wait with their buttons hidden ("Waiting for pivox to come
back"), a service being restarted shows which device asked and for how long,
and the hourglass button in the top bar lists what runs or waits now.
**History** (above) keeps the actions of the last 90 days, with the device,
the outcome and how long it took; trust updates stay in **Recent changes**.
There are no pop-up toasts for other people's work.

A service's or stack's menu has **Logs**: the last 300 lines
(`journalctl -u`, `docker logs`, `docker compose logs`), at most 64 KiB, signed
like any action and allowed for protected units because it only reads.

The agent never runs anything itself:

- It drops each request in `/var/lib/kry/actions`.
- The root oneshot `kry exec` does the work. The units `krynodes-exec.path` and
  `krynodes-exec.timer` start it, the timer every 5 minutes to refresh the list of
  services. A run starts no new request after 20 minutes and leaves the rest
  to the next run, so nothing it started is cut off by the unit's one-hour
  limit; Move into Krynodes gives up copying the old folder after 15 minutes
  and starts the stack from it again.
- `krynodes-containers.service` runs `kry watch-containers` as root in the
  same sandbox as `kry exec`. It follows `docker events`, writes the
  containers' states to `/var/lib/kry-exec/containers.json` after each
  start, stop, restart or health change, refreshes the file's time every
  minute and reconnects when Docker restarts. It only reads Docker; the
  agent itself still has no Docker access.
- `kry exec` refuses anything that is not signed by a trusted passkey and
  aimed at something present on the server. The only unsigned requests it
  takes are turning auto-restart off, restarting a listed unit that is down
  and running the Security check.
- It never starts, stops or restarts ssh, the network, the firewall (ufw,
  firewalld, nftables, iptables), Docker itself, systemd internals, cloudflared
  or Krynodes; it only reads their logs. The firewall is turned on and off as
  a protection under the server page's Security.
- It keeps its state in `/var/lib/kry-exec`.

To take Krynodes off a server, delete the node in the dashboard while the
server is online: with **Remove Krynodes from the server** ticked (on by
default for servers your passkey can sign for) one
passkey confirmation queues the whole job and the dialog closes. Krynodes spreads the
token, asks the server to remove Krynodes, and deletes the node once every step
is done; the removal runs 30 seconds later, after the answer reached Krynodes.
Meanwhile the server shows as **deleting**; if a step fails it shows **delete
stopped** and stays, and Delete node offers to try again or **Delete anyway**.
Without it, or for a server that is offline, run:

```sh
sudo kry uninstall-service
```

It first stops new work and waits (up to an hour) for a stack change, a
protection, a Docker install or an agent update that is still running, so
nothing is cut half way. It leaves nothing of Krynodes behind: its units, `/usr/local/bin/kry`,
`/etc/kry`, `/var/lib/kry`, `/var/lib/kry-exec` (seal key and token piece
included), the `kry` user, the tunnel container and its image, and the
containment rules of Contained stacks. Every protection it turned on is turned
off again, with the packages it installed for them, and a server that is
locked down is unlocked first; it prints what it turned off, such as "SSH
accepts passwords again". Stacks Krynodes runs keep running: each folder moves
to `/var/lib/krynodes-stacks/<name>`, with its secrets, and it prints the
`docker compose` command to manage it. With `--delete-apps` they are deleted
instead, with their volumes. Stacks you started yourself are never touched.
When the server held a piece of the Cloudflare token it says so: spread the
token again on the Cloudflare page unless Delete node already did.

### Deploy

The Services page deploys Docker Compose stacks. Each server's box lists its
stacks, with their containers folded under them; the server page gives each
stack a card with the same row. A stack's ⋯
holds its actions, and **Deploy on all N servers** when the project runs on
more than one. A deploy runs `docker compose pull`, then `up -d`, in the
stack's own directory, with its own compose files. A failed deploy keeps the images that
ran before it, and **Roll back** starts them again.

Servers with Docker and Compose show the Docker logo on Fleet, Services and the
server page (faded when Compose is missing). A stack's menu also has **Start**, **Stop**, **Restart**, **Remove** and
**Delete permanently**, and a container's menu has **Remove**. A removed
container leaves the list as soon as its server confirms.

**Remove** takes a stack's containers and networks down and moves it to
**Removed**, under the server lists. It waits there for 7 days with its volumes
and compose files: **Restore** starts it again (with your passkey), and
**Delete permanently** deletes it at once. After 7 days the server deletes it
by itself, but not while its clock is not synchronized with a time server.
**Delete permanently**, on a running or a removed stack, deletes its
containers, networks and volumes, and the folder Krynodes made for it; a folder
elsewhere (a stack you started yourself) stays. Type the name to confirm.
Images stay. A stack started again outside Krynodes leaves Removed with nothing
deleted, and New stack refuses a name that waits there.

**New stack** (Services page) runs a pasted `compose.yml` on a server, also a
project that is not yours. The text is signed into the command. The server
writes it to `/var/lib/kry-exec/compose/<name>`, resolves it with
`docker compose config` and refuses, naming the service and the reason, a file
that builds from source, asks for privileged mode, extra capabilities,
devices or GPUs, shares the server's network, processes or namespaces, sets
its own confinement (any `security_opt` but `no-new-privileges`), mounts anything outside its own folder (also through a symlink),
uses an external or host network or volume, or includes other files. Published
ports are bound to `127.0.0.1`; reach them through a Cloudflare Tunnel. Then
it pulls, starts and health-checks the stack like a deploy. Do not paste
passwords you use elsewhere: the text is kept with the action in History.

**Stack and container names.** The Name is what Services, its dialogs and the
command palette show, written as you like (`AdGuard Home`, up to 64 characters);
its dashed form (`adguard-home`) is the folder and the Docker project. Once the
compose file is pasted, **Container Names** under the Name lists what each
container will be called: the dashed name for a stack of one service,
`<stack>-<service>` for several (`paperless-db`), or the file's own
`container_name`. Change any of them; an empty box takes the suggestion. A
service that runs more than one copy keeps Docker's numbers. The names live in
the stack's `krynodes.json` and are written into Krynodes' own compose files,
never into the pasted text. Edit compose has the same Name and Container Names,
so a stack made before gets the new names when saved. Before you save, Edit
compose says how many running containers get a new name (they restart), and
Container Names shows what each runs as now. Docker checks on the old name
follow, and a Web address keeps answering on the old name as an alias. Agent
0.7.1 or newer.

**A name belongs to one stack.** Container Names refuses a name that another
stack on the server already uses for a container or a service, and says whose
it is ("uptime-kuma is a service of Monitoring on io."); names ending in
`.<stack>` are kept for Krynodes. Every service also answers to
`<service>.<stack>` on its networks, and Web addresses route to that name, so
two stacks with a service of the same name never get each other's traffic. An
address made earlier moves to it the next time the vault opens, once its stack
has been saved again. A Krynodes network refuses a second service with a name
another stack already has on it, and two stacks on one server cannot share a
display name. When a stack is gone but its folder or volumes stay, New Stack
says so and offers **Delete Leftovers** (typed confirmation) before the name
can be used again. Move says why a server cannot take the stack. Agent 0.7.1 or
newer.

Deploys, like start, stop and restart, need a trusted passkey. On
**Passkeys** (account menu) you register a passkey on your laptop or phone; each
server keeps the public keys in `/var/lib/kry-exec/trust.json`, and the root
executor checks every action against them, so nothing on Cloudflare can run one
on its own. One passkey confirmation opens a 5-minute session, like sudo. It ends at
once when the page is hidden (another tab or app in front, the screen locked, a
phone screen off) and is checked against the clock before every signature, so
a laptop that slept needs the passkey again. Nothing on screen shows whether a
session is open. Agents and the Worker accept sessions of at most 15 minutes.
Signatures carry Krynodes' time (from its responses), so a device whose clock
is off still signs; a server whose clock is off refuses with both times in the
message.

The Worker takes changes (and the live feed) only from its own page: a
request whose `Origin` is another site, or that the browser marks as
cross-site, is refused, so another tab cannot act with your Access login.

One admin login can be shared safely by several people, and the rules are
these:

- **Passkeys** (account menu) are the trusted passkeys every server knows.
  Each one reaches (may run actions on) only the servers it is given. A
  passkey someone registers waits until it is approved, and you get an email.
- Each passkey belongs to the Access account that registered it, and a
  passkey's dialog names its owner when it is not yours. Nobody signs with
  someone else's passkey: the Worker refuses it, and the passkey prompt offers
  only your own. Only the owner renames or forgets a passkey. Passkeys from
  before owners existed belong to whoever last used them, and one never used
  is claimed by the first account that verifies with it.
- The first passkey trusts itself on your servers (**Trust on servers**). The
  second one, such as one on your phone, is approved by the first and reaches
  every server enrolled then.
- With one or two trusted passkeys, one approval adds or removes a passkey.
  With more than two, two approvals from two different passkeys.
- Each passkey is one line saying where it acts ("All Servers", "io, pivox").
  Clicking it (or its ⋯ **Servers**) shows its fingerprint, whether it is
  synced, when it was last used, and a checklist of the servers it reaches.
  A server's own ⋯ menu, on Fleet and on the server page, has **Passkeys**, the
  same checklist from the server's side, and **Remove Every Passkey**. A server
  is given to a passkey only by another passkey that already reaches it, never
  by the passkey itself, so giving another passkey a server you reach takes
  just your approval; when nobody else reaches it, by one other trusted passkey
  (two when there are more than two). Servers enrolled later start with the
  passkeys and nobody reaching them.
- The Passkeys page shows a server only when it needs you: **Trust** when it
  knows no passkey yet, **Choose Passkeys** when nobody reaches it, **Sync**
  when its list is older, and an agent update when it runs an old agent.
- A passkey already registered, under any name, cannot be set up again.
- Changes wait under **Waiting for approval** for up to 24 hours. Each approval
  signs the exact change; the dialog shows new passkeys' key fingerprints for
  you to compare with the new device's screen.
- **Recent changes**, under the devices, lists every closed change
  newest first ("Give Budi access to pivox"): its outcome, who opened and
  approved it and when, and any server that has not taken it yet.
- Every approval, session and confirmation needs a passkey that you unlock
  with your fingerprint, your face or a PIN: Windows Hello, Google Password
  Manager, iCloud Keychain, a phone, or a security key such as a YubiKey with
  its PIN. A touch alone ("a finger is there") is
  refused by the browser, the Worker and every server; a passkey
  that only takes a touch (such as Microsoft Password Manager) cannot join, and
  one trusted earlier reads **Cannot sign** until it is removed and set up
  again. There is no passphrase and no setting to turn this off.
- On a computer that cannot open your passkey, choose **Use a phone** in the
  passkey window: the phone's own passkey signs, so it is the trusted one. It
  joins as "Phone"; a security key joins as "Security key".
- WebAuthn only reports that the person was verified, not how, so a PIN counts
  the same as a fingerprint or a face. Keep those PINs private.
- Each passkey shows **Synced** or **This Device Only** (`--` for one set up
  before, until its next use). A synced passkey follows your account (such as
  Google Password Manager or iCloud Keychain) to your other devices: it is
  convenient, but whoever takes over that account and its unlock can approve.
  One kept on this device only, such as a security key, is stronger and needs
  a backup.
- Keep two passkeys or more: with one, losing it needs SSH to recover. With
  two, the other removes a lost one alone.

To start over on a server:

```sh
sudo kry trust --reset
```

### Stacks without SSH, secured servers

Everything below is signed with your passkey and lands in History.

Each agent makes a P-256 seal key in `/var/lib/kry-exec/keys` (root only) and
reports the public half. The browser encrypts secrets, token pieces and tunnel
tokens to it, so D1, History and backups only ever hold sealed text. A Worker
taken over while you use it can still serve changed app code; sealing protects
stored data, not a live takeover.

**Access level.** New stack, Edit compose and Move ask for one per stack:

- **Contained** (default): the vetting above, plus at most 1 CPU, 1 GB memory
  and 512 processes per service (set when absent; more is refused), and no way
  to reach `169.254.169.254`, `fd00:ec2::254` or the server's own addresses,
  from boot on (`krynodes-guard.service` sets the rules before Docker starts).
  Its networks are its own (no `name:` of another network, no IPv6), its
  volumes plain local ones (no driver options or plugins), and it runs on
  `runc`. Its logs stay on the server (`local` or `json-file`, size options
  only), and its images come from a registry that is not the server itself
  (Docker pulls and ships logs from the server's own network). Privileged
  hooks, provider services and models are refused. Only the usual Compose
  keys are taken (a key it does not know, such as `use_api_socket`, needs
  Full access), and Deploy, Rollback and Restore check an older Contained
  stack against these rules again. Each service runs one copy and joins only
  the stack's own networks.
  Published ports are bound to `127.0.0.1`, and the server can open them:
  replies to a connection the server started come back, but the stack cannot
  start one to the server. **Reach this server on**
  lists the ports the stack may open on its server, such as `3000/tcp`, at
  most 16; the rule covers every network of that stack only, is signed with
  the compose file and goes when the list is emptied or the stack removed.
  The rule is in place before the stack starts, so an app
  that calls the server as it starts finds the port open.
  The rules live in the `KRY-CONTAINED` chain, which INPUT enters for the
  stacks' bridges. From agent 0.7.1 the same list covers ports other stacks
  publish on the server: a connection to the server's address that Docker
  forwards to another stack is held by `KRY-PORTS` (`DOCKER-USER`) unless its
  port is in Reach this server on, and each refused try is logged with
  `kry-reach `.
- **Full access**: public ports, host network, server folders, builds and
  devices. Before you sign, the dialog lists what the stack opens. It
  is root-equivalent; use it for stacks you trust like the server itself.

Pulls are refused when the images need more disk than is free (compressed size
doubled, plus 1 GB kept free).

**Secrets.** Name and value pairs, sealed in the browser to the target server
and written there as a root-only `.env` beside the compose file. Refer to them
as `${NAME}`. Edit compose lists the secrets a stack has by name, each shown
as `••••••`: **Replace** takes a new value, **Remove** drops it, and one left
alone is kept on the server as it is, so its value never leaves the server and
Cancel changes nothing. Removing every one empties the `.env`. A reinstalled agent has a new key: enter them again
with Edit compose.

**Web address.** A stack's ⋯ **Web address** picks a service and its port and
opens `<app>-<server>.<zone>` over a Cloudflare Tunnel, with HTTPS and no port
opened on the server. Who can open it: **Only people I allow** (the same
Cloudflare Access login as this dashboard), **Login only for a path** (such as
`/admin`), or **Everyone**. The login copies the dashboard's Access app: its
policies, its login methods and Instant Auth, so a dashboard that signs in
straight through one identity provider gives every address the same. Krynodes makes one tunnel per server
(`krynodes-<server id>`), runs `cloudflared` as a digest-pinned container on
the stacks' own networks only, and touches only the DNS records, Access apps
and tunnels it made. A hostname that already exists is refused. On a stack
that has an address, **Web address** opens with its settings: pick the
address (or **New address**), change the service, port, or who can open it,
and **Save** changes it in place; its name stays. The login
comes first: the Access app is made (or updated in place) before the route and
the DNS record, and an older login is removed last, so a protected address is
never open, not even when a step fails. **Close web address**, Remove and
Delete permanently remove what it made, the login last.

**Cloudflare token** (Settings → Cloudflare). Create one token with
Account · Cloudflare Tunnel · Edit, Account · Access: Apps and Policies · Edit
and Zone · DNS · Edit for your zone, expiring in a year, and paste it once. The
browser splits it with Shamir's scheme: any 2 pieces rebuild it. Every
online server your passkey reaches gets one piece, sealed to its key; one
server keeps the whole token, two servers must both be online, three or more
need any two. A new split takes over only once two of its pieces are stored,
and each server keeps its piece of the split in use until then, so a spread
that stops half way leaves the token as it was. One token change runs at a
time; the page shows how many steps are left. Each step wakes the server of the
next one, and the servers store their new pieces at the same time, so a spread
takes seconds, not a minute per server.
A server rebuilds the token only for a signed request, uses it, and erases it.
Open addresses keep working while servers are down. **Spread again** appears
when a reachable server holds no piece; **Replace token** splits a new one.
Krynodes mails 30 days before the token expires.

**Delete node** on a server that holds a piece first spreads the token across
the other servers, makes the leaving server forget its piece and removes its
tunnel, DNS records and Access apps, then deletes it, on its own after your
passkey. When the token cannot move (fewer than two pieces online),
the dialog says why and offers **Delete anyway**; replace the token if the
server may be in the wrong hands.

**Edit compose / View compose.** Stacks Krynodes runs can be edited: the new
text is vetted for the stack's access level and started, and the previous one
stays as the Roll back target. Stacks started elsewhere can only be read until
they move.

**Move to server** copies a stack to another server: tick the services that
move (unticked ones leave `depends_on`, and values that still name them are
flagged, like a test mailpit), review the compose file, and choose the access
level there. Images are pinned to the digests that ran, secrets are sealed
again to the target, and small files beside the compose file (up to 32 KB
together) come along; app data does not. Once the copy runs healthy the
original is deleted now (type the stack's name first, since its volumes go
too), moved to Removed, or kept, as you chose; if the copy fails the original
is untouched.

**Move into Krynodes** copies a stack started elsewhere into
`/var/lib/kry-exec/compose/<name>`, stops the old one and starts the copy
under the same project name, so named volumes stay. The old folder is left as
it was. A stack that mounts server folders moves as Full access.

**Security check.** Right after enrolling, every 6 hours, and after every
change below, each server checks SSH password and root login, SSH keys, ports
open to the internet (also ones Krynodes did not open), automatic updates,
pending updates and restarts, privileged containers and `docker.sock` mounts,
and a clock that is not synchronized (signed actions depend on it). Fleet
shows a shield (green, amber, red); the server page lists the findings with
**Check now**. A new serious finding is mailed under the quiet rules. The
system's end of life comes from endoflife.date, fetched by the Worker once a
day: the Security section shows `Updates until 30 Jun 2028`, or
`Updates until --` for a system it does not list, with a warning 90 days ahead
and a serious finding after, never mailed.

A port counts as open to the internet when the firewall lets it in from
anywhere: ufw rules without a source restriction, on any
interface or on the interface of the default route, or everything when the
input policy is ACCEPT; firewalld's zone of that interface (or the default
zone), its services and ports, or everything when its target is ACCEPT. With
no firewall on, every public listener counts. Ports Docker publishes always
count, since Docker goes around the host firewall.

**Private addresses** (Settings → Private addresses) keeps one list of address
ranges (IPv4 or IPv6, at most 32) for every server, empty until you fill it.
Listeners bound to an address inside a range, such as a VPN's, are left out of
the public-ports finding. The agent reports each listener's
address; the Worker applies the list when it shows the report, so a change
shows at once, without a new check. A server's interface addresses inside a
range show among its addresses under the interface's name, such as
`tailscale0`.

**Settings** (the account menu, under Passkeys) is its own page for
what applies to every server: Cloudflare, Private addresses, Enroll defaults (what a new install command sets up) and Usage, each at its
own address (`/settings/usage`).

**Protections** on the server page, each with Turn off (Undo):

| Protection                    | What it does                                                                                                                                               |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Automatic security updates    | `unattended-upgrades` (Debian, Ubuntu); a daily Krynodes timer running `dnf -y upgrade --security` (RHEL family)                                           |
| Restart when needed           | restarts at the hour you pick (your time) when an update asks for it, at most once a day, never during an action, a protection or a Docker install         |
| SSH keys only                 | no password login over SSH; offered only when root or a sudo user can log in with a key                                                                    |
| Block repeated login failures | fail2ban for SSH (from EPEL on RHEL, Rocky, AlmaLinux, Oracle Linux and CentOS Stream)                                                                     |
| Firewall                      | ufw or firewalld: every port SSH listens on (its config, `ssh.socket`, its open sockets) and the ports you tick stay open; Docker's ports are not affected |
| Free port 53                  | stops systemd-resolved holding port 53, for a DNS server such as AdGuard; refused when systemd-resolved knows no upstream DNS server                       |

Each one writes its own drop-in file and never edits yours; Turn off removes
it, and the packages Krynodes installed for it. A protection that fails half
way, or whose record cannot be saved, is taken back (SSH keys only drops its
file when SSH cannot reload, Free port 53 puts DNS back). SSH keys only counts
only accounts SSH really lets in with a key (`PermitRootLogin`, `AllowUsers`,
`DenyUsers`, `AllowGroups`, `DenyGroups`, `PubkeyAuthentication`,
`AuthenticationMethods`, keys in the files `AuthorizedKeysFile` names) and
leaves root's login rule alone. **Apply
recommended** turns on the first five with one passkey confirmation, the firewall with
the ports you tick. The agent connects outward, so none of them can cut
Krynodes off. Free port 53 is not a finding: it is offered only for a server
that will run a DNS server.

**No root login** (agent 0.7.1) writes `PermitRootLogin no` in its own drop-in
and is offered only once a sudo user other than root logs in with a key. It is
not part of Apply recommended, since root may be a server's only key login.
While it is off, Security shows "Root can log in over SSH." as a note.

**Lock down server** (server menu) stops containers that publish ports to the
internet and the tunnel, and turns on SSH keys only when a key is set up.
**Unlock server** brings back exactly what it changed. A lock down that fails
half way gives everything back at once. While a server is locked down nothing
starts there: new stacks, Deploy, Rollback, Start, Restart, Edit compose, Move
into Krynodes, restoring a removed stack and Web address are refused until it
is unlocked; Stop, Remove, logs and reading files still work.

**Install Docker** (server menu, for a server without Docker or Compose) adds
Docker's own repository and installs Docker with Compose, or only the Compose
plugin when Docker is there. It refuses next to Podman. A repository the owner
added already is used as it is. A Docker it installs keeps container logs small
(Docker's `local` log driver, unless `/etc/docker/daemon.json` already exists).

### Docker networks

A server's page lists its Docker networks under What Runs (agent 0.7.1):
the ones Krynodes made and, as **Outside Krynodes**, user-made bridges no
compose project owns. **Create Network** makes one of two kinds:

- **Contained**: for Contained stacks; a Full access stack joins only as a
  guest, and not when it is privileged, adds `NET_ADMIN`, `NET_RAW` or `ALL`,
  or sets `network_mode`. Nothing leaves through it (`--internal`), and members
  reach each other only on the ports they **Offer on this network** and only
  when a Contained stack ticks them under **Reach stack on** (rules in
  `KRY-PEERS`, refused tries logged with `kry-reach `). A guest answers and
  never starts a connection there. Each service gets a fixed address and the
  name `<service>.<project>`, runs one copy and drops `NET_RAW`.
- **Full access**: a plain bridge for Full access stacks; open between members.

A network is Krynodes-made only while Docker's network ID matches the one the
agent recorded, never by its name or label. The subnet is picked in the
browser (a free `/24` in `172.24.0.0/13`) or typed, refused when it overlaps
another Docker network, the private network, Tailscale or the server's own
networks, and checked again by the agent. **Copy Compose Lines** gives the
`external: true` lines to add; **Delete Network** waits until nothing uses it.
Move creates the networks a stack uses on the target first, and says which
reaches it loses.

**Upgrading to 0.7.1:** a Contained stack that reached another stack's
published port through the server's address stops reaching it unless that
port is in its Reach this server on. Check those stacks before you update.

### Admin user

Enroll defaults hold up to 4 SSH public keys, pasted several at once or read
from a `.pub` or `authorized_keys` file (changing them asks for your passkey).
The user name is typed for each server: in the Enroll dialog, where it is set
when the command is made, or in Add Admin User. **Add Admin User** at enroll, or Actions →
Add Admin User on a server (agent 0.7.1), makes a sudo user (`sudo` or
`wheel`) that logs in with exactly those keys, then turns on SSH keys only and
No root login once key login works for it. On an enrolled server your
passkey gets a command, `sudo kry admin-user <name>`, to run within 30
minutes. The server shows the keys before writing anything, and the password
is typed into `passwd` on the server's own terminal: it never passes through
Krynodes, the agent, an argument, the environment or a file. The changes it
makes are taken as yours and do not warn.

### Packages

**Packages** (server menu, after Refresh services, or the Updates row of This
server) shows a Debian or Ubuntu server's apt packages, from agent 0.7.0: the
updates waiting, security ones first; what was installed here (by whom, from
apt's history, plus what Krynodes installed for a protection or Docker) or
every package; the sources, each key with its fingerprint; and what runs on its
own. **Check for updates** runs `apt-get update`. **Install package** searches
by name and shows what the install adds, removes and opens before you sign;
**Upgrade all**, **Remove** (with or without its settings), **Hold**, **Release
hold**, **Add repository** (paste the vendor's instructions; Krynodes reads the
key and shows its fingerprint) and **Remove repository** each take one
passkey confirmation, and the agent refuses a key that is not the one shown. A package
Krynodes installed for a protection or Docker goes when that is turned off.

A running job shows its step in the hourglass and on Fleet; a finished one says
what changed, what restarted and whether a restart is needed. Restart needed
shows on the server, and in Fleet's issues when Restart when needed is off, as
do security updates waiting when Automatic security updates is off. History
records every change and opens an upgrade to each package's old and new
version; a failed one keeps apt's last lines and what did change. Search finds
package names. The search and the try-outs before a change are not kept.

**Tailscale** on This server: once `tailscale` is installed, **Sign in** asks
tailscaled for a login link, sealed to this browser, so no terminal is needed.
An expired key shows in Fleet's issues.

Agents before 0.7.0 have no Packages; the page offers Update agent.

### Private network

**Network** (top menu) joins servers into one WireGuard mesh, `kry0`, so a stack
on one server reaches a database on another without opening it to the
internet. Every member is a peer of every other; one server going down breaks
only its own links. From agent 0.7.0.

- **Create Network** reads every candidate first (kernel WireGuard, tools,
  free range, NAT, the UDP port tested from the other servers, firewall, MTU,
  clock) and shows what is already fine, what Krynodes does and what is yours to
  fix. The range is a free `/24` in `10.88.0.0/16` that no interface, Docker
  network, Tailscale or **Private addresses** range uses; the port is
  `51820/udp`, or the next free one on a server where it is taken. Both are
  fixed after creation. A hand-made `wg0` is left alone and avoided.
- **Each server makes its own key**; only the public half leaves it. The
  preshared key of each pair is made in the browser and sealed to both servers.
  The member list is a **network document signed with a trusted
  passkey**; an agent applies only a version newer than its last, so the Worker
  can neither add a peer nor replay an old list. Without a signature the Worker
  can only take a member away. A peer's `AllowedIPs` is its own `/32`, never a
  wider range, so a bad change cannot cut Krynodes off a server.
- Each server keeps its address for good and gets the name `<server>.kry` in a
  Krynodes block of `/etc/hosts` on every member. ufw or firewalld get
  `allow <port>/udp` and `allow in on kry0`; Docker waits for `kry0` at boot.
  A server behind NAT dials out to the others; two servers both behind NAT
  cannot link, and their pair says so.
- **Add Server** shows the address each server gets. **Join Private Network**
  in Enroll a server (and Enroll defaults) gets a new server ready while it
  enrolls; the others learn its key only when you press **Join** (or **Not now**
  undoes it), so a leaked install command cannot bring anyone in.
- The page lists links with no answer first (a link to an offline server is
  not a problem), waiting servers, every server with **Links n of m**, Recent
  changes and This network. The menu item counts the links with no answer.
  `--` means not measured, never 0 ms.
- **Test Link** (a problem row, a server's links, **Test links** for all its
  pairs, **Test all links**) reads both servers and changes nothing: agents,
  `kry0` and keys, clocks, public addresses, firewall rules, handshakes, small
  and large packets, then the most likely cause. Its fixes take your passkey:
  **Send again**, **Put rule back** and **Use 1380** (a smaller MTU for that
  server). Every test is kept in History.
- **Remove from network**, **Make new keys** and **Delete network** say before
  you sign what stops working; an address a stack still points to is held, and
  freed addresses are given out last. Delete network offers to turn off the
  checks that go through it. Delete node takes the server out of the network
  first, and renaming a member tells the others its new name.

Stacks on the network:

- **A Contained stack is closed to the network until you say otherwise.** On a
  member, Edit compose and New stack have a **Private Network** section: each
  published port is **This Server Only**, **All Servers** or **Chosen Servers**,
  and **Reach Other Servers On** lists the places on other servers (such as
  `vps-2:5432/tcp`) its containers may connect to. Replies to connections that
  came in always pass. The agent keeps the lists beside the stack and turns
  them into iptables rules for `kry0` in `DOCKER-USER`; a server leaving takes
  its rules with it.
- **A Full access stack reaches every server**, and What this stack opens says
  so. **Use Private Address** rewrites `"3000:3000"` to
  `"${KRY_PRIVATE_IP}:3000:3000"` in the editor only; Krynodes fills in
  `KRY_PRIVATE_IP` with the server's own private address at deploy, and refuses
  a file that uses it on a server outside the network.
- Inside containers every member is `<server>.kry` (`extra_hosts`, added at
  deploy without changing the compose file).
- Listeners only on the private network are not public: Security lists them on
  a grey line, and on a member points a public Full access stack to the private
  address. Turn on firewall keeps the network's port as a locked row.
- **Move** carries the lists, offers to change the other stacks that reach this
  one (the same passkey signs them) and turns red when the new server is
  outside the network. Checks suggests a TCP check for each place a Contained
  stack reaches; **Not now** hides it until that list changes.

### Tailscale rules

Krynodes can keep who may reach your servers over Tailscale. Rules for your
laptop, phone and other people stay yours, in Tailscale's admin console. From
agent 0.7.0.

- **Before Connect** each server reads from its own tailscaled which peers may
  open connections to it, on which ports, and Network turns amber when every
  device reaches every port. No credential is needed for that.
- **Connect Tailscale** (Network) asks for four things from Tailscale's admin
  console: `"tag:kry": ["autogroup:admin"],` inside `tagOwners`; a trust
  credential with Policy File Write, Devices Core Write, Auth Keys Write and
  Tags `tag:kry` and nothing else (Tailscale adds the read scopes itself); its
  client ID and secret; and a webhook to `<agent origin>/hooks/tailscale`
  (`AGENT_ORIGIN`, else `PUBLIC_ORIGIN`) with the events `nodeCreated` and
  `policyUpdate`.
- **What is kept where.** The client secret is held as the Cloudflare token is:
  split in the browser, one piece sealed to each 0.7.0 server that is not
  quarantined, any two rebuild it on one server for one signed job, which uses
  it and erases it. It needs two such servers. The Worker keeps the sealed
  pieces, the client ID, the tailnet, the rules you saved and the webhook
  secret; that secret can only make Krynodes believe an event that did not
  happen, never open anything.
- **Start With These Rules** opens after Connect, from what listens on each
  server and what was in use when the policy file was read. An "everyone to
  everything" rule becomes "Your devices → everything except your servers".
  Saving tags the servers `tag:kry` and turns off their key expiry.
- **Saving** reads the policy file, replaces only the lines between
  `// krynodes: begin` and `// krynodes: end`, has Tailscale validate the
  file and writes it only if it did not change since it was read. Rules name
  servers by their Tailscale addresses, never by the tag. A Krynodes line
  changed in the admin console is never overwritten: Keep the Change or Put
  Back Krynodes', then sign again. Each server's own report shows Applied.
- **Sign In**, once connected, needs no link: a server holding a piece makes a
  one-time key tagged `tag:kry`, sealed to the joining server.
- **Two alarms**, each a red row on Network and one mail: a device that joins
  with `tag:kry` that Krynodes never signed in, and a policy change made with
  Krynodes' credential without your passkey.
- A quarantined server's place on your tailnet gets **Remove from Tailnet**;
  its credential piece gets **Reshare Without It**, and Delete Node reshares it
  first. **Disconnect** erases every piece and leaves your rules in the policy
  file; delete the trust credential in the admin console too.

### Quarantine

What Krynodes does on its own when a server looks broken into. It only ever
takes access away; giving access back always asks for your passkey. From
agent 0.7.0.

- **A warning first.** A new SSH key, a sign-in with a key not from Krynodes, a
  new user or sudo rule, a port opened on a public address outside Krynodes,
  Krynodes' firewall rule removed, or an agent that goes quiet while its peers
  still see the server: the server page shows an amber strip and a mail goes
  out. **Cut Off Now** quarantines it at once; **It Was Me** (passkey)
  takes the change as yours. Unanswered, the server is cut off after the time
  in Settings, Quarantine (15 minutes by default, or Warn Only).
- **A scan.** A member that knocks on more closed ports or servers in one
  minute than **Counts as a Scan** is dropped at once by every server it
  knocked on, and quarantined when enough servers agree. One wrong port knocked
  again and again is a setting mistake: a row on the Network page, nothing cut
  off.
- **Quarantined.** Every other server drops its WireGuard key for good and,
  when it is on your tailnet, blocks its Tailscale address; Krynodes locks it
  down, sends it nothing, refuses every action except reading and believes
  none of its reports (its checks show **Not Trusted**). The server page shows
  the red card, **What Happened** to the second, and **Change These**: the
  stacks whose secrets to change, services elsewhere that trusted it, its
  Cloudflare token piece (**Reshare Without It**), web addresses still on its
  tunnel (**Remove Web Addresses**) and its place on your tailnet (**Admin
  Console ↗**). Actions keeps only Refresh Services, Release Server, Remove
  from Network and Delete Node.
- **Release Server.** Really broken into? Reinstall it and enroll it again. A
  false alarm: run `sudo kry release-code` on the server, type the code it
  shows (it works for 10 minutes) and sign. From agent 0.7.2 the code reaches
  Krynodes within seconds; an older agent sends it with its next report, up to
  a minute later, and needs `sudo chmod 644 /var/lib/kry-exec/release.json`
  after each `release-code`. The server makes new keys
  (WireGuard, sealing and its sign-in to Krynodes); the old ones stay blocked.
  The same passkey releases it, lifts the Tailscale block and sends its new
  keys to the network. The code shows you were on the server; it does not show
  the server is clean.
- **A Contained stack that knocks** (tries places it was not given) is stopped
  and stays stopped after a reboot, while the server stays trusted. What Runs
  shows what it tried, with Logs and Start; change its secrets first.
- **Settings, Quarantine** holds the four choices. A stricter one reaches the
  servers at once; a looser one asks for your passkey and travels in the
  next signed network document.
- A quarantined server's checks are grouped last on Checks under
  **Quarantined**, its windows are **Quarantined** (faded red) and not counted
  against uptime, and the public status page shows No data for them.
- Delete Node on a quarantined server first makes your servers stop blocking
  its Tailscale address; remove it from your tailnet before.
- Every network document names the one before it, and an agent refuses one
  that is not built on what it applied, so the Worker cannot slip a member list
  past the browser.

## Data retention

A daily cron (03:17 UTC) keeps the database small enough for the Free plan's
500 MB and its daily write quota. **Usage** shows the database size.

| Data                               | Kept                               |
| ---------------------------------- | ---------------------------------- |
| Server metrics (5-minute windows)  | 8 days                             |
| Check results                      | latest per check only              |
| Incidents                          | while open, then 180 days          |
| Incident updates                   | as long as their incident          |
| Actions (**History**)              | 90 days                            |
| Log text fetched with **Logs**     | 1 day; the action stays            |
| Compose text read with **View**    | 1 day; the action stays            |
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
state, 90 days of incident-based uptime, and recent incidents with the updates
posted on them, newest first. It never shows a check's kind, target, server or
error messages, nor who posted an update. A new or deleted update reaches the
cached page within about 30 seconds, as a change of state does. The page is plain HTML, cached
for 10 minutes and rate limited per IP. One small inline script, allowed by its
hash in the CSP, rewrites times into the visitor's time zone; without script
they read UTC. CI deploys it after the dashboard.

## Why there is no ESLint

`typescript-eslint` does not load against TypeScript 7, so no parser-based rule
can run here. `tooling/lint/unhandled-async.mjs` stands in for
`no-floating-promises` and `no-misused-promises` until it does.
