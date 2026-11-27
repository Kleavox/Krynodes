# Krynodes

Krynodes is a small, self-hosted console for a handful of Linux servers and the
Windows laptops that reach them, run on Cloudflare Workers. A single root
daemon, `kry`, runs on each server, and a Windows service runs on each laptop;
each keeps one WebSocket open to the Worker. The dashboard shows every machine
as Online or Offline as it happens, and sits behind Cloudflare Access. D1 holds
the machines, the passkeys, the private network's signed documents and the
history.

Nothing a machine does is decided by the Worker or by the dashboard login. A
person signs each action and each change to the private network with a passkey
in the browser, and the machine checks that signature against the passkeys it
was told to trust before it acts. A stolen Access session, or a Worker that has
been taken over, cannot make a server restart, update or remove itself, and
cannot add a machine to the private network or open a port on it, as long as
the owner compares fingerprints: a fresh browser asks the owner to check every
member's fingerprint once before it signs anything, and a laptop's first join is
anchored by the fingerprint the owner checks and the fresh keys it makes.

This is an overhaul that turns Krynodes into a private network between servers
and laptops, with Docker stacks that move between servers. This tree holds the
first three parts:

- **Fleet.** Enroll a server with one command; see it Online or Offline live.
- **Passkeys.** Add a passkey, rename it, choose which machines trust it,
  remove it.
- **Actions.** Update Agent, Restart Server, Remove Server, each signed by a
  trusted passkey. A command is instant or refused: a machine that is offline
  refuses it at once, and nothing waits in a queue.
- **Private network.** Servers and laptops ask to join and the owner approves
  or rejects each one. Servers refuse each other unless a Connections rule
  allows it. Laptops reach the servers and can send their internet traffic out
  through one server, the exit node.
- **Stacks.** Install Docker, then run Docker Compose stacks on any server:
  New Stack, Deploy, Edit Compose, Rollback, Start, Stop, Restart, Logs,
  Remove and Adopt, each signed by a trusted passkey.
- **Checks.** Choose containers to watch; a lasting failure and a server that
  stays offline send one mail.
- **Status page.** A public page with the checks the owner makes public.
- **History.** Every action and every network change, who it went to and how
  it ended.

The dashboard's pages are plain for now; their visual design comes later.
Moving stacks between servers and web addresses come in later parts. The 0.7
line's metrics, incidents, quarantine and hardening are not in this tree; they
are not hidden, they are removed.

```text
Browser ── Cloudflare Access ── kry Worker ── D1
 (signs)                           │
                                   └── FleetHub (Durable Object) ══ wss ══ kry on each server
                                                                 ══ wss ══ Krynodes on each laptop

server-1 ══ WireGuard (kry0) ══ server-2 ══ … ══ laptop-1
```

## Layout

| Path                | What                                                                                         |
| ------------------- | -------------------------------------------------------------------------------------------- |
| `worker/`           | Hono Worker: dashboard API, agent API, the `FleetHub` Durable Object, D1; the `stats` Worker |
| `app/`              | React dashboard (Tailwind v4, shadcn/ui, TanStack Query)                                     |
| `agent/`            | Go daemon `kry`, standard library only                                                       |
| `packages/protocol` | Zod schemas for the agent and Worker wire, with fixtures the Go tests read                   |
| `tooling/`          | TypeScript presets, Vite config, lint scripts                                                |

## Develop

```sh
pnpm install
pnpm turbo run build --filter=@krynodes/worker^...
pnpm exec wrangler dev --config worker/wrangler.jsonc --port 8790
```

With no Access variables set, the Worker runs as a local standalone operator,
so the dashboard opens without signing in. Production refuses to serve at all
without Access. Rebuild the app and restart `wrangler dev` after every app
change; it serves the built assets from `app/dist`. The status page runs with
`pnpm exec wrangler dev --config worker/wrangler.stats.jsonc` on port 8791.

## Check

```sh
pnpm check         # format, knip, lint scripts, typecheck, tests, build
pnpm native:check  # go test, vet, build, deadcode, the Windows module
```

CI (`.github/workflows/ci.yml`) runs the same steps on every push to any
branch. Only on `main` does its `deploy` job ship the Worker to production.

## Install a server

In the dashboard, Fleet, **Enroll Server**: give the server a name, choose the
passkeys it trusts from the start, and copy the command:

```sh
curl -fsSL https://<agent-host>/i/<code> | sudo sh
```

The code works once and expires after an hour. The script downloads the agent
release the Worker pinned for the server's architecture (amd64 or arm64),
checks its SHA-256 and its signature against the release key written into the
script (it needs OpenSSL 3), installs `/usr/local/bin/kry`, enrolls the server
and starts `krynodes.service`. The configuration is `/etc/kry/config.json` and
the state is in `/var/lib/kry`.

The script ends by printing the server's network fingerprint, for example
`Network fingerprint: 1A2B-3C4D-5E6F-7081`. The server is Online in Fleet
within a few seconds and asks to join the private network. Afterwards:

```sh
sudo systemctl status krynodes
kry version
sudo kry network fingerprint
```

Remove Server in the dashboard takes the unit, `/etc/kry`, `/var/lib/kry`, the
binary and the Docker guard drop-in off the server; the server itself keeps
running. A member of the private network must be removed from it first.
`sudo kry uninstall-service` does the same by hand.

## The private network

Every enrolled machine makes its own network keys and asks to join. Asking
changes nothing on the machine: no package is installed and no port is opened.
The request waits under **Join Requests** on the Network page.

**Approve and fingerprints.** Approve shows a fingerprint the browser computes
from the exact keys it is about to sign. Compare it with the one the machine
shows (`sudo kry network fingerprint` on a server, the install output or the
tray's **Fingerprint** on a laptop) and approve only when they match. A Worker
that swapped a key would show a different fingerprint. Each browser remembers
the fingerprints it has checked and the last document it signed. A member it
has not checked yet, because another browser approved it or the site's data was
cleared, is listed with its fingerprint for a one-time check before anything is
signed. A member whose keys changed since this browser last saw them is listed
the same way, with a warning, and checked again. A document older than the
last one this browser signed or checked stops the change. The first approval is
**Create Network**: it picks a random range such as `10.88.37.0/24` that no
chosen machine already uses. Each member gets a random free address in it, not
the next one in order. **Reject** keeps the machine in Fleet and out of the
network; ⋯ **Ask to Join Again** puts it back in the list. The Enroll dialog
also offers Approve for a server that has just enrolled.

**Connections.** Servers refuse each other on the private network by default.
Only ping between members and replies to allowed connections pass. A rule opens
one direction: `server-1 → server-2 · 81/tcp` lets server-1 connect to port 81
on server-2, and server-2 still cannot connect to server-1. `From` is one
member, All Laptops or All Servers; `To` is one server or All Servers, never a
laptop. Ports are All Ports or up to eight entries such as `22/tcp`,
`8000-8100/tcp` or `53/udp`. A new network starts with one rule, **All Laptops
→ All Servers · All Ports**, which the owner can change or delete. The rules
also cover Docker ports published on `0.0.0.0`: a container on server-2 stays
closed to server-1 until a rule opens that port. Removing a rule refuses new
connections; one that is already open keeps running until it closes.

**On a server** the rules live in the server's own firewall chains (`KRY-EDGE`,
`KRY-IN`, `KRY-FWD`, `KRY-EXIT`). They are put back before `kry0` comes up at
boot, and if they cannot be, `kry0` does not start. Every 10 seconds the daemon
puts back a missing jump, for example after Docker is installed later. Member
names answer as `<name>.kry` through a block in `/etc/hosts`.

**Laptops.** On the Network page, **Add Laptop** gives a download link pinned
to the Worker's release and a PowerShell command with a code that works once
for 10 minutes. Run it as Administrator. It prints the fingerprint and starts
the tray at once; the tray also starts at every sign-in. The laptop then waits
for Approve like a server. Laptops refuse every connection that comes in over
the tunnel. Started with no command, `krynodes-windows-amd64.exe` only says
that it is installed from the dashboard. `krynodes uninstall`, run as
Administrator, takes it off the laptop; remove it from the network on the
Network page as well.

**Exit node.** ⋯ **Exit Node for Laptops** on a public server lets laptops
send all their internet traffic out through it. Each laptop picks it under
**Exit Node** in the tray. Exit traffic never reaches private, shared or
link-local addresses behind the exit node. While an exit is on, a laptop sends
every name to the network's DNS (**Laptop DNS** on the Network page). If
Tailscale has also claimed every name, the laptop keeps Tailscale's own names
(`.ts.net`) on Tailscale's resolver, so they still answer. This works for
Tailscale only. When another VPN also claims every name, Windows holds two
rules for every name and gives no guarantee which resolver answers.

**Behind NAT.** A machine that cannot be reached from outside still joins.
Laptops reach it through another member, a meeting point, and the tray says
"via server-1" while they do.
A server is reached directly only when its cloud firewall (security group) lets
UDP 51820-51919 in from the internet; otherwise it is treated as behind NAT
(relaying through a meeting point comes later).

**Other changes.** ⋯ **Test Link** checks the tunnel between two members.
**New Keys** gives a server a new key in one passkey touch and shows the new
fingerprint first. **Remove from Network** drops a member, its rules and its
key from every other member. **Delete Network** makes every member leave. A
member that was offline catches up on every change, in order, when it comes
back, without a new signature. ⋯ **Delete Laptop** in Fleet deletes a laptop
that is not in the network, for example a lost one.

Turning an exit node off, or leaving the network, leaves the kernel's IP
forwarding on until the next reboot while Krynodes' chains refuse what it would
forward; this is intended, since Docker and other tools rely on forwarding too.
A member that was offline while a passkey that signed some of the changes it
missed lost its trust cannot check those changes: take it off locally
(`sudo kry uninstall-service`, or `krynodes uninstall` on a laptop), enroll it
again and approve it.

## Stacks

The Stacks page lists each server's Docker Compose stacks, its containers that
belong to no stack and its systemd units. **Install Docker** puts Docker and
Docker Compose from Docker's own packages on a Debian or RHEL family server.
**New Stack** takes a name such as `web`, an optional title, the compose file,
an access level, a choice for each published port and an optional `.env`. The
server keeps them in `/var/lib/kry/compose/<name>`.

From a stack's ⋯ menu, **Deploy** pulls the newest images and starts them. When
the new images fail their health check within two minutes, the previous images
come back and the result says so; a stopped stack stays stopped. **Edit
Compose** changes the file and deploys it, and puts the previous file back when
the new one fails. **Rollback** goes back one step, to the images that ran
before the last deploy. **Remove** stops a stack and keeps it under Removed for
7 days, where **Restore** brings it back and **Delete Permanently** deletes it
with its volumes. A stack started by hand with Compose shows as Not Managed;
**Adopt** lets Krynodes manage it. Containers and units have Start, Stop and
Restart, and containers have Logs; protected ones, such as ssh, Docker and
Krynodes itself, are left alone.

**Access.** A **Contained** stack, the default, keeps to its own named volumes
and its own networks: host paths, privileged mode, extra capabilities, devices,
host namespaces, the Docker socket, building from source and images from the
server itself are refused, and the refusal names the setting. Its containers
reach the internet only: not the server's own services, not the members of the
private network and not any private or special address (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`,
`198.18.0.0/15`, the cloud metadata addresses and their IPv6 counterparts).
The containers of one stack still talk to each other, replies to what the
server allowed come back, and DNS keeps working through the nameserver Docker
uses, even when it sits in a private range. The exceptions are a nameserver that
is this server itself or a member of the private network. An app that must reach
a VPC or LAN address is a **Full** stack. **Full** access lets a stack reach the
server itself, its folders, devices and network; the owner chooses it in the
dialog.

**The guard.** The firewall rules that keep Contained stacks off the server
and the private network are in place before Docker starts. `kry guard` runs as
`ExecStartPre` of `docker.service`, from the drop-in
`/etc/systemd/system/docker.service.d/krynodes-guard.conf`, without a `-`
prefix: when the guard fails, Docker does not start, and the server's checks
and mails say so. `kry install-service` and **Install Docker** prove the guard
first and then write the drop-in. The daemon puts it back when it goes missing
and writes it without the proof once a Contained stack exists. One lock,
`/run/krynodes-guard.lock`, keeps two passes from working at once. Remove
Server and `kry uninstall-service` remove the drop-in, so Docker can start
again.

**Ports.** At every access level each published port is bound to
`127.0.0.1`, so a published port never listens on the internet; a Full stack
that shares the server's network can still listen by itself. A port set to **Private Network** is also bound to
the server's `kry0` address and is reachable from the members a Connections
rule allows, for example `server-2 → server-1 · 8080/tcp`. Without such a rule
the dialog says "Nothing reaches this port until a rule in Connections allows
it."

**.env.** The browser seals the `.env` to the server's own key before it is
signed, so the Worker never reads it. The compose file is sealed to the server
the same way, so the signed command carries no compose text. A failed stack or
container command says only one fixed sentence the Worker keeps, such as
"Deploy of web failed."; what Compose or Docker said is sealed to the browser
and shown under that sentence, so the Worker and History never hold it. The
Worker never sees a compose file, an `.env`, logs or the output of a stack or container command. The
server's inventory still reports each stack's title and service names, each
container's name, image and ports, and the host folder of an adopted stack. The
server writes the `.env` with mode `0600` and never sends it back; Edit Compose
shows only the names of its variables. A compose file is at most 32 KB and an `.env` at most
16 KB.

## Checks

**Add Check** in a stack's ⋯ menu watches one container under a name the owner
chooses. A check reads **Up** (running, and healthy when the container has a
health check), **Down**, **Paused** (stopped by the owner) or "--" (no such
container, nothing reported yet, or the server is offline). Adding, renaming,
making public and deleting a check change no machine, so they need no passkey.
A server reports a check only when its state changes.

A check that stays down for five minutes, and a server that stays offline for
five minutes, send one mail each, at most once an hour per check or server.
There is no mail for a recovery or for the owner's own stop, remove or deploy.
Mail goes through the Worker's `EMAIL` binding from `FROM_EMAIL` to
`ALERT_EMAIL`; without them nothing is sent. A server holds at most 64 checks.

## Status page

The `stats` Worker (`worker/wrangler.stats.jsonc`) is a public page, for
example `https://stats.example.test`, that reads the same D1 database. It shows
only the checks marked public, each by its public name and note: its state, 24
hourly bars, 90 daily bars and the uptime. It names no server and no
container. A check whose server has been offline for five minutes shows No
data, and time without data does not count against the uptime. History older
than 90 days is deleted. The Checks page links to the page when the Worker's
`STATUS_PAGE_URL` variable is set.

## Security model in plain words

- **The machine decides.** A server or laptop applies a network document only
  when a passkey it trusts signed it, with fingerprint, face or PIN. The
  document must also be exactly the next version after the one it holds, built
  on that version, and name the machine's own keys. The Worker only stores and
  forwards documents.
- **Every network command is signed.** That includes checks such as Test
  Link, because an unsigned check could make the fleet send traffic for
  someone else. One passkey touch opens a 5-minute session for a whole flow.
  The session ends when the page is hidden, and an ended session signs
  nothing.
- **Nothing joins without a touch.** There is no auto-approve and no document
  built by the Worker.
- **The Worker holds no secret.** Private keys stay on each machine.
  Preshared keys are made in the browser and sealed to each member's seal key,
  which is itself in the signed document.
- **Fail closed.** When a change cannot be applied, the machine keeps its
  previous document, configuration and rules exactly as they were.
- **Unsigned hints cost availability only.** The Worker suggests endpoints and
  meeting points, which can change where packets go but never who is a peer or
  what is allowed.
- **Every stack command is signed.** The sealed compose file, the access level, the
  served ports, the title and the sealed `.env` are part of the signed
  command, and the server runs nothing it did not receive inside one. Logs and
  reading a compose file are signed too, since both can hold secrets.
- **Logs, a compose file and every failure come back sealed.** For each stack or
  container command the browser makes a one-time key and signs its public half
  into the command. The server seals the text to that key and to its own seal
  key (`v:2`), so the Worker and D1 hold ciphertext only: they cannot open it
  and cannot forge an answer the browser accepts. A failed command carries one
  fixed sentence and, sealed the same way, what the server saw; progress lines
  are fixed phrases too. A success carries no text except Logs and Edit
  Compose. The first stack or container command on a server in a browser asks
  for the one-time fingerprint check, and a server outside the private network
  is refused before anything is signed, so its stacks cannot be changed from the
  dashboard.
- **The guard comes before Docker.** Contained stacks reach the internet only,
  and the rules that say so exist before the first container starts. When the
  guard cannot be installed, Docker stays down on that server: the cost is the
  server's apps, not an open firewall.
- **A Contained stack is vetted on the server.** The server checks the
  pasted text, then runs `docker compose config` as a user with no privileges
  and vets that output too, so anchors, `extends`, `include` and `${…}` cannot
  hide a setting. Host networking, privileged mode and the other settings
  listed under Stacks are refused. A Full stack is normalised as root and is
  refused only builds from source and networks that overlap the private
  network; Full is the owner's signed choice.
- **No port reaches the internet by accident.** At every access level a
  published port is bound to `127.0.0.1`, and a Private Network port also to
  the server's `kry0` address; `0.0.0.0`, `::` and empty addresses never reach
  Docker. A Full stack that shares the server's network can still listen on
  any address by itself.
- **The Worker never reads an `.env`.** It is sealed in the browser, and only
  for a server whose fingerprint this browser has checked.
- **Reports cost availability only.** Container states and inventories are
  unsigned reports: a Worker that has been taken over can hide a failure or
  invent one, but cannot start, stop or read anything. A sealed Logs, compose or
  failure answer is kept for 24 hours and left out of the action list.
- **Stated limits.** At enroll a machine takes its first passkey trust from the
  Worker once; the fingerprint check is how the owner closes that gap for the
  network. A fresh browser must check every member's fingerprint once before it
  signs a change. A server's first document must build on the one named in the
  signed prepare. A laptop has no prepare: it makes new keys whenever it leaves,
  so an old document never names it. The browser's memory covers the members,
  their keys and the version, not the rules: a taken-over Worker that serves a
  newer forged document with the same members could change the rules the owner
  builds on. Only a machine joining in that change would apply them; every
  member refuses the document because it does not follow the one they hold, and
  shows a failure. A signed document never ages, so a member offline for weeks still
  catches up. Code running in the dashboard during one passkey session could
  sign more than the owner meant, and such a chain breaks at the owner's next
  real change.

## Agent releases

`.github/workflows/agent-release.yml` builds the agent from `agent/VERSION`
and signs it with the release key. A push to `main` that changes `agent/` with
a new version publishes the release `agent-v<version>` as the Latest one;
production servers update only from Latest.

Running the workflow by hand on any other branch publishes a **pre-release**
instead. It carries the Linux and Windows builds, is never marked Latest, and
is never seen by a production Worker, which follows `releases/latest`. Test builds on the
overhaul branch are `0.7.90` and up; the first release of the new line is
`0.8.0`, made from `main`.

Agents older than `0.7.94` are refused by the Worker.

## Test deployment

Before anything reaches production, the overhaul runs on a separate deployment
of its own: the Worker `kry-test` and the D1 database `kry-test`, with the
dashboard at its own hostname behind its own Access application. It is the
`env.test` block of `worker/wrangler.jsonc`; the `RELEASES` variable lets that
Worker see pre-releases. Nothing in CI deploys it. The owner creates it by hand,
keeps the D1 id in a local copy of the config that is never committed, and
deletes it once the change lands.

## Production

- **Access.** Put the dashboard hostname behind a Cloudflare Access
  application. The Worker verifies the Access token itself and answers 401
  without one.
- **Agents** report to the Worker's `workers.dev` address (`AGENT_ORIGIN`),
  outside the zone, so zone bot protection cannot challenge them. The install
  command uses the same address once, so Bot Fight Mode can stay on for the
  zone. `/api/agent/*` and `/i/*` are rate limited per address.
- **Configuration.** `env.production` in `worker/wrangler.jsonc` holds the
  public values. The GitHub environment `production` supplies the rest:
  secrets `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `KRY_D1_ID`,
  `ALERT_EMAIL`, and variables `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`.
- **Bindings.** D1 `DB`, the `FLEET` Durable Object, static assets `ASSETS`,
  the `EMAIL` send binding. CI deploys the `stats` Worker after `kry`, on the
  same D1 database.
- **HTTPS.** The Worker sends `Strict-Transport-Security` on its own
  hostnames. Set the zone's minimum TLS version to 1.2 in Cloudflare.
- **GitHub.** CI's token is read-only; only the release workflow may write.

## Why there is no ESLint

`typescript-eslint` does not load against TypeScript 7, so no parser-based rule
can run here. `tooling/lint/unhandled-async.mjs` stands in for
`no-floating-promises` and `no-misused-promises` until it does.
