# Krynodes

Krynodes is a small, self-hosted console for a handful of Linux servers, run on
Cloudflare Workers. A single root daemon, `kry`, runs on each server and keeps
one WebSocket open to the Worker. The dashboard shows each server as Online or
Offline as it happens, and sits behind Cloudflare Access. D1 holds the servers,
the passkeys and the history.

Nothing a server does is decided by the Worker or by the dashboard login. A
person signs each action with a passkey in the browser, and the daemon checks
that signature against the passkeys it was told to trust before it acts. A
stolen Access session, or a Worker that has been taken over, cannot make a
server restart, update or remove itself.

This is the first part of an overhaul that turns Krynodes into a private mesh
between servers and laptops, with Docker stacks that move between servers. Part
1, in this tree, is the skeleton only:

- **Fleet.** Enroll a server with one command; see it Online or Offline live.
- **Passkeys.** Add a passkey, rename it, choose which servers trust it, remove
  it.
- **Actions.** Update Agent, Restart Server, Remove Server, each signed by a
  trusted passkey. A command is instant or refused: a server that is offline
  refuses it at once, and nothing waits in a queue.
- **History.** Every action, who it went to and how it ended.

The mesh, moving stacks, container checks, web addresses and the Windows agent
come in later parts. The 0.7 line's metrics, incidents and hardening are not in
this tree; they are not hidden, they are removed.

```text
Browser ── Cloudflare Access ── kry Worker ── D1
 (signs)                           │
                                   └── FleetHub (Durable Object) ══ wss ══ kry on each server
```

## Layout

| Path                | What                                                                       |
| ------------------- | -------------------------------------------------------------------------- |
| `worker/`           | Hono Worker: dashboard API, agent API, the `FleetHub` Durable Object, D1   |
| `app/`              | React dashboard (Tailwind v4, shadcn/ui, TanStack Query)                   |
| `agent/`            | Go daemon `kry`, standard library only                                     |
| `packages/protocol` | Zod schemas for the agent and Worker wire, with fixtures the Go tests read |
| `tooling/`          | TypeScript presets, Vite config, lint scripts                              |

## Develop

```sh
pnpm install
pnpm turbo run build --filter=@krynodes/worker^...
pnpm exec wrangler dev --config worker/wrangler.jsonc --port 8790
```

With no Access variables set, the Worker runs as a local standalone operator,
so the dashboard opens without signing in. Production refuses to serve at all
without Access. Rebuild the app and restart `wrangler dev` after every app
change; it serves the built assets from `app/dist`.

## Check

```sh
pnpm check         # format, knip, lint scripts, typecheck, tests, build
pnpm native:check  # go test, vet, build, deadcode
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

The server is Online in Fleet within a few seconds. Afterwards:

```sh
sudo systemctl status krynodes
kry version
```

Remove Server in the dashboard takes the unit, `/etc/kry`, `/var/lib/kry` and
the binary off the server; the server itself keeps running. `sudo kry
uninstall-service` does the same by hand.

## Agent releases

`.github/workflows/agent-release.yml` builds the agent from `agent/VERSION`
and signs it with the release key. A push to `main` that changes `agent/` with
a new version publishes the release `agent-v<version>` as the Latest one;
production servers update only from Latest.

Running the workflow by hand on any other branch publishes a **pre-release**
instead. It is built for Linux only, is never marked Latest, and is never seen
by a production Worker, which follows `releases/latest`. Test builds on the
overhaul branch are `0.7.90` and up; the first release of the new line is
`0.8.0`, made from `main`.

Agents older than `0.7.90` are refused by the Worker.

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
- **Bindings.** D1 `DB`, the `FLEET` Durable Object, static assets `ASSETS`.
- **HTTPS.** The Worker sends `Strict-Transport-Security` on its own
  hostnames. Set the zone's minimum TLS version to 1.2 in Cloudflare.
- **GitHub.** CI's token is read-only; only the release workflow may write.

## Why there is no ESLint

`typescript-eslint` does not load against TypeScript 7, so no parser-based rule
can run here. `tooling/lint/unhandled-async.mjs` stands in for
`no-floating-promises` and `no-misused-promises` until it does.
