import { receiveReport, type Finding } from "../actions/report";
import {
  healStatements,
  heartbeatActions,
  plannedNodes,
  REBOOT_MS,
  stoppedChecks,
  workingChecks,
} from "../actions/store";
import {
  acceptResults,
  commit,
  heartbeatResponse,
  heartbeatStatements,
  insertWindow,
  updateRetry,
  loadAgentConfig,
  resultStatements,
  type AgentNode,
} from "../agent/ingest";
import { restartOf } from "../agent/quiet";
import { windowStart } from "../agent/windows";
import type { Env } from "../env";
import {
  loadBox,
  receive,
  type IncidentNotice,
  type MailBox,
  type ServerChanges,
} from "../incident/notify";
import {
  sendFleetEmail,
  sendQuarantineEmail,
  sendSecurityEmail,
  sendServerEmail,
  sendStoppedEmail,
  sendTailnetDeviceEmail,
  sendTailnetPolicyEmail,
  sendWarningEmail,
  type StoppedMail,
  type TailnetMail,
  type WarningMail,
} from "../lib/mail";
import { actionsSchema, heartbeatSchema } from "../schemas";
import { agentConfigResponseSchema } from "@krynodes/protocol";
import {
  drain,
  fold,
  liveView,
  newState,
  resumeWindow,
  type Flush,
  type StoredWindow,
  type StreamState,
} from "./stream";
import { HubNetwork } from "./network";
import {
  cutOffWarning,
  intake,
  warningStatement,
  type Cutoff,
  type Intake,
} from "../quarantine/events";
import {
  holdStatement,
  quarantine,
  quarantineReport,
} from "../quarantine/quarantine";
import { readSettings } from "../quarantine/settings";
import { judgeTailnet } from "../tailscale/hook";

const NODE_SQL = `SELECT id, interval_seconds, update_requested_version, update_requested_at,
         update_attempts, update_error, inventory_hash, refresh_requested_at, security,
         boot, reports, release,
         EXISTS (SELECT 1 FROM quarantines q
                 WHERE q.node_id = nodes.id AND q.released_at IS NULL) AS quarantined
  FROM nodes
  WHERE id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL`;

const CUTOFFS = "cutoffs";
const TAILNET = "tailnet";
const QUIET_HANDSHAKE_S = 180;
const CLONED = "Reported from two machines at once";

type Reply = (message: Record<string, unknown>) => void;

const WATCH = "watch";
const MAIL = "mail";
const ROSTER = "roster";
const MAIL_STATE = "mailState";
const MESSAGES_PER_MINUTE = 60;
const STOPPED_MS = 10 * 60_000;
const MAILS_AT_ONCE = 5;
const WATCHDOG_RETRY_MS = 60_000;
const RECHECK_MS = 60_000;

interface RosterEntry {
  interval: number;
  lastSeen?: number;
  offline?: boolean;
  checkedAt?: number;
  disk?: boolean;
}

const DISK_FULL = 95;
const DISK_CLEAR = 90;

type Roster = Record<string, RosterEntry>;

interface Tailnet {
  owner: string;
  due: number;
}

const offlineAfterMs = (interval: number) => Math.max(90, 3 * interval) * 1000;

function restarting(security: string | null, seen: number, now: number) {
  const restart = restartOf(security);
  return (
    now - seen < REBOOT_MS &&
    restart.hour === new Date(seen).getUTCHours() &&
    restart.pending
  );
}

const watching = (ws: WebSocket) =>
  (ws.deserializeAttachment() as { watch?: boolean } | null)?.watch === true;

export class FleetHub {
  private readonly ctx: DurableObjectState;
  private readonly env: Env;
  private readonly spent = new WeakMap<
    WebSocket,
    { since: number; count: number }
  >();
  private readonly network: HubNetwork;
  private readonly stopped = new Map<
    string,
    { at: number; checks: Set<string> }
  >();

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
    this.network = new HubNetwork(env.DB, ctx.storage);
    ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong"),
    );
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/connect") {
      const nodeId = request.headers.get("x-kry-node");
      const ownerId = request.headers.get("x-kry-owner");
      const interval = Number(request.headers.get("x-kry-interval") ?? "60");
      if (!nodeId || !ownerId) return new Response(null, { status: 400 });
      const [client, server] = Object.values(new WebSocketPair());
      await this.accept(server!, nodeId, ownerId, interval);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/watch") {
      const [client, server] = Object.values(new WebSocketPair());
      await this.watch(server!);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/announce" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as {
        topics?: unknown;
      } | null;
      const topics = Array.isArray(body?.topics)
        ? body.topics.filter(
            (topic): topic is string => typeof topic === "string",
          )
        : [];
      if (topics.length > 0) this.announce(topics);
      return Response.json({ announced: topics.length > 0 });
    }
    if (url.pathname === "/live") {
      return Response.json({
        nodes: liveView(
          this.ctx
            .getWebSockets()
            .filter((ws) => !watching(ws))
            .map((ws) => ws.deserializeAttachment() as StreamState),
        ),
        mail: (await this.ctx.storage.get(MAIL_STATE)) ?? null,
      });
    }
    if (url.pathname === "/network") {
      return Response.json(Object.fromEntries(this.network.latest));
    }
    if (url.pathname === "/tailnet" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as {
        owner?: unknown;
        due?: unknown;
      } | null;
      if (typeof body?.owner !== "string" || typeof body.due !== "number") {
        return new Response(null, { status: 400 });
      }
      const stored = await this.ctx.storage.get<Tailnet>(TAILNET);
      await this.ctx.storage.put(TAILNET, {
        owner: body.owner,
        due: Math.min(stored?.due ?? Infinity, body.due),
      });
      await this.schedule(Date.now());
      return Response.json({});
    }
    if (url.pathname === "/poke" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as {
        nodeIds?: unknown;
      } | null;
      const nodeIds = Array.isArray(body?.nodeIds)
        ? body.nodeIds.filter((id): id is string => typeof id === "string")
        : [];
      return Response.json({ poked: this.poke(nodeIds) });
    }
    return new Response(null, { status: 404 });
  }

  private poke(nodeIds: string[]): number {
    let poked = 0;
    for (const nodeId of nodeIds) {
      for (const ws of this.ctx.getWebSockets(nodeId)) {
        try {
          ws.send(JSON.stringify({ type: "poke" }));
          poked += 1;
        } catch {
          continue;
        }
      }
    }
    return poked;
  }

  async accept(
    ws: WebSocket,
    nodeId: string,
    ownerId: string,
    interval: number,
  ): Promise<void> {
    for (const old of this.ctx.getWebSockets(nodeId)) {
      await this.leave(old);
      try {
        old.close(4000, "Replaced by a newer connection");
      } catch {
        continue;
      }
    }
    this.ctx.acceptWebSocket(ws, [nodeId]);
    ws.serializeAttachment(newState(nodeId, ownerId, interval));
    const roster = await this.roster();
    roster[nodeId] = {
      interval,
      offline: roster[nodeId]?.offline,
      disk: roster[nodeId]?.disk,
    };
    await this.ctx.storage.put(ROSTER, roster);
    await this.schedule(Date.now());
  }

  async watch(ws: WebSocket): Promise<void> {
    this.ctx.acceptWebSocket(ws, [WATCH]);
    ws.serializeAttachment({ watch: true });
  }

  announce(topics: string[]): void {
    const message = JSON.stringify({ type: "changed", topics });
    for (const ws of this.ctx.getWebSockets(WATCH)) {
      try {
        ws.send(message);
      } catch {
        continue;
      }
    }
  }

  async webSocketMessage(
    ws: WebSocket,
    message: string | ArrayBuffer,
  ): Promise<void> {
    if (watching(ws)) return;
    const now = Date.now();
    const spent = this.spent.get(ws);
    if (!spent || now - spent.since >= 60_000) {
      this.spent.set(ws, { since: now, count: 1 });
    } else if (++spent.count > MESSAGES_PER_MINUTE) {
      if (spent.count === MESSAGES_PER_MINUTE + 1) {
        ws.send(JSON.stringify({ type: "error", code: "TOO_MANY_MESSAGES" }));
      }
      return;
    }
    let body: unknown;
    try {
      body = JSON.parse(
        typeof message === "string"
          ? message
          : new TextDecoder().decode(message),
      );
    } catch {
      ws.send(JSON.stringify({ type: "error", code: "INVALID_MESSAGE" }));
      return;
    }
    const envelope = (body ?? {}) as {
      id?: unknown;
      type?: unknown;
      heartbeat?: unknown;
      report?: unknown;
    };
    if (typeof envelope.id !== "number") {
      ws.send(JSON.stringify({ type: "error", code: "INVALID_MESSAGE" }));
      return;
    }
    const id = envelope.id;
    const reply: Reply = (answer) => {
      try {
        ws.send(JSON.stringify({ id, ...answer }));
      } catch {
        return;
      }
    };
    const invalid = () => reply({ type: "error", code: "INVALID_MESSAGE" });
    const state = ws.deserializeAttachment() as StreamState;
    try {
      if (envelope.type === "heartbeat") {
        const parsed = heartbeatSchema.safeParse(envelope.heartbeat);
        if (!parsed.success || parsed.data.nodeId !== state.nodeId) {
          invalid();
          return;
        }
        await this.heartbeat(ws, state, parsed.data, reply);
      } else if (envelope.type === "config") {
        const node = await this.node(ws, state);
        if (!node) return;
        const agent = await loadAgentConfig(this.env.DB, node);
        reply({
          type: "config",
          config: agentConfigResponseSchema.parse({
            ...agent.config,
            configVersion: agent.configVersion,
          }),
        });
      } else if (envelope.type === "actions") {
        let parsed = actionsSchema.safeParse(envelope.report);
        if (!parsed.success) {
          console.error("[kry fleet] report refused", parsed.error.issues[0]);
          const report = (envelope.report ?? {}) as {
            nodeId?: unknown;
            results?: unknown;
          };
          parsed = actionsSchema.safeParse({
            nodeId: report.nodeId,
            results: report.results,
          });
        }
        if (!parsed.success || parsed.data.nodeId !== state.nodeId) {
          invalid();
          return;
        }
        const node = await this.node(ws, state);
        if (!node) return;
        this.stopped.delete(node.id);
        const { alerts, next, deleted, ...response } = await receiveReport(
          this.env.DB,
          node,
          parsed.data,
          Date.now(),
        );
        reply({ type: "actions", response });
        this.poke(next);
        this.announce(
          deleted
            ? ["all"]
            : parsed.data.results || parsed.data.inventory
              ? ["actions", "services"]
              : ["actions"],
        );
        if (alerts.length > 0) await this.securityMail(node.id, alerts);
      } else {
        invalid();
      }
    } catch (error) {
      console.error("[kry fleet]", error);
      reply({ type: "error", code: "SERVER_ERROR" });
    }
  }

  private async node(ws: WebSocket, state: StreamState) {
    const node = await this.env.DB.prepare(NODE_SQL)
      .bind(state.nodeId)
      .first<AgentNode>();
    if (!node) ws.close(4401, "Unknown or disabled server");
    return node;
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    if (watching(ws)) return;
    await this.leave(ws);
    this.announce(["nodes"]);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    if (watching(ws)) return;
    await this.leave(ws);
    this.announce(["nodes"]);
  }

  private async box() {
    return loadBox(await this.ctx.storage.get<MailBox>(MAIL));
  }

  private async roster() {
    return (await this.ctx.storage.get<Roster>(ROSTER)) ?? {};
  }

  private heard(ws: WebSocket, state: StreamState) {
    return Math.max(
      state.lastSeen ?? state.connectedAt,
      this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime() ?? 0,
    );
  }

  private pulse(nodeId: string, entry: RosterEntry) {
    let pulse: { seen?: number; limit: number } = {
      seen: entry.lastSeen,
      limit: offlineAfterMs(entry.interval),
    };
    for (const socket of this.ctx.getWebSockets(nodeId)) {
      const state = socket.deserializeAttachment() as StreamState;
      const seen = this.heard(socket, state);
      if (seen > (pulse.seen ?? 0)) {
        pulse = { seen, limit: offlineAfterMs(state.interval) };
      }
    }
    return pulse;
  }

  private async cutoffs() {
    return (await this.ctx.storage.get<Record<string, number>>(CUTOFFS)) ?? {};
  }

  private async keepCutoffs(cutoffs: Cutoff[]) {
    if (cutoffs.length === 0) return;
    const stored = await this.cutoffs();
    for (const cutoff of cutoffs) {
      stored[`${cutoff.nodeId}|${cutoff.id}`] = cutoff.at;
    }
    await this.ctx.storage.put(CUTOFFS, stored);
  }

  private async cutOff(now: number) {
    const stored = await this.cutoffs();
    const due = Object.entries(stored).filter(([, at]) => at <= now);
    if (due.length === 0) return;
    const poke: string[] = [];
    const quarantined: string[] = [];
    for (const [key] of due) {
      const [nodeId, id] = key.split("|") as [string, string];
      const cut = await cutOffWarning(this.env.DB, nodeId, id);
      poke.push(...cut.nodes);
      quarantined.push(...cut.quarantined);
      delete stored[key];
    }
    await this.ctx.storage.put(CUTOFFS, stored);
    this.poke(poke);
    this.announce(["all"]);
    await this.tell({ quarantined });
  }

  private async tell(told: {
    warned?: WarningMail[];
    stopped?: StoppedMail[];
    quarantined?: string[];
    tailnet?: TailnetMail[];
  }) {
    const { warned = [], stopped = [], quarantined = [], tailnet = [] } = told;
    if (
      warned.length + stopped.length + quarantined.length + tailnet.length ===
      0
    )
      return;
    try {
      for (const mail of warned) await sendWarningEmail(this.env, mail);
      for (const mail of stopped) await sendStoppedEmail(this.env, mail);
      for (const nodeId of quarantined) {
        const report = await quarantineReport(this.env.DB, nodeId);
        if (report) await sendQuarantineEmail(this.env, report);
      }
      for (const mail of tailnet) {
        if (mail.kind === "device")
          await sendTailnetDeviceEmail(this.env, mail);
        else await sendTailnetPolicyEmail(this.env, mail);
      }
      await this.noteMail(this.mailSetup());
    } catch (error) {
      console.error("[kry mail]", error);
      await this.noteMail(error);
    }
  }

  private async quiet(silent: { nodeId: string; seen: number }[], now: number) {
    if (silent.length === 0) return;
    const db = this.env.DB;
    const members = (
      await db
        .prepare(
          `SELECT m.node_id, m.key, n.owner_user_id AS owner, n.name FROM network_members m
           JOIN nodes n ON n.id = m.node_id
           WHERE m.state = 'in' AND m.node_id IN (SELECT value FROM json_each(?))`,
        )
        .bind(JSON.stringify(silent.map((item) => item.nodeId)))
        .all<{ node_id: string; key: string; owner: string; name: string }>()
    ).results;
    const cutoffs: Cutoff[] = [];
    const warned: WarningMail[] = [];
    for (const member of members) {
      const seenBy = [...this.network.latest]
        .filter(
          ([other, entry]) =>
            other !== member.node_id &&
            entry.links.some(
              (link) =>
                link.key === member.key &&
                link.handshake !== null &&
                now / 1000 - link.handshake < QUIET_HANDSHAKE_S,
            ),
        )
        .map(([other]) => other);
      if (seenBy.length === 0) continue;
      const names = (
        await db
          .prepare(
            "SELECT name FROM nodes WHERE id IN (SELECT value FROM json_each(?)) ORDER BY name",
          )
          .bind(JSON.stringify(seenBy))
          .all<{ name: string }>()
      ).results.map((row) => row.name);
      const seen = silent.find((item) => item.nodeId === member.node_id)!.seen;
      const settings = await readSettings(db, member.owner);
      const cutAt =
        settings.cutoff === null ? null : now + settings.cutoff * 60_000;
      const id = `quiet:${seen}`;
      const detail = {
        lastReport: new Date(seen).toISOString(),
        seenBy: names.join(", "),
      };
      const at = new Date(now).toISOString();
      const written = await warningStatement(db, {
        nodeId: member.node_id,
        id,
        kind: "quiet",
        detail,
        at,
        cutAt,
      }).run();
      if ((written.meta.changes ?? 0) === 0) continue;
      warned.push({
        nodeId: member.node_id,
        nodeName: member.name,
        kind: "quiet",
        detail,
        at,
        cutAt,
      });
      if (cutAt !== null) {
        cutoffs.push({ nodeId: member.node_id, id, at: cutAt });
      }
    }
    await this.keepCutoffs(cutoffs);
    await this.tell({ warned });
  }

  private async judge(now: number) {
    const tailnet = await this.ctx.storage.get<Tailnet>(TAILNET);
    if (!tailnet || tailnet.due > now) return;
    const judged = await judgeTailnet(this.env.DB, tailnet.owner, now);
    if (judged.due === null) await this.ctx.storage.delete(TAILNET);
    else await this.ctx.storage.put(TAILNET, { ...tailnet, due: judged.due });
    await this.tell({ tailnet: judged.mails });
  }

  private async schedule(now: number) {
    const times: number[] = Object.values(await this.cutoffs());
    const tailnet = await this.ctx.storage.get<Tailnet>(TAILNET);
    if (tailnet) times.push(tailnet.due);
    for (const [nodeId, entry] of Object.entries(await this.roster())) {
      if (entry.offline) continue;
      const { seen, limit } = this.pulse(nodeId, entry);
      times.push(
        Math.max((seen ?? now) + limit, (entry.checkedAt ?? 0) + RECHECK_MS),
      );
    }
    if (times.length === 0) await this.ctx.storage.deleteAlarm();
    else
      await this.ctx.storage.setAlarm(
        Math.max(Math.min(...times), now + 1_000),
      );
  }

  private async notify(notices: IncidentNotice[], now: number) {
    const { box, send } = receive(await this.box(), notices, now);
    await this.ctx.storage.put(MAIL, box);
    return send;
  }

  private async watchdog(now: number): Promise<IncidentNotice[]> {
    const db = this.env.DB;
    const roster = await this.roster();
    const notices: IncidentNotice[] = [];
    let changed = false;
    const silent: { nodeId: string; entry: RosterEntry; seen: number }[] = [];
    for (const [nodeId, entry] of Object.entries(roster)) {
      if (entry.offline) continue;
      const { seen, limit } = this.pulse(nodeId, entry);
      if (seen === undefined) {
        entry.lastSeen = now;
        changed = true;
        continue;
      }
      if (now - seen <= limit || now - (entry.checkedAt ?? 0) < RECHECK_MS) {
        continue;
      }
      changed = true;
      silent.push({ nodeId, entry, seen });
    }
    const ids = JSON.stringify(silent.map((item) => item.nodeId));
    const rows =
      silent.length === 0
        ? []
        : (
            await db
              .prepare(
                `SELECT id, security FROM nodes WHERE id IN (SELECT value FROM json_each(?))
                 AND enrolled_at IS NOT NULL AND disabled_at IS NULL`,
              )
              .bind(ids)
              .all<{ id: string; security: string | null }>()
          ).results;
    const known = new Map(rows.map((row) => [row.id, row.security]));
    const planned = await plannedNodes(db, [...known.keys()], now);
    const quiet: { nodeId: string; seen: number }[] = [];
    for (const { nodeId, entry, seen } of silent) {
      if (!known.has(nodeId)) {
        delete roster[nodeId];
      } else if (
        restarting(known.get(nodeId) ?? null, seen, now) ||
        planned.has(nodeId)
      ) {
        entry.checkedAt = now;
      } else {
        entry.offline = true;
        delete entry.checkedAt;
        quiet.push({ nodeId, seen });
        for (const socket of this.ctx.getWebSockets(nodeId)) {
          const state = socket.deserializeAttachment() as StreamState;
          socket.serializeAttachment({ ...state, away: true });
        }
        notices.push({
          nodeId,
          checkId: null,
          checkName: null,
          kind: "opened",
          summary: "Stopped reporting",
          occurredAt: new Date(seen).toISOString(),
        });
      }
    }
    if (changed) await this.ctx.storage.put(ROSTER, roster);
    await this.quiet(quiet, now);
    return notices;
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    let send: ServerChanges[] = [];
    try {
      const offline = await this.watchdog(now);
      send = offline.length > 0 ? await this.notify(offline, now) : [];
      await this.cutOff(now);
      await this.judge(now);
      await this.schedule(now);
    } catch (error) {
      console.error("[kry fleet] watchdog", error);
      await this.ctx.storage.setAlarm(now + WATCHDOG_RETRY_MS);
    }
    await this.mail(send);
  }

  private async securityMail(nodeId: string, findings: Finding[]) {
    try {
      const row = await this.env.DB.prepare(
        "SELECT name FROM nodes WHERE id = ?",
      )
        .bind(nodeId)
        .first<{ name: string }>();
      if (row) {
        await sendSecurityEmail(this.env, {
          nodeId,
          nodeName: row.name,
          findings,
        });
        await this.noteMail(this.mailSetup());
      }
    } catch (error) {
      console.error("[kry mail]", error);
      await this.noteMail(error);
    }
  }

  private mailSetup() {
    return this.env.EMAIL && this.env.ALERT_EMAIL
      ? null
      : new Error("the Worker has no ALERT_EMAIL or EMAIL binding.");
  }

  private async noteMail(error: unknown) {
    if (error === null) {
      if (await this.ctx.storage.get(MAIL_STATE)) {
        await this.ctx.storage.delete(MAIL_STATE);
      }
      return;
    }
    await this.ctx.storage.put(MAIL_STATE, {
      failedAt: new Date(Date.now()).toISOString(),
      error: (error instanceof Error ? error.message : String(error)).slice(
        0,
        300,
      ),
    });
  }

  private async mail(send: ServerChanges[]) {
    if (send.length === 0) return;
    try {
      const rows = await this.env.DB.prepare(
        "SELECT id, name FROM nodes WHERE id IN (SELECT value FROM json_each(?))",
      )
        .bind(JSON.stringify(send.map((server) => server.nodeId)))
        .all<{ id: string; name: string }>();
      const names = new Map(rows.results.map((row) => [row.id, row.name]));
      const named = send.flatMap((server) => {
        const nodeName = names.get(server.nodeId);
        return nodeName ? [{ nodeName, ...server }] : [];
      });
      if (named.length > MAILS_AT_ONCE) {
        await sendFleetEmail(this.env, named);
      } else {
        for (const server of named) await sendServerEmail(this.env, server);
      }
      await this.noteMail(this.mailSetup());
    } catch (error) {
      console.error("[kry mail]", error);
      await this.noteMail(error);
    }
  }

  private async heartbeat(
    ws: WebSocket,
    current: StreamState,
    beat: Parameters<typeof fold>[1],
    reply: Reply,
  ) {
    const db = this.env.DB;
    const now = Date.now();
    const known = await this.node(ws, current);
    if (!known) return;
    const poked: string[] = [];
    const cloned: string[] = [];
    if (
      !known.quarantined &&
      beat.boot &&
      known.boot &&
      beat.boot.id !== known.boot &&
      beat.boot.count <= (known.reports ?? 0)
    ) {
      const started = await quarantine(db, {
        nodeId: known.id,
        why: CLONED,
        now,
      });
      poked.push(...started.nodes);
      if (started.started) cloned.push(known.id);
      known.quarantined = 1;
    }
    const trusted = !known.quarantined;
    const retried = updateRetry(db, known, beat, now);
    const node = retried.node;
    let state: StreamState = { ...current, interval: node.interval_seconds };
    if (state.lastSeen === null) {
      const row = await db
        .prepare(
          `SELECT window_start, samples, cpu_percent, memory_used_bytes,
                  memory_total_bytes, disk_used_bytes, disk_total_bytes, load_1,
                  load_5, load_15, uptime_seconds, checks
           FROM node_windows WHERE node_id = ? AND window_start = ?`,
        )
        .bind(node.id, windowStart(now, node.interval_seconds))
        .first<StoredWindow>();
      state = resumeWindow(state, row, now);
    }
    const disk = await this.disk(node.id, current, beat.metrics, now);
    state = { ...state, diskFull: disk.full };
    const agent = await loadAgentConfig(db, node);
    const accepted = trusted
      ? acceptResults(agent.checks, beat.results ?? [])
      : [];
    const owned = {
      id: node.id,
      ownerId: current.ownerId,
      connectedAt: current.connectedAt,
    };
    const working = accepted.some((result) => result.status === "DOWN")
      ? new Set([
          ...(await workingChecks(db, owned, agent.checks, now)),
          ...(await this.stoppedChecks(owned, agent.checks, now)),
        ])
      : new Set<string>();
    const ingestion = resultStatements(
      db,
      agent.checks,
      accepted,
      now,
      working,
    );
    const folded = fold(state, beat, accepted, now);
    const leading: D1PreparedStatement[] = [];
    if (folded.flushed)
      leading.push(this.flushStatement(node.id, folded.flushed));
    if (folded.writeNode) {
      leading.push(...heartbeatStatements(db, node, beat, now));
    }
    leading.push(...retried.statements);
    const reported = beat.release ? JSON.stringify(beat.release) : null;
    const pending = known.release ?? null;
    if (
      reported !== pending &&
      !(JSON.parse(pending ?? "null") as { released?: boolean } | null)
        ?.released
    ) {
      leading.push(
        db
          .prepare(
            `UPDATE nodes SET release = ? WHERE id = ?
             AND (release IS NULL OR json_extract(release, '$.released') IS NULL)`,
          )
          .bind(reported, node.id),
      );
    }
    if (current.lastSeen === null || current.away) {
      await this.returned(node.id);
    }
    const notices = await commit(this.env, node.id, leading, ingestion);
    const heals = await healStatements(
      db,
      { id: node.id, agent_version: beat.agentVersion ?? null },
      notices
        .filter((notice) => notice.kind === "opened" && notice.checkId)
        .map((notice) => notice.checkId!),
      now,
    );
    const healing = new Set<string>();
    if (heals.length > 0) {
      const done = await db.batch(heals.map((heal) => heal.statement));
      heals.forEach((heal, index) => {
        if ((done[index]?.meta.changes ?? 0) > 0) {
          for (const id of heal.checkIds) healing.add(id);
        }
      });
    }
    const marked = [
      ...notices.map((notice) =>
        notice.checkId && healing.has(notice.checkId)
          ? { ...notice, healing: true }
          : notice,
      ),
      ...disk.notices,
    ];
    const mails = marked.length > 0 ? await this.notify(marked, now) : [];
    await disk.store?.();
    let taken: Intake | null = null;
    try {
      const network =
        beat.network && trusted
          ? await this.network.beat(
              node.id,
              current.ownerId,
              current.networkStamp,
              beat.network,
              now,
            )
          : null;
      taken = !beat.events?.length
        ? null
        : trusted
          ? await intake(db, { nodeId: node.id, events: beat.events, now })
          : {
              acked: beat.events.map((event) => event.id),
              cutoffs: [],
              nodes: [],
              quarantined: [],
              warned: [],
              stopped: [],
            };
      if (taken) {
        await this.keepCutoffs(taken.cutoffs);
        poked.push(...taken.nodes);
        if (taken.cutoffs.length > 0) await this.schedule(now);
      }
      if (!trusted) {
        await holdStatement(db, node.id, new Date(now).toISOString()).run();
      }
      const actions = await heartbeatActions(db, node.id, now);
      ws.serializeAttachment({
        ...folded.state,
        away: false,
        networkStamp: network?.stamp ?? current.networkStamp,
      });
      if (current.lastSeen === null || notices.length > 0) {
        await this.schedule(now);
      }
      reply({
        type: "heartbeat",
        response: {
          ...heartbeatResponse(
            node,
            agent.configVersion,
            beat.agentVersion,
            actions,
          ),
          ...(network?.reply ? { network: network.reply } : {}),
          ...(taken ? { acked: taken.acked } : {}),
          ...(trusted ? {} : { quarantined: true }),
        },
      });
      if (network) this.poke(network.poke);
      if (poked.length > 0) {
        this.poke(poked.filter((id) => id !== node.id));
        this.announce(["all"]);
      }
      const topics = [
        ...(current.lastSeen === null ? ["nodes"] : []),
        ...(ingestion.statements.length > 0 || ingestion.transitions.length > 0
          ? ["checks"]
          : []),
        ...(actions.length > 0 ? ["actions"] : []),
      ];
      if (topics.length > 0) this.announce(topics);
    } finally {
      await this.mail(mails);
      await this.tell({
        warned: taken?.warned,
        stopped: taken?.stopped,
        quarantined: [...cloned, ...(taken?.quarantined ?? [])],
      });
    }
  }

  private async stoppedChecks(
    node: { id: string; ownerId: string },
    checks: { id: string; kind: string; target: string }[],
    now: number,
  ) {
    const kept = this.stopped.get(node.id);
    if (kept && now - kept.at < STOPPED_MS) return kept.checks;
    const found = await stoppedChecks(this.env.DB, node, checks);
    this.stopped.set(node.id, { at: now, checks: found });
    return found;
  }

  private async disk(
    nodeId: string,
    current: StreamState,
    metrics: Parameters<typeof fold>[1]["metrics"],
    now: number,
  ): Promise<{
    full?: boolean;
    notices: IncidentNotice[];
    store?: () => Promise<void>;
  }> {
    const { diskUsedBytes: used, diskTotalBytes: total } = metrics;
    if (used === null || !total) return { full: current.diskFull, notices: [] };
    const percent = Math.round((used / total) * 100);
    const full =
      percent >= DISK_FULL ? true : percent < DISK_CLEAR ? false : undefined;
    if (full === undefined || full === current.diskFull) {
      return { full: current.diskFull, notices: [] };
    }
    const roster = await this.roster();
    const entry = roster[nodeId];
    if (!entry || Boolean(entry.disk) === full) {
      return { full, notices: [] };
    }
    const store = async () => {
      const latest = await this.roster();
      if (latest[nodeId]) {
        latest[nodeId] = { ...latest[nodeId], disk: full };
        await this.ctx.storage.put(ROSTER, latest);
      }
    };
    return {
      full,
      store,
      notices: full
        ? [
            {
              nodeId,
              checkId: null,
              checkName: null,
              kind: "opened",
              summary: `${percent}% full`,
              occurredAt: new Date(now).toISOString(),
              disk: true,
            },
          ]
        : [],
    };
  }

  private async returned(nodeId: string) {
    const roster = await this.roster();
    const entry = roster[nodeId];
    if (!entry?.offline) return;
    roster[nodeId] = { interval: entry.interval, disk: entry.disk };
    await this.ctx.storage.put(ROSTER, roster);
  }

  private flushStatement(nodeId: string, flush: Flush) {
    return insertWindow(
      this.env.DB,
      nodeId,
      flush.start,
      flush.samples,
      flush.metrics,
      flush.checks,
    );
  }

  private async leave(ws: WebSocket) {
    const state = ws.deserializeAttachment() as StreamState | null;
    if (!state || state.left) return;
    const drained = drain(state);
    ws.serializeAttachment({ ...drained.state, left: true });
    const statements: D1PreparedStatement[] = [];
    if (drained.flushed) {
      statements.push(this.flushStatement(state.nodeId, drained.flushed));
    }
    const roster = await this.roster();
    roster[state.nodeId] = {
      ...roster[state.nodeId],
      interval: state.interval,
      lastSeen: this.heard(ws, state),
    };
    await this.ctx.storage.put(ROSTER, roster);
    if (state.beat && state.lastSeen !== null) {
      statements.push(
        ...heartbeatStatements(
          this.env.DB,
          { id: state.nodeId, interval_seconds: state.interval },
          state.beat,
          state.lastSeen,
        ),
      );
    }
    if (statements.length === 0) return;
    try {
      await this.env.DB.batch(statements);
    } catch (error) {
      console.error("[kry fleet]", error);
    }
  }
}
