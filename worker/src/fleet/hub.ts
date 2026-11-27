import {
  agentSupported,
  hubMessageSchema,
  MIN_AGENT,
  parseAgentMessage,
  type AgentMessage,
  type HubMessage,
  type TrustReport,
} from "@krynodes/protocol";

import type { Env } from "../env";
import {
  type DownCheck,
  mailReady,
  sendCheckDownEmail,
  sendOfflineEmail,
} from "../lib/mail";
import { clearOldOutput } from "../routes/actions";
import { HubNetwork } from "./network";

const AGENT = "agent";
const WATCH = "watch";
const SEEN_EVERY_MS = 10 * 60_000;
const PING_EVERY_MS = 25_000;
const SILENT_AFTER_MS = 3 * PING_EVERY_MS;
const SWEEP_EVERY_MS = 60_000;
const SILENT_CODE = 4408;
const MAX_INVENTORY_BYTES = 1024 * 1024;
const DUE = "due";
const AGENTS = "agents";
const SLACK_MS = 10 * 60_000;
const MAIL_AFTER_MS = 5 * 60_000;
const MAIL_EVERY_MS = 60 * 60_000;
const MAIL_RETRY_MS = 60_000;
const KEEP_TRANSITIONS_MS = 90 * 24 * 60 * 60_000;

interface Attachment {
  nodeId: string;
  version: string;
  since: number;
  heard: number;
}

interface Facts {
  hostname: string | null;
  os: string | null;
  arch: string | null;
  kernel: string | null;
  version: string | null;
  seal_key: string | null;
  last_seen_at: string | null;
}

type Hello = Extract<AgentMessage, { type: "hello" }>;
type Result = Extract<AgentMessage, { type: "result" }>;
type Inventory = Extract<AgentMessage, { type: "inventory" }>;
type Check = Extract<AgentMessage, { type: "check" }>;

interface DueCheck {
  id: string;
  node_id: string;
  node_name: string;
  container: string;
  name: string;
  since: string;
  mailed_at: string | null;
}

interface DueNode {
  id: string;
  name: string;
  last_seen_at: string;
  offline_mailed_at: string | null;
}

const dueAt = (start: string, mailed: string | null) =>
  Math.max(
    Date.parse(start) + MAIL_AFTER_MS,
    mailed ? Date.parse(mailed) + MAIL_EVERY_MS : 0,
  );

export class FleetHub implements DurableObject {
  private readonly ctx: DurableObjectState;
  private readonly env: Env;
  private readonly network: HubNetwork;
  private readonly inventories = new Map<string, string>();
  private mailOff = false;
  private lostChecked = false;
  private passing: number | null = null;
  private wroteDuring = Infinity;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
    this.network = new HubNetwork(env.DB, ctx.storage, {
      send: (nodeId, message) => this.sendTo(nodeId, message),
      online: () => this.online(),
      announce: (topics) => this.announce(topics),
    });
    ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong"),
    );
  }

  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    const post = request.method === "POST";
    if (pathname === "/connect") {
      const nodeId = request.headers.get("x-kry-node");
      if (!nodeId) return new Response(null, { status: 400 });
      const [client, server] = Object.values(new WebSocketPair());
      await this.join(server!, nodeId, request.headers.get("x-kry-version"));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (pathname === "/watch") {
      const [client, server] = Object.values(new WebSocketPair());
      this.watch(server!);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (pathname === "/online") return Response.json(this.online());
    if (pathname === "/via") return Response.json(await this.network.via());
    if (pathname === "/command" && post) return this.command(request);
    if (pathname === "/drop" && post) return this.drop(request);
    if (pathname === "/document" && post) return this.document(request);
    if (pathname === "/checks" && post) {
      const body = (await request.json().catch(() => null)) as {
        nodeId?: unknown;
      } | null;
      if (typeof body?.nodeId !== "string") {
        return new Response(null, { status: 400 });
      }
      if (this.online().includes(body.nodeId)) {
        this.sendTo(body.nodeId, await this.checksFor(body.nodeId));
      }
      this.announce(["checks"]);
      return new Response(null, { status: 204 });
    }
    if (pathname === "/refresh" && post) {
      await this.network.refresh();
      return new Response(null, { status: 204 });
    }
    if (pathname === "/announce" && post) {
      const body = (await request.json().catch(() => null)) as {
        topics?: unknown;
      } | null;
      const topics = Array.isArray(body?.topics)
        ? body.topics.filter((topic) => typeof topic === "string")
        : [];
      if (topics.length > 0) this.announce(topics);
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 404 });
  }

  async join(
    ws: WebSocket,
    nodeId: string,
    version: string | null,
  ): Promise<void> {
    if (!version || !agentSupported(version)) {
      this.ctx.acceptWebSocket(ws);
      ws.close(
        4426,
        `Agents before ${MIN_AGENT} are no longer supported. Update the agent.`,
      );
      return;
    }
    for (const old of this.agents(nodeId)) {
      try {
        old.ws.close(4000, "replaced");
      } catch {
        continue;
      }
    }
    this.ctx.acceptWebSocket(ws, [AGENT, nodeId]);
    const now = Date.now();
    ws.serializeAttachment({
      nodeId,
      version,
      since: now,
      heard: now,
    } satisfies Attachment);
    this.announce(["fleet"]);
    const recorded = (await this.ctx.storage.get<string[]>(AGENTS)) ?? [];
    if (!recorded.includes(nodeId)) {
      await this.ctx.storage.put(AGENTS, [...recorded, nodeId]);
    }
    await this.arm(now + SWEEP_EVERY_MS);
  }

  watch(ws: WebSocket): void {
    this.ctx.acceptWebSocket(ws, [WATCH]);
  }

  async webSocketMessage(
    ws: WebSocket,
    raw: string | ArrayBuffer,
  ): Promise<void> {
    const agent = ws.deserializeAttachment() as Attachment | null;
    if (!agent) return;
    ws.serializeAttachment({
      ...agent,
      heard: Date.now(),
    } satisfies Attachment);
    const message = typeof raw === "string" ? parseAgentMessage(raw) : null;
    if (!message) {
      ws.send(JSON.stringify({ type: "error", code: "INVALID_MESSAGE" }));
      return;
    }
    const { nodeId } = agent;
    switch (message.type) {
      case "hello":
        return this.hello(ws, nodeId, message);
      case "result":
        return this.result(ws, nodeId, message);
      case "progress":
        return this.toWatchers({
          type: "progress",
          id: message.id,
          line: message.line,
        });
      case "applied":
        return this.network.applied(nodeId, message);
      case "links":
        return this.network.links(nodeId, message.links);
      case "announce":
        return this.network.announce(nodeId, message.key, message.signature);
      case "meet":
        return this.network.meet(nodeId, message.via);
      case "inventory":
        return this.inventory(nodeId, message);
      case "check":
        return this.check(nodeId, message);
      default: {
        const never: never = message;
        return never;
      }
    }
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    const agent = ws.deserializeAttachment() as Attachment | null;
    if (!agent) return;
    if (this.agents(agent.nodeId).length === 0) {
      const recorded = (await this.ctx.storage.get<string[]>(AGENTS)) ?? [];
      if (recorded.includes(agent.nodeId)) {
        await this.ctx.storage.put(
          AGENTS,
          recorded.filter((id) => id !== agent.nodeId),
        );
      }
    }
    await this.left(agent.nodeId);
  }

  private async left(nodeId: string): Promise<void> {
    const node = await this.env.DB.prepare(
      "UPDATE nodes SET last_seen_at = ? WHERE id = ? RETURNING kind, EXISTS (SELECT 1 FROM checks WHERE node_id = nodes.id AND state != 'unknown') AS watched",
    )
      .bind(new Date().toISOString(), nodeId)
      .first<{ kind: string; watched: number }>();
    this.announce(["fleet"]);
    await this.network.gone(nodeId);
    if (node?.kind === "server" && !this.online().includes(nodeId)) {
      await this.due(Date.now() + MAIL_AFTER_MS, node.watched === 1);
    }
  }

  private async lost(): Promise<void> {
    const recorded = (await this.ctx.storage.get<string[]>(AGENTS)) ?? [];
    const open = new Set(this.agents().map(({ agent }) => agent.nodeId));
    const gone = recorded.filter((id) => !open.has(id));
    if (gone.length === 0) return;
    await this.ctx.storage.put(
      AGENTS,
      recorded.filter((id) => open.has(id)),
    );
    for (const nodeId of gone) await this.left(nodeId);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.webSocketClose(ws);
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    const cutoff = now - SILENT_AFTER_MS;
    const silent = this.agents()
      .filter(({ ws, agent }) => this.heardAt(ws, agent) < cutoff)
      .map(({ ws }) => ws);
    for (const ws of silent) {
      try {
        ws.close(SILENT_CODE, "silent");
      } catch {
        continue;
      }
    }
    if (this.agents().length > 0) await this.arm(now + SWEEP_EVERY_MS);
    const storage = this.ctx.storage;
    const due = await storage.get<number>(DUE);
    this.passing = due !== undefined && due <= now ? due : null;
    this.wroteDuring = Infinity;
    try {
      for (const ws of silent) await this.webSocketClose(ws);
      if (!this.lostChecked) {
        this.lostChecked = true;
        await this.lost();
      }
      if (due === undefined) return;
      if (due > now) {
        await this.arm(due);
        return;
      }
      let next: number | null;
      try {
        next = await this.pass(now);
      } catch (error) {
        const stored = (await storage.get<number>(DUE)) ?? Infinity;
        await storage.put(DUE, Math.min(stored, due));
        await this.arm(now + SWEEP_EVERY_MS);
        throw error;
      }
      const merged = Math.min(next ?? Infinity, this.wroteDuring);
      if (!Number.isFinite(merged)) {
        await storage.delete(DUE);
        return;
      }
      await storage.put(DUE, merged);
      await this.arm(Math.max(merged, now));
    } finally {
      this.passing = null;
    }
  }

  private mailOn(): boolean {
    if (mailReady(this.env)) return true;
    if (!this.mailOff) {
      this.mailOff = true;
      console.log(
        "[kry email] not configured: the Worker needs the EMAIL binding, ALERT_EMAIL and FROM_EMAIL to send mail.",
      );
    }
    return false;
  }

  private async arm(at: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || at < current) await this.ctx.storage.setAlarm(at);
  }

  private async due(at: number, always = false): Promise<void> {
    if (!always && !this.mailOn()) return;
    const due = await this.ctx.storage.get<number>(DUE);
    if (this.passing !== null) {
      this.wroteDuring = Math.min(this.wroteDuring, at);
    }
    if (due === undefined || due === this.passing || at < due) {
      await this.ctx.storage.put(DUE, at);
    }
    await this.arm(at);
  }

  private async pass(now: number): Promise<number | null> {
    const marked = await this.offline(now);
    const mailed = await this.mail(now);
    const next = Math.min(marked ?? Infinity, mailed ?? Infinity);
    return Number.isFinite(next) ? next : null;
  }

  private async offline(now: number): Promise<number | null> {
    const outcome = await this.ctx.blockConcurrencyWhile(() =>
      this.markOffline(now).then(
        (next) => ({ next }),
        (error: unknown) => ({ error }),
      ),
    );
    if ("error" in outcome) throw outcome.error;
    return outcome.next;
  }

  private async markOffline(now: number): Promise<number | null> {
    const db = this.env.DB;
    const { results } = await db
      .prepare(
        "SELECT n.id, n.last_seen_at FROM nodes n WHERE n.kind = 'server' AND n.last_seen_at IS NOT NULL AND EXISTS (SELECT 1 FROM checks c WHERE c.node_id = n.id AND c.state != 'unknown')",
      )
      .all<{ id: string; last_seen_at: string }>();
    const online = new Set(this.online());
    const keep = new Date(now - KEEP_TRANSITIONS_MS).toISOString();
    const writes: D1PreparedStatement[] = [];
    let next = Infinity;
    for (const row of results) {
      if (online.has(row.id)) continue;
      const at = Date.parse(row.last_seen_at) + MAIL_AFTER_MS;
      if (at > now) {
        next = Math.min(next, at);
        continue;
      }
      writes.push(
        db
          .prepare(
            "INSERT INTO check_transitions (check_id, state, cause, at) SELECT id, 'unknown', 'offline', ?1 FROM checks WHERE node_id = ?2 AND state != 'unknown'",
          )
          .bind(row.last_seen_at, row.id),
        db
          .prepare(
            "UPDATE checks SET state = 'unknown', cause = 'offline', since = ?1 WHERE node_id = ?2 AND state != 'unknown'",
          )
          .bind(row.last_seen_at, row.id),
        db
          .prepare(
            "DELETE FROM check_transitions WHERE check_id IN (SELECT id FROM checks WHERE node_id = ?1) AND at < ?2 AND id != (SELECT p.id FROM check_transitions p WHERE p.check_id = check_transitions.check_id AND p.at < ?2 ORDER BY p.at DESC, p.id DESC LIMIT 1)",
          )
          .bind(row.id, keep),
      );
    }
    if (writes.length > 0) {
      await db.batch(writes);
      this.announce(["checks"]);
    }
    return Number.isFinite(next) ? next : null;
  }

  private async mail(now: number): Promise<number | null> {
    if (!this.mailOn()) return null;
    const db = this.env.DB;
    const [checks, nodes] = await Promise.all([
      db
        .prepare(
          "SELECT c.id, c.node_id, n.name AS node_name, c.container, c.name, c.since, c.mailed_at FROM checks c JOIN nodes n ON n.id = c.node_id WHERE c.state = 'down' AND c.cause IS NULL AND c.since IS NOT NULL AND (c.mailed_at IS NULL OR c.mailed_at < c.since)",
        )
        .all<DueCheck>(),
      db
        .prepare(
          "SELECT id, name, last_seen_at, offline_mailed_at FROM nodes WHERE kind = 'server' AND last_seen_at IS NOT NULL AND (offline_mailed_at IS NULL OR offline_mailed_at < last_seen_at)",
        )
        .all<DueNode>(),
    ]);
    const online = new Set(this.online());
    const stamp = new Date(now).toISOString();
    const down = new Map<
      string,
      { nodeName: string; checks: DownCheck[]; ids: string[] }
    >();
    let next = Infinity;
    for (const row of checks.results) {
      const at = dueAt(row.since, row.mailed_at);
      if (at > now) {
        next = Math.min(next, at);
        continue;
      }
      const server = down.get(row.node_id) ?? {
        nodeName: row.node_name,
        checks: [],
        ids: [],
      };
      server.checks.push({
        name: row.name,
        container: row.container,
        since: row.since,
      });
      server.ids.push(row.id);
      down.set(row.node_id, server);
    }
    const offline: DueNode[] = [];
    for (const row of nodes.results) {
      if (online.has(row.id)) continue;
      const at = dueAt(row.last_seen_at, row.offline_mailed_at);
      if (at > now) {
        next = Math.min(next, at);
        continue;
      }
      offline.push(row);
    }
    const sends = [
      ...offline.map((row) => async () => {
        await sendOfflineEmail(this.env, {
          nodeName: row.name,
          lastSeen: row.last_seen_at,
        });
        await db
          .prepare("UPDATE nodes SET offline_mailed_at = ?1 WHERE id = ?2")
          .bind(stamp, row.id)
          .run();
      }),
      ...[...down.values()].map(({ ids, ...server }) => async () => {
        await sendCheckDownEmail(this.env, server);
        await db.batch(
          ids.map((id) =>
            db
              .prepare("UPDATE checks SET mailed_at = ?1 WHERE id = ?2")
              .bind(stamp, id),
          ),
        );
      }),
    ];
    for (const send of sends) {
      try {
        await send();
      } catch (error) {
        console.error("[kry mail]", error);
        next = Math.min(next, now + MAIL_RETRY_MS);
      }
    }
    return Number.isFinite(next) ? next : null;
  }

  private heardAt(ws: WebSocket, agent: Attachment): number {
    const pinged = this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime();
    return Math.max(agent.heard, pinged ?? 0);
  }

  private agents(tag = AGENT) {
    return this.ctx.getWebSockets(tag).flatMap((ws) => {
      const agent = ws.deserializeAttachment() as Attachment | null;
      return agent && ws.readyState === WebSocket.OPEN ? [{ ws, agent }] : [];
    });
  }

  private heard(tag = AGENT) {
    const cutoff = Date.now() - SILENT_AFTER_MS;
    return this.agents(tag).filter(
      ({ ws, agent }) => this.heardAt(ws, agent) >= cutoff,
    );
  }

  private online(): string[] {
    return [...new Set(this.heard().map(({ agent }) => agent.nodeId))];
  }

  private sendTo(nodeId: string, message: HubMessage): void {
    const text = JSON.stringify(message);
    for (const { ws } of this.heard(nodeId)) {
      try {
        ws.send(text);
        return;
      } catch {
        continue;
      }
    }
  }

  private async command(request: Request): Promise<Response> {
    const body = (await request.json().catch(() => null)) as {
      nodeId?: unknown;
      command?: unknown;
    } | null;
    const parsed = hubMessageSchema.safeParse(body?.command);
    if (
      typeof body?.nodeId !== "string" ||
      !parsed.success ||
      parsed.data.type !== "command"
    ) {
      return Response.json({ code: "INVALID_COMMAND" }, { status: 400 });
    }
    for (const { ws } of this.heard(body.nodeId)) {
      try {
        ws.send(JSON.stringify(parsed.data));
        return Response.json({ sent: true });
      } catch {
        continue;
      }
    }
    return Response.json({ code: "OFFLINE" }, { status: 409 });
  }

  private async drop(request: Request): Promise<Response> {
    const body = (await request.json().catch(() => null)) as {
      nodeId?: unknown;
    } | null;
    if (typeof body?.nodeId !== "string") {
      return new Response(null, { status: 400 });
    }
    for (const { ws } of this.agents(body.nodeId)) {
      try {
        ws.close(4001, "removed");
      } catch {
        continue;
      }
    }
    return new Response(null, { status: 204 });
  }

  private async document(request: Request): Promise<Response> {
    const body = (await request.json().catch(() => null)) as {
      version?: unknown;
    } | null;
    const version = body?.version;
    if (typeof version !== "number" || !Number.isInteger(version)) {
      return new Response(null, { status: 400 });
    }
    const stored = await this.env.DB.prepare(
      "SELECT 1 FROM network_documents WHERE version = ?",
    )
      .bind(version)
      .first();
    if (!stored) return new Response(null, { status: 404 });
    await this.network.push(version);
    return new Response(null, { status: 204 });
  }

  private async hello(ws: WebSocket, nodeId: string, hello: Hello) {
    const db = this.env.DB;
    const stored = await db
      .prepare(
        "SELECT hostname, os, arch, kernel, version, seal_key, last_seen_at FROM nodes WHERE id = ?",
      )
      .bind(nodeId)
      .first<Facts>();
    if (!stored) {
      ws.close(4401, "Unknown server");
      return;
    }
    if (hello.kind === "server") {
      ws.send(JSON.stringify(await this.checksFor(nodeId)));
    }
    const now = new Date();
    const facts = {
      hostname: hello.hostname,
      os: hello.os,
      arch: hello.arch,
      kernel: hello.kernel,
      version: hello.version,
      seal_key: hello.sealKey,
    };
    const changed = Object.entries(facts).some(
      ([key, value]) => stored[key as keyof Facts] !== value,
    );
    const due =
      !stored.last_seen_at ||
      now.getTime() - Date.parse(stored.last_seen_at) >= SEEN_EVERY_MS;
    if (changed || due) {
      await db
        .prepare(
          "UPDATE nodes SET hostname = ?, os = ?, arch = ?, kernel = ?, version = ?, seal_key = ?, last_seen_at = ? WHERE id = ?",
        )
        .bind(
          ...Object.values(facts),
          due ? now.toISOString() : stored.last_seen_at,
          nodeId,
        )
        .run();
    }
    const trusted = hello.trust
      ? await this.storeTrust(nodeId, hello.trust)
      : false;
    if (changed || trusted) this.announce(["fleet"]);
    if (hello.network) await this.network.hello(nodeId, hello.network);
  }

  private async checksFor(nodeId: string): Promise<HubMessage> {
    const { results } = await this.env.DB.prepare(
      "SELECT container FROM checks WHERE node_id = ? ORDER BY container",
    )
      .bind(nodeId)
      .all<{ container: string }>();
    return { type: "checks", names: results.map((row) => row.container) };
  }

  private async stackChecks(nodeId: string, stack: string) {
    const db = this.env.DB;
    const [checks, stored] = await Promise.all([
      db
        .prepare("SELECT container FROM checks WHERE node_id = ?")
        .bind(nodeId)
        .all<{ container: string }>(),
      db
        .prepare("SELECT body FROM node_inventory WHERE node_id = ?")
        .bind(nodeId)
        .first<{ body: string }>(),
    ]);
    const listed = (stored ? JSON.parse(stored.body) : {}) as {
      stacks?: { project: string }[];
      removed?: { project: string; names?: string[] }[];
      containers?: { name: string; project: string | null }[];
    };
    const labelled = new Map(
      (listed.containers ?? []).map((one) => [one.name, one.project]),
    );
    const named = new Set(
      (listed.removed ?? []).find((one) => one.project === stack)?.names ?? [],
    );
    const longer = [...(listed.stacks ?? []), ...(listed.removed ?? [])]
      .map((one) => one.project)
      .filter((one) => one.startsWith(`${stack}-`));
    return checks.results
      .map((row) => row.container)
      .filter(
        (container) =>
          (labelled.has(container)
            ? labelled.get(container) === stack
            : container.startsWith(`${stack}-`) || named.has(container)) &&
          !longer.some((one) => container.startsWith(`${one}-`)),
      );
  }

  private async check(nodeId: string, check: Check) {
    const db = this.env.DB;
    const stored = await db
      .prepare(
        "SELECT id, state, cause, mailed_at FROM checks WHERE node_id = ? AND container = ?",
      )
      .bind(nodeId, check.name)
      .first<{
        id: string;
        state: string;
        cause: string | null;
        mailed_at: string | null;
      }>();
    if (!stored || stored.state === check.state) return;
    let cause: string | null = check.cause;
    if (
      cause === null &&
      stored.state === "unknown" &&
      stored.cause === "offline"
    ) {
      const before = await db
        .prepare(
          "SELECT state, cause FROM check_transitions WHERE check_id = ? AND cause IS NOT 'offline' ORDER BY at DESC, id DESC LIMIT 1",
        )
        .bind(stored.id)
        .first<{ state: string; cause: string | null }>();
      if (before?.state === check.state) cause = before.cause;
    }
    const now = Date.now();
    const at = new Date(
      stored.cause === "offline"
        ? now
        : Math.min(Math.max(Date.parse(check.at), now - SLACK_MS), now),
    ).toISOString();
    await db.batch([
      db
        .prepare(
          "UPDATE checks SET state = ?1, cause = ?2, since = ?3 WHERE id = ?4",
        )
        .bind(check.state, cause, at, stored.id),
      db
        .prepare(
          "INSERT INTO check_transitions (check_id, state, cause, at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(stored.id, check.state, cause, at),
      db
        .prepare(
          "DELETE FROM check_transitions WHERE check_id = ?1 AND at < ?2 AND id != (SELECT p.id FROM check_transitions p WHERE p.check_id = ?1 AND p.at < ?2 ORDER BY p.at DESC, p.id DESC LIMIT 1)",
        )
        .bind(stored.id, new Date(now - KEEP_TRANSITIONS_MS).toISOString()),
    ]);
    this.announce(["checks"]);
    if (check.state === "down" && cause === null) {
      await this.due(dueAt(at, stored.mailed_at));
    }
  }

  private async result(ws: WebSocket, nodeId: string, result: Result) {
    const known = await this.env.DB.prepare("SELECT 1 FROM nodes WHERE id = ?")
      .bind(nodeId)
      .first();
    if (!known) {
      ws.close(4401, "Unknown server");
      return;
    }
    const db = this.env.DB;
    const pending = await db
      .prepare(
        "SELECT kind, action, name FROM actions WHERE id = ? AND node_id = ? AND status IN ('sent', 'running')",
      )
      .bind(result.id, nodeId)
      .first<{ kind: string; action: string; name: string }>();
    const dropped =
      result.ok && pending?.kind === "stack" && pending.action === "purge"
        ? await this.stackChecks(nodeId, pending.name)
        : [];
    const write = db
      .prepare(
        "UPDATE actions SET status = ?, message = ?, output = ?, finished_at = ? WHERE id = ? AND node_id = ? AND status IN ('sent', 'running')",
      )
      .bind(
        result.ok ? "done" : "failed",
        result.message,
        result.output ?? null,
        new Date().toISOString(),
        result.id,
        nodeId,
      );
    const written =
      dropped.length > 0
        ? (
            await db.batch([
              db
                .prepare(
                  "DELETE FROM checks WHERE node_id = ?1 AND container IN (SELECT value FROM json_each(?2)) AND EXISTS (SELECT 1 FROM actions WHERE id = ?3 AND node_id = ?1 AND status IN ('sent', 'running'))",
                )
                .bind(nodeId, JSON.stringify(dropped), result.id),
              write,
            ])
          )[1]!
        : await write.run();
    const finished = written.meta.changes > 0 ? pending : null;
    if (finished && result.output !== undefined) {
      await clearOldOutput(db);
    }
    if (finished && dropped.length > 0) {
      this.sendTo(nodeId, await this.checksFor(nodeId));
      this.announce(["checks"]);
    }
    if (finished?.kind === "network" && result.ok) {
      await this.network.result(nodeId, finished.action, result.message);
    }
    const trusted = result.trust
      ? await this.storeTrust(nodeId, result.trust)
      : false;
    ws.send(JSON.stringify({ type: "ack", id: result.id }));
    if (finished || trusted) this.announce(["fleet"]);
  }

  private async inventory(nodeId: string, inventory: Inventory) {
    if (this.inventories.get(nodeId) === inventory.hash) return;
    const { type: _type, hash, ...body } = inventory;
    const text = JSON.stringify(body);
    if (new TextEncoder().encode(text).length > MAX_INVENTORY_BYTES) {
      this.inventories.set(nodeId, hash);
      console.warn(`[kry] skipped an inventory over 1 MiB from ${nodeId}`);
      return;
    }
    const written = await this.env.DB.prepare(
      "INSERT INTO node_inventory (node_id, hash, body, updated_at) SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM nodes WHERE id = ?1) ON CONFLICT (node_id) DO UPDATE SET hash = excluded.hash, body = excluded.body, updated_at = excluded.updated_at WHERE node_inventory.hash <> excluded.hash",
    )
      .bind(nodeId, hash, text, new Date().toISOString())
      .run();
    this.inventories.set(nodeId, hash);
    if (written.meta.changes > 0) this.announce(["stacks"]);
  }

  private async storeTrust(nodeId: string, trust: TrustReport) {
    const db = this.env.DB;
    const core = JSON.stringify(trust.core);
    const access = JSON.stringify(trust.access);
    const stored = await db
      .prepare("SELECT version, core, access FROM node_trust WHERE node_id = ?")
      .bind(nodeId)
      .first<{ version: number; core: string; access: string }>();
    if (
      stored?.version === trust.version &&
      stored.core === core &&
      stored.access === access
    ) {
      return false;
    }
    await db
      .prepare(
        "INSERT INTO node_trust (node_id, version, core, access, reported_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (node_id) DO UPDATE SET version = excluded.version, core = excluded.core, access = excluded.access, reported_at = excluded.reported_at",
      )
      .bind(nodeId, trust.version, core, access, new Date().toISOString())
      .run();
    return true;
  }

  private announce(topics: string[]): void {
    this.toWatchers({ type: "changed", topics });
  }

  private toWatchers(message: object): void {
    const text = JSON.stringify(message);
    for (const ws of this.ctx.getWebSockets(WATCH)) {
      try {
        ws.send(text);
      } catch {
        continue;
      }
    }
  }
}
