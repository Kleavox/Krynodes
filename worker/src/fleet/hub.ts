import {
  agentSupported,
  hubMessageSchema,
  MIN_AGENT,
  parseAgentMessage,
  type AgentMessage,
  type TrustReport,
} from "@krynodes/protocol";

import type { Env } from "../env";

const AGENT = "agent";
const WATCH = "watch";
const SEEN_EVERY_MS = 10 * 60_000;
const PING_EVERY_MS = 25_000;
const SILENT_AFTER_MS = 3 * PING_EVERY_MS;
const SWEEP_EVERY_MS = 60_000;
const SILENT_CODE = 4408;

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

export class FleetHub implements DurableObject {
  private readonly ctx: DurableObjectState;
  private readonly env: Env;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
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
    if (pathname === "/command" && post) return this.command(request);
    if (pathname === "/drop" && post) return this.drop(request);
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
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(now + SWEEP_EVERY_MS);
    }
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
    if (message.type === "hello") await this.hello(ws, agent.nodeId, message);
    else if (message.type === "result") {
      await this.result(ws, agent.nodeId, message);
    } else {
      this.toWatchers({ type: "progress", id: message.id, line: message.line });
    }
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    const agent = ws.deserializeAttachment() as Attachment | null;
    if (!agent) return;
    await this.env.DB.prepare("UPDATE nodes SET last_seen_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), agent.nodeId)
      .run();
    this.announce(["fleet"]);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.webSocketClose(ws);
  }

  async alarm(): Promise<void> {
    const cutoff = Date.now() - SILENT_AFTER_MS;
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
    if (this.agents().length > 0) {
      await this.ctx.storage.setAlarm(Date.now() + SWEEP_EVERY_MS);
    }
    await Promise.all(silent.map((ws) => this.webSocketClose(ws)));
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
  }

  private async result(ws: WebSocket, nodeId: string, result: Result) {
    const known = await this.env.DB.prepare("SELECT 1 FROM nodes WHERE id = ?")
      .bind(nodeId)
      .first();
    if (!known) {
      ws.close(4401, "Unknown server");
      return;
    }
    const finished = await this.env.DB.prepare(
      "UPDATE actions SET status = ?, message = ?, finished_at = ? WHERE id = ? AND node_id = ? AND status IN ('sent', 'running')",
    )
      .bind(
        result.ok ? "done" : "failed",
        result.message,
        new Date().toISOString(),
        result.id,
        nodeId,
      )
      .run();
    const trusted = result.trust
      ? await this.storeTrust(nodeId, result.trust)
      : false;
    ws.send(JSON.stringify({ type: "ack", id: result.id }));
    if (finished.meta.changes > 0 || trusted) this.announce(["fleet"]);
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
