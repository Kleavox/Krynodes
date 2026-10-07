import type { AgentHeartbeat, CheckResult } from "@krynodes/protocol";

import type { Env } from "../env";
import type { IncidentNotice } from "../incident/notify";
import type { CheckKind } from "../lib/checks";
import { sha256 } from "../lib/crypto";
import { agentSupported, compareVersions } from "@krynodes/protocol";
import {
  mergeChecks,
  parseChecks,
  windowStart,
  type WindowChecks,
} from "./windows";

export const CHECK_LIMIT = 10;
const INCIDENT_THRESHOLD = 2;

export interface AgentNode {
  id: string;
  interval_seconds: number;
  owner_user_id?: string;
  update_requested_version?: string | null;
  update_requested_at?: string | null;
  update_attempts?: number;
  update_error?: string | null;
  inventory_hash?: string | null;
  refresh_requested_at?: string | null;
  security?: string | null;
}

export interface LiveCheck {
  id: string;
  name: string;
  kind: CheckKind;
  target: string;
  timeout_seconds: number;
  status: "UNKNOWN" | "UP" | "DOWN";
  consecutive_failures: number;
}

interface Transition {
  kind: "opened" | "resolved";
  checkId: string;
  checkName: string;
  summary: string;
  occurredAt: string;
  statement: D1PreparedStatement;
}

export interface Ingestion {
  statements: D1PreparedStatement[];
  transitions: Transition[];
}

function sqliteTime(epochMs: number): string {
  return new Date(epochMs).toISOString().replace("T", " ").slice(0, 19);
}

export async function loadAgentConfig(db: D1Database, node: AgentNode) {
  const rows = await db
    .prepare(
      `SELECT id, name, kind, target, timeout_seconds, status, consecutive_failures
       FROM checks WHERE node_id = ? AND enabled = 1
       ORDER BY created_at, id`,
    )
    .bind(node.id)
    .all<LiveCheck>();
  const config = {
    nodeId: node.id,
    intervalSeconds: node.interval_seconds,
    checks: rows.results.map((check) => ({
      id: check.id,
      name: check.name,
      kind: check.kind,
      target: check.target,
      timeoutSeconds: check.timeout_seconds,
    })),
  };
  const configVersion = (await sha256(JSON.stringify(config))).slice(0, 16);
  return { checks: rows.results, config, configVersion };
}

function updateDone(
  node: Pick<AgentNode, "update_requested_version">,
  version: string,
): boolean {
  const requested = node.update_requested_version;
  return Boolean(requested) && compareVersions(version, requested!) >= 0;
}

const UPDATE_RETRY_MS = 15 * 60_000;
const UPDATE_ATTEMPTS = 3;

export function updateRetry(
  db: D1Database,
  node: AgentNode,
  heartbeat: Pick<AgentHeartbeat, "agentVersion" | "update">,
  now: number,
): { node: AgentNode; statements: D1PreparedStatement[] } {
  const requested = node.update_requested_version;
  if (!requested || updateDone(node, heartbeat.agentVersion)) {
    return { node, statements: [] };
  }
  const attempts = node.update_attempts || 1;
  const reported =
    heartbeat.update?.version === requested ? heartbeat.update.message : null;
  const error = reported ?? node.update_error ?? null;
  const since = Date.parse(node.update_requested_at ?? "");
  const retry =
    attempts < UPDATE_ATTEMPTS &&
    (Number.isNaN(since) || now - since >= UPDATE_RETRY_MS);
  if (!retry && error === (node.update_error ?? null)) {
    return { node, statements: [] };
  }
  const next: AgentNode = {
    ...node,
    update_requested_at: retry
      ? new Date(now).toISOString()
      : (node.update_requested_at ?? null),
    update_attempts: retry ? attempts + 1 : attempts,
    update_error: error,
  };
  return {
    node: next,
    statements: [
      db
        .prepare(
          `UPDATE nodes SET update_requested_at = ?, update_attempts = ?, update_error = ?
           WHERE id = ? AND update_requested_version = ?`,
        )
        .bind(
          next.update_requested_at,
          next.update_attempts,
          next.update_error,
          node.id,
          requested,
        ),
    ],
  };
}

export function forcedUpdate(
  db: D1Database,
  node: AgentNode,
  agentVersion: string,
  release: string | null,
  now: number,
): { node: AgentNode; statements: D1PreparedStatement[] } {
  if (
    agentSupported(agentVersion) ||
    node.update_requested_version ||
    !release ||
    compareVersions(agentVersion, release) >= 0
  ) {
    return { node, statements: [] };
  }
  const requestedAt = new Date(now).toISOString();
  return {
    node: {
      ...node,
      update_requested_version: release,
      update_requested_at: requestedAt,
      update_attempts: 1,
      update_error: null,
    },
    statements: [
      db
        .prepare(
          `UPDATE nodes SET update_requested_version = ?, update_requested_at = ?,
             update_attempts = 1, update_error = NULL
           WHERE id = ? AND update_requested_version IS NULL`,
        )
        .bind(release, requestedAt, node.id),
    ],
  };
}

export function heartbeatResponse(
  node: AgentNode,
  configVersion: string,
  agentVersion: string,
  actions: unknown[],
) {
  const requested = node.update_requested_version;
  return {
    ok: true,
    intervalSeconds: node.interval_seconds,
    configVersion,
    ...(requested && !updateDone(node, agentVersion)
      ? {
          update: {
            version: requested,
            requestedAt: node.update_requested_at,
          },
        }
      : {}),
    ...(actions.length > 0 ? { actions } : {}),
    ...(node.refresh_requested_at ? { refresh: true } : {}),
  };
}

export function heartbeatStatements(
  db: D1Database,
  node: AgentNode,
  heartbeat: Omit<AgentHeartbeat, "results">,
  now: number,
): D1PreparedStatement[] {
  const metrics = heartbeat.metrics;
  const at = sqliteTime(now);
  const updated = updateDone(node, heartbeat.agentVersion);
  return [
    db
      .prepare(
        `UPDATE nodes
         SET hostname = ?, architecture = ?, operating_system = ?,
             agent_version = ?, last_seen_at = ?,
             cpu_percent = ?, memory_used_bytes = ?, memory_total_bytes = ?,
             disk_used_bytes = ?, disk_total_bytes = ?, load_1 = ?,
             uptime_seconds = ?, updated_at = ?,
             update_requested_at = CASE WHEN ?
               THEN NULL ELSE update_requested_at END,
             update_requested_version = CASE WHEN ?
               THEN NULL ELSE update_requested_version END,
             update_attempts = CASE WHEN ? THEN 0 ELSE update_attempts END,
             update_error = CASE WHEN ? THEN NULL ELSE update_error END
         WHERE id = ?`,
      )
      .bind(
        heartbeat.hostname,
        heartbeat.architecture,
        heartbeat.operatingSystem,
        heartbeat.agentVersion,
        at,
        metrics.cpuPercent,
        metrics.memoryUsedBytes,
        metrics.memoryTotalBytes,
        metrics.diskUsedBytes,
        metrics.diskTotalBytes,
        metrics.load1,
        metrics.uptimeSeconds,
        at,
        updated ? 1 : 0,
        updated ? 1 : 0,
        updated ? 1 : 0,
        updated ? 1 : 0,
        node.id,
      ),
  ];
}

function worstPerCheck(results: CheckResult[]): CheckResult[] {
  const byCheck = new Map<string, CheckResult>();
  for (const result of results) {
    const current = byCheck.get(result.checkId);
    if (!current || (current.status === "UP" && result.status === "DOWN")) {
      byCheck.set(result.checkId, result);
    }
  }
  return [...byCheck.values()];
}

export function acceptResults(
  checks: Pick<LiveCheck, "id">[],
  results: CheckResult[],
): CheckResult[] {
  const known = new Set(checks.map((check) => check.id));
  return worstPerCheck(results.filter((result) => known.has(result.checkId)));
}

export function insertWindow(
  db: D1Database,
  nodeId: string,
  start: string,
  samples: number,
  metrics: AgentHeartbeat["metrics"],
  checks: WindowChecks,
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO node_windows (
         node_id, window_start, samples, cpu_percent, memory_used_bytes,
         memory_total_bytes, disk_used_bytes, disk_total_bytes, load_1,
         load_5, load_15, uptime_seconds, checks
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (node_id, window_start) DO UPDATE SET
         samples = excluded.samples, cpu_percent = excluded.cpu_percent,
         memory_used_bytes = excluded.memory_used_bytes,
         memory_total_bytes = excluded.memory_total_bytes,
         disk_used_bytes = excluded.disk_used_bytes,
         disk_total_bytes = excluded.disk_total_bytes,
         load_1 = excluded.load_1, load_5 = excluded.load_5,
         load_15 = excluded.load_15, uptime_seconds = excluded.uptime_seconds,
         checks = excluded.checks`,
    )
    .bind(
      nodeId,
      start,
      samples,
      metrics.cpuPercent,
      metrics.memoryUsedBytes,
      metrics.memoryTotalBytes,
      metrics.diskUsedBytes,
      metrics.diskTotalBytes,
      metrics.load1,
      metrics.load5,
      metrics.load15,
      metrics.uptimeSeconds,
      JSON.stringify(checks),
    );
}

export function resultStatements(
  db: D1Database,
  checks: LiveCheck[],
  accepted: CheckResult[],
  now: number,
  maintenance = false,
): Ingestion {
  const byId = new Map(checks.map((check) => [check.id, check]));
  if (accepted.length === 0) return { statements: [], transitions: [] };

  const receivedAt = new Date(now).toISOString();
  const statements: D1PreparedStatement[] = [];
  const transitions: Transition[] = [];
  for (const result of accepted) {
    const check = byId.get(result.checkId);
    if (!check) continue;

    const failures =
      result.status === "DOWN"
        ? Math.min(
            check.consecutive_failures + 1,
            maintenance ? INCIDENT_THRESHOLD - 1 : INCIDENT_THRESHOLD,
          )
        : 0;
    if (
      result.status === check.status &&
      failures === check.consecutive_failures
    ) {
      continue;
    }
    statements.push(
      db
        .prepare(
          `UPDATE checks
           SET status = ?, latency_ms = ?, last_checked_at = ?,
               consecutive_failures = ?, last_message = ?, updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          result.status,
          result.latencyMs,
          receivedAt,
          failures,
          result.message,
          sqliteTime(now),
          check.id,
        ),
    );

    if (result.status === "DOWN" && failures >= INCIDENT_THRESHOLD) {
      const summary = `${check.name} is down${result.message ? `: ${result.message}` : ""}`;
      transitions.push({
        kind: "opened",
        checkId: check.id,
        checkName: check.name,
        summary,
        occurredAt: receivedAt,
        statement: db
          .prepare(
            `INSERT OR IGNORE INTO incidents (id, check_id, status, started_at, summary)
             VALUES (?, ?, 'OPEN', ?, ?)`,
          )
          .bind(crypto.randomUUID(), check.id, receivedAt, summary),
      });
    }
    if (result.status === "UP" && check.status === "DOWN") {
      transitions.push({
        kind: "resolved",
        checkId: check.id,
        checkName: check.name,
        summary: `${check.name} is responding again.`,
        occurredAt: receivedAt,
        statement: db
          .prepare(
            `UPDATE incidents SET status = 'RESOLVED', resolved_at = ?
             WHERE check_id = ? AND status = 'OPEN'`,
          )
          .bind(receivedAt, check.id),
      });
    }
  }
  return { statements, transitions };
}

export async function commit(
  env: Env,
  nodeId: string,
  leading: D1PreparedStatement[],
  ingestion: Ingestion,
): Promise<IncidentNotice[]> {
  const statements = [
    ...leading,
    ...ingestion.statements,
    ...ingestion.transitions.map((transition) => transition.statement),
  ];
  if (statements.length === 0) return [];
  const results = await env.DB.batch(statements);
  const offset = leading.length + ingestion.statements.length;
  return ingestion.transitions
    .filter((_, index) => (results[offset + index]?.meta.changes ?? 0) > 0)
    .map((transition) => ({
      nodeId,
      checkId: transition.checkId,
      checkName: transition.checkName,
      kind: transition.kind,
      summary: transition.summary,
      occurredAt: transition.occurredAt,
    }));
}
