import type { AgentHeartbeat } from "@krynodes/protocol";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { hubHarness, type FakeSocket } from "../test/hub";
import { keyOf, seedFleet, V1, V2, V3 } from "../test/fleet";
import { OWNER, seedCheck } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import { quarantine } from "./quarantine";

const NOW = Date.parse("2026-10-27T21:04:00Z");
const CHECK = "c1111111-1111-4111-8111-111111111111";

const beat = (
  nodeId: string,
  extra: Partial<AgentHeartbeat> = {},
): AgentHeartbeat => ({
  nodeId,
  hostname: nodeId,
  operatingSystem: "linux",
  architecture: "amd64",
  agentVersion: "0.7.0",
  metrics: {
    cpuPercent: 1,
    memoryUsedBytes: 1,
    memoryTotalBytes: 2,
    diskUsedBytes: 1,
    diskTotalBytes: 10,
    load1: 0,
    load5: 0,
    load15: 0,
    uptimeSeconds: 100,
  },
  ...extra,
});

const sshKey = {
  id: "ssh-key:abc",
  kind: "ssh-key" as const,
  at: "2026-10-27T21:03:58Z",
  detail: { user: "root", item: "root:/root/.ssh/authorized_keys:SHA256:x" },
};

function setup() {
  const { db, sqlite } = createTestDb();
  seedFleet(sqlite);
  const mail = vi.fn(async () => ({ messageId: "m" }));
  const harness = hubHarness({
    DB: db,
    EMAIL: { send: mail },
    ALERT_EMAIL: "owner@example.test",
    FROM_EMAIL: "kry@example.test",
  } as never);
  const subjects = () =>
    (mail.mock.calls as unknown as [{ subject: string; text: string }][]).map(
      ([message]) => message.subject,
    );
  const texts = () =>
    (mail.mock.calls as unknown as [{ text: string }][]).map(
      ([message]) => message.text,
    );
  const storage = (
    harness.hub as unknown as {
      ctx: { storage: { alarm: number | null } };
    }
  ).ctx.storage;
  const send = async (ws: FakeSocket, heartbeat: AgentHeartbeat, at = NOW) => {
    vi.setSystemTime(at);
    return (await harness.request(ws, "heartbeat", { heartbeat })) as {
      response: Record<string, unknown>;
    } | null;
  };
  const open = () =>
    sqlite
      .prepare("SELECT node_id AS node, why, at FROM quarantines")
      .all() as { node: string; why: string; at: string }[];
  return { db, sqlite, harness, storage, send, open, subjects, texts };
}

describe("the hub and quarantine", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it("acks a beat's events and wakes at the warning's cut-off to quarantine at that minute", async () => {
    const { harness, storage, send, open } = setup();
    const ws = await harness.connect(V1, OWNER);
    const reply = await send(ws, beat(V1, { events: [sshKey] }));
    expect(reply?.response.acked).toEqual(["ssh-key:abc"]);
    const cut = NOW + 15 * 60_000;
    expect(storage.alarm).toBeLessThanOrEqual(cut);
    vi.setSystemTime(cut + 500);
    await harness.hub.alarm();
    expect(open()).toEqual([
      {
        node: V1,
        why: "Nobody said the new SSH key for root was theirs within 15 minutes",
        at: new Date(cut).toISOString(),
      },
    ]);
  });

  it("mails every warning at once, outside the hourly rule, and the quarantine at its cut-off", async () => {
    const { harness, send, subjects, texts } = setup();
    const ws = await harness.connect(V1, OWNER);
    await send(ws, beat(V1, { events: [sshKey] }));
    await send(
      ws,
      beat(V1, {
        events: [
          {
            id: "user:eve",
            kind: "user",
            at: "2026-10-27T21:04:30Z",
            detail: { user: "eve", item: "eve" },
          },
        ],
      }),
      NOW + 30_000,
    );
    await send(ws, beat(V1, { events: [sshKey] }), NOW + 40_000);
    expect(subjects()).toEqual([
      "[Krynodes] vps-1: new SSH key for root",
      "[Krynodes] vps-1: new user eve",
    ]);
    vi.setSystemTime(NOW + 15 * 60_000 + 500);
    await harness.hub.alarm();
    const quarantined = subjects().indexOf("[Krynodes] vps-1 is quarantined");
    expect(quarantined).toBeGreaterThan(1);
    expect(texts()[quarantined]).toContain(
      "Why: Nobody said the new SSH key for root was theirs within 15 minutes",
    );
    expect(texts()[quarantined]).toContain("Dropped by: vps-2 and vps-3");
  });

  it("mails a stopped stack and a server reporting from two machines", async () => {
    const { sqlite, harness, send, subjects, texts } = setup();
    sqlite.exec(
      `UPDATE nodes SET boot = 'b1', reports = 100 WHERE id = '${V1}'`,
    );
    const ws = await harness.connect(V1, OWNER);
    await send(
      ws,
      beat(V1, {
        events: [
          {
            id: "stack:app:1",
            kind: "stack",
            at: "2026-10-27T21:03:00Z",
            detail: {
              stack: "app",
              count: "14",
              tried: "10.88.0.2:22/tcp 10.88.0.2:80/tcp",
              stopped: "true",
            },
          },
        ],
      }),
    );
    expect(subjects()).toEqual(["[Krynodes] app on vps-1 was stopped"]);
    expect(texts()[0]).toContain(
      "Tried: 10.88.0.2:22/tcp, 10.88.0.2:80/tcp and 12 more",
    );
    const copy = await harness.connect(V1, OWNER);
    await send(copy, beat(V1, { boot: { id: "b3", count: 60 } }), NOW + 1000);
    expect(subjects().slice(1)).toEqual(["[Krynodes] vps-1 is quarantined"]);
    expect(texts()[1]).toContain("Why: Reported from two machines at once");
    expect(texts()[1]).toContain(
      "Change: Its place on your tailnet, listed on the server page",
    );
  });

  it("does not cut off a warning answered with It Was Me", async () => {
    const { sqlite, harness, send, open } = setup();
    const ws = await harness.connect(V1, OWNER);
    await send(ws, beat(V1, { events: [sshKey] }));
    sqlite.exec("UPDATE warnings SET answer = 'me'");
    vi.setSystemTime(NOW + 16 * 60_000);
    await harness.hub.alarm();
    expect(open()).toEqual([]);
  });

  it("quarantines one identity reporting from two machines, and lets a reboot through", async () => {
    const { sqlite, harness, send, open } = setup();
    sqlite.exec(
      `UPDATE nodes SET boot = 'b1', reports = 100 WHERE id = '${V1}'`,
    );
    const ws = await harness.connect(V1, OWNER);
    await send(ws, beat(V1, { boot: { id: "b2", count: 101 } }));
    expect(open()).toEqual([]);
    expect(
      sqlite
        .prepare(`SELECT boot, reports FROM nodes WHERE id = '${V1}'`)
        .get(),
    ).toEqual({ boot: "b2", reports: 101 });
    const copy = await harness.connect(V1, OWNER);
    const reply = await send(copy, beat(V1, { boot: { id: "b3", count: 60 } }));
    expect(open().map((row) => row.why)).toEqual([
      "Reported from two machines at once",
    ]);
    expect(reply?.response.quarantined).toBe(true);
  });

  it("opens no incident for a quarantined server's failing check and delivers only its Lock Down", async () => {
    const { db, sqlite, harness, send } = setup();
    seedCheck(sqlite, { id: CHECK, nodeId: V1 });
    for (const [id, action] of [
      ["p1", "restart"],
      ["p2", "logs"],
    ]) {
      sqlite.exec(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status,
           requested_by, requested_at, deliverable_at)
         VALUES ('${id}', '${id}', 0, 'parallel', '${V1}', 'systemd', 'nginx.service', '${action}',
           'queued', 'owner', '${new Date(NOW - 5000).toISOString()}', '${new Date(NOW - 5000).toISOString()}')`,
      );
    }
    await quarantine(db, { nodeId: V1, why: "why", now: NOW - 1000 });
    const ws = await harness.connect(V1, OWNER);
    const down = {
      results: [
        {
          checkId: CHECK,
          status: "DOWN" as const,
          latencyMs: null,
          message: "refused",
        },
      ],
    };
    const first = await send(ws, beat(V1, down));
    const second = await send(ws, beat(V1, down), NOW + 60_000);
    expect(sqlite.prepare("SELECT * FROM incidents").all()).toEqual([]);
    expect(
      (first?.response.actions as { action: string }[])
        .map((a) => a.action)
        .sort(),
    ).toEqual(["lockdown", "logs"]);
    expect(second?.response.actions ?? []).toEqual([]);
    expect(
      sqlite.prepare("SELECT status FROM actions WHERE id = 'p1'").get(),
    ).toEqual({ status: "cancelled" });
    expect(first?.response.quarantined).toBe(true);
  });

  it("acks a quarantined server's events but believes none of them, nor its links", async () => {
    const { db, sqlite, harness, send, open } = setup();
    sqlite.exec(
      `INSERT INTO quarantine_settings (owner_user_id, cutoff, scan, agree, stop, updated_at)
       VALUES ('${OWNER}', 15, 10, 1, 1, 'now')`,
    );
    await quarantine(db, { nodeId: V1, why: "why", now: NOW - 1000 });
    const ws = await harness.connect(V1, OWNER);
    const knock = {
      id: "knock:1",
      kind: "knock" as const,
      at: "2026-10-27T21:03:58Z",
      detail: { from: "10.88.0.2", count: "40" },
    };
    const reply = await send(
      ws,
      beat(V1, {
        events: [knock, sshKey],
        network: {
          version: 1,
          key: keyOf(1),
          links: [
            {
              key: keyOf(2),
              handshake: Math.floor(NOW / 1000) - 10,
              rx: 1,
              tx: 1,
              endpoint: null,
              ms: null,
            },
          ],
        },
      } as Partial<AgentHeartbeat>),
    );
    expect(reply?.response.acked).toEqual(["knock:1", "ssh-key:abc"]);
    expect(open().map((row) => row.node)).toEqual([V1]);
    expect(sqlite.prepare("SELECT * FROM warnings").all()).toEqual([]);
    expect(sqlite.prepare("SELECT * FROM knocks").all()).toEqual([]);
    expect(reply?.response.network).toBeUndefined();
    const latest = (await (
      await harness.hub.fetch(new Request("https://hub/network"))
    ).json()) as Record<string, unknown>;
    expect(latest[V1]).toBeUndefined();
  });

  it("keeps the release the agent reports, writing it only when it changes", async () => {
    const { sqlite, harness, send } = setup();
    const release = {
      key: keyOf(9),
      signer: keyOf(19),
      seal: "c2VhbA",
      token: "a".repeat(64),
      expires: "2026-10-27T21:14:00.000Z",
    };
    const ws = await harness.connect(V1, OWNER);
    await send(ws, beat(V1, { release }));
    expect(
      JSON.parse(
        (
          sqlite
            .prepare(`SELECT release FROM nodes WHERE id = '${V1}'`)
            .get() as {
            release: string;
          }
        ).release,
      ),
    ).toEqual(release);
    const writes = (
      sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }
    ).n;
    await send(ws, beat(V1, { release }), NOW + 30_000);
    expect(
      (sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }).n,
    ).toBe(writes);
  });

  it("warns when an agent goes quiet while another server still sees its handshake", async () => {
    const { sqlite, harness, send } = setup();
    const quiet = await harness.connect(V1, OWNER);
    await send(quiet, beat(V1));
    quiet.close(1006, "gone");
    await harness.hub.webSocketClose(quiet as unknown as WebSocket);
    const peer = await harness.connect(V2, OWNER);
    const late = NOW + 10 * 60_000;
    await send(
      peer,
      beat(V2, {
        network: {
          version: 1,
          key: keyOf(2),
          links: [
            {
              key: keyOf(1),
              handshake: Math.floor(late / 1000) - 30,
              rx: 1,
              tx: 1,
              endpoint: null,
              ms: null,
            },
          ],
        },
      } as Partial<AgentHeartbeat>),
      late,
    );
    await harness.hub.alarm();
    expect(
      sqlite.prepare("SELECT node_id AS node, kind FROM warnings").all(),
    ).toEqual([{ node: V1, kind: "quiet" }]);
    expect(V3).toBeDefined();
  });
});
