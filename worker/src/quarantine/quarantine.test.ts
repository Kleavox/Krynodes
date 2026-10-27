import { describe, expect, it } from "vitest";

import { createBatch, deliverActions } from "../actions/store";
import { decodeJson } from "../lib/b64url";
import { IO, keyOf, OLD, queued, seedFleet, V1, V2, V3 } from "../test/fleet";
import { createTestDb } from "../test/sqlite-d1";
import { quarantine, quarantineRefusal } from "./quarantine";

const NOW = Date.parse("2026-10-27T21:18:00Z");

function setup() {
  const { db, sqlite } = createTestDb();
  seedFleet(sqlite);
  return { db, sqlite };
}

describe("quarantine", () => {
  it("sends the suspect one Lock Down, drops it from every other member and blocks its Tailscale addresses on every 0.7.0 server", async () => {
    const { db, sqlite } = setup();
    const started = await quarantine(db, {
      nodeId: V1,
      why: "vps-2 and vps-3 saw it knock on 41 closed ports in one minute",
      now: NOW,
    });
    expect(started.started).toBe(true);
    const rows = queued(sqlite);
    expect(
      rows.map((row) => [row.nodeId, row.kind, row.name, row.action]),
    ).toEqual([
      [V1, "host", "server", "lockdown"],
      [V2, "network", "kry0", "drop"],
      [V3, "network", "kry0", "drop"],
      [V2, "host", "tailscale", "block"],
      [V3, "host", "tailscale", "block"],
      [IO, "host", "tailscale", "block"],
    ]);
    expect(rows.every((row) => row.signed === null)).toBe(true);
    expect(rows.every((row) => row.requestedBy === "Quarantine")).toBe(true);
    expect(rows.every((row) => row.deliverableAt !== null)).toBe(true);
    expect(decodeJson(rows[1]!.attachment!)).toEqual({
      node: V1,
      key: keyOf(1),
      address: "10.88.0.1",
    });
    expect(decodeJson(rows[3]!.attachment!)).toEqual({
      addresses: "100.101.7.10 fd7a:115c:a1e0::7",
    });
    expect(rows.some((row) => row.nodeId === OLD)).toBe(false);
    expect(
      sqlite.prepare("SELECT key, node_id AS node FROM network_blocked").all(),
    ).toEqual([{ key: keyOf(1), node: V1 }]);
    expect(
      sqlite
        .prepare("SELECT change, requested_by AS by FROM network_changes")
        .all(),
    ).toEqual([{ change: "Quarantine vps-1", by: "Quarantine" }]);
  });

  it("starts once for a server already quarantined", async () => {
    const { db, sqlite } = setup();
    await quarantine(db, { nodeId: V1, why: "first", now: NOW });
    const again = await quarantine(db, {
      nodeId: V1,
      why: "second",
      now: NOW + 1000,
    });
    expect(again.started).toBe(false);
    expect(
      queued(sqlite).filter((row) => row.action === "lockdown"),
    ).toHaveLength(1);
  });

  it("holds back what was queued for the suspect before, delivering only reading and the one Lock Down", async () => {
    const { db, sqlite } = setup();
    const at = (n: number) => NOW - 60_000 + n;
    for (const [action, name] of [
      ["restart", "app"],
      ["logs", "app"],
    ] as const) {
      await db.batch(
        createBatch(db, {
          action,
          mode: "parallel",
          targets: [
            {
              nodeId: V1,
              kind: "compose",
              name,
              ...(action === "logs" ? {} : { signed: { command: "x" } }),
            },
          ],
          requestedBy: "owner@example.test",
          now: at(action === "logs" ? 1 : 0),
        }).statements,
      );
    }
    await quarantine(db, { nodeId: V1, why: "why", now: NOW });
    const delivered = await deliverActions(db, V1, NOW + 1000);
    expect(delivered.map((action) => action.action).sort()).toEqual([
      "lockdown",
      "logs",
    ]);
    expect(await deliverActions(db, V1, NOW + 2000)).toEqual([]);
    expect(
      sqlite
        .prepare("SELECT status FROM actions WHERE action = 'restart'")
        .get(),
    ).toEqual({ status: "cancelled" });
  });

  it("refuses every action on the suspect except reading", async () => {
    const { db } = setup();
    await quarantine(db, { nodeId: V1, why: "why", now: NOW });
    expect(await quarantineRefusal(db, [V1, V2], "restart")).toEqual({
      code: "QUARANTINED",
      message: "vps-1 is quarantined. Only reading works there.",
    });
    expect(await quarantineRefusal(db, [V1], "logs")).toBeNull();
    expect(await quarantineRefusal(db, [V2], "restart")).toBeNull();
  });
});
