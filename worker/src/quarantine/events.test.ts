import type { QuarantineEvent } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { OWNER } from "../test/seed";
import { seedFleet, V1, V2, V3 } from "../test/fleet";
import { createTestDb } from "../test/sqlite-d1";
import { intake } from "./events";
import { writeSettings } from "./settings";

const NOW = Date.parse("2026-10-27T21:04:00Z");

const event = (
  id: string,
  kind: QuarantineEvent["kind"],
  detail: Record<string, string>,
): QuarantineEvent => ({ id, kind, at: "2026-10-27T21:03:58Z", detail });

const sshKey = event("ssh-key:abc", "ssh-key", {
  user: "root",
  file: "/root/.ssh/authorized_keys",
  key: "ED25519 SHA256:x laptop",
  item: "root:/root/.ssh/authorized_keys:SHA256:x",
});

const knock = (count: number) =>
  event(`knock:10.88.0.1:${count}`, "knock", {
    from: "10.88.0.1",
    count: String(count),
    sample: "10.88.0.2:22/tcp",
  });

function setup(members?: string[]) {
  const { db, sqlite } = createTestDb();
  seedFleet(sqlite, members);
  const open = () =>
    sqlite.prepare("SELECT node_id AS node, why FROM quarantines").all() as {
      node: string;
      why: string;
    }[];
  return { db, sqlite, open };
}

describe("intake", () => {
  it("makes one warning with its cut-off at the setting, acks the event, and makes nothing new when it comes again", async () => {
    const { db, sqlite } = setup();
    const first = await intake(db, { nodeId: V1, events: [sshKey], now: NOW });
    expect(first.acked).toEqual(["ssh-key:abc"]);
    expect(first.cutoffs).toEqual([
      { nodeId: V1, id: "ssh-key:abc", at: NOW + 15 * 60_000 },
    ]);
    const again = await intake(db, {
      nodeId: V1,
      events: [sshKey],
      now: NOW + 60_000,
    });
    expect(again).toEqual({
      acked: ["ssh-key:abc"],
      cutoffs: [],
      nodes: [],
      quarantined: [],
      warned: [],
      stopped: [],
    });
    expect(
      sqlite.prepare("SELECT kind, cut_at, answer FROM warnings").all(),
    ).toEqual([
      { kind: "ssh-key", cut_at: "2026-10-27T21:19:00.000Z", answer: null },
    ]);
  });

  it("never cuts off with Warn Only", async () => {
    const { db, sqlite } = setup();
    await writeSettings(
      db,
      OWNER,
      { cutoff: null, scan: 10, agree: 2, stop: true },
      "now",
    ).run();
    const taken = await intake(db, { nodeId: V1, events: [sshKey], now: NOW });
    expect(taken.cutoffs).toEqual([]);
    expect(sqlite.prepare("SELECT cut_at FROM warnings").get()).toEqual({
      cut_at: null,
    });
  });

  it("quarantines a knocker once as many servers as the setting asks agree", async () => {
    const { db, open } = setup();
    await intake(db, { nodeId: V2, events: [knock(41)], now: NOW });
    expect(open()).toEqual([]);
    const second = await intake(db, {
      nodeId: V3,
      events: [knock(12)],
      now: NOW + 30_000,
    });
    expect(open()).toEqual([
      {
        node: V1,
        why: "vps-2 and vps-3 saw it knock on 41 closed ports in one minute",
      },
    ]);
    expect(second.nodes).toContain(V2);
  });

  it("asks a two-server network for no more than the one other server", async () => {
    const { db, open } = setup([V1, V2]);
    await intake(db, { nodeId: V2, events: [knock(14)], now: NOW });
    expect(open()).toEqual([
      { node: V1, why: "vps-2 saw it knock on 14 closed ports in one minute" },
    ]);
  });

  it("forgets knocks older than the agreement window", async () => {
    const { db, open } = setup();
    await intake(db, { nodeId: V2, events: [knock(41)], now: NOW });
    await intake(db, {
      nodeId: V3,
      events: [knock(12)],
      now: NOW + 11 * 60_000,
    });
    expect(open()).toEqual([]);
  });

  it("keeps a stopped stack, and a wrong port is a problem that never cuts off", async () => {
    const { db, sqlite, open } = setup();
    const taken = await intake(db, {
      nodeId: V1,
      events: [
        event("stack:app:1", "stack", {
          stack: "app",
          count: "14",
          tried: "10.88.0.2:5432/tcp 10.88.0.3:22/tcp",
          stopped: "true",
        }),
        event("wrong-port:x", "wrong-port", {
          from: "10.88.0.1",
          target: "10.88.0.2:5433/tcp",
        }),
      ],
      now: NOW,
    });
    expect(taken.cutoffs).toEqual([]);
    expect(open()).toEqual([]);
    expect(
      sqlite.prepare("SELECT project, tried, count FROM stopped_stacks").all(),
    ).toEqual([
      {
        project: "app",
        tried: '["10.88.0.2:5432/tcp","10.88.0.3:22/tcp"]',
        count: 14,
      },
    ]);
    expect(sqlite.prepare("SELECT kind, cut_at FROM warnings").all()).toEqual([
      { kind: "wrong-port", cut_at: null },
    ]);
    expect(
      sqlite
        .prepare("SELECT change, requested_by AS by FROM network_changes")
        .all(),
    ).toEqual([{ change: "Stop app on vps-1", by: "Quarantine" }]);
  });
});
