import { describe, expect, it } from "vitest";

import type { ActionRecord, NodeRecord } from "../types";
import {
  activity,
  elapsedText,
  maintenanceSpans,
  plannedNow,
  serverOperation,
} from "./operations";

const NOW = Date.parse("2026-10-01T12:00:00.000Z");
const ago = (minutes: number) => new Date(NOW - minutes * 60_000).toISOString();

const node = (overrides: Partial<NodeRecord> = {}) =>
  ({
    id: "n1",
    name: "pivox",
    agent_version: "0.3.3",
    update_requested_version: null,
    update_requested_at: null,
    update_attempts: 0,
    last_seen_at: null,
    connected_at: undefined,
    ...overrides,
  }) as NodeRecord;

const action = (overrides: Partial<ActionRecord>): ActionRecord => ({
  id: "a1",
  batchId: "b1",
  position: 0,
  mode: "rolling",
  nodeId: "n1",
  kind: "docker",
  name: "nginx",
  action: "restart",
  status: "sent",
  requestedBy: "budi@example.test",
  requestedAt: ago(1),
  deliverableAt: ago(1),
  sentAt: ago(1),
  finishedAt: null,
  exitCode: null,
  output: null,
  deviceId: null,
  ...overrides,
});

const reboot = (overrides: Partial<ActionRecord>) =>
  action({
    id: "r1",
    kind: "host",
    name: "server",
    action: "reboot",
    requestedBy: "owner@example.test",
    ...overrides,
  });

describe("server operations", () => {
  it("is restarting while the reboot is on its way and until the agent comes back", () => {
    expect(serverOperation(node(), [reboot({})], NOW)).toMatchObject({
      kind: "restarting",
      by: "owner",
      since: NOW - 60_000,
    });
    const done = reboot({ status: "done", finishedAt: ago(3) });
    expect(
      serverOperation(node({ connected_at: ago(20) }), [done], NOW),
    ).toMatchObject({ kind: "restarting" });
    expect(serverOperation(node({ connected_at: ago(1) }), [done], NOW)).toBe(
      null,
    );
  });

  it("stops calling it a restart after 10 minutes, a failure, or a server that never went away", () => {
    expect(
      serverOperation(
        node(),
        [reboot({ status: "done", finishedAt: ago(11) })],
        NOW,
      ),
    ).toBe(null);
    expect(
      serverOperation(
        node(),
        [reboot({ status: "failed", finishedAt: ago(1) })],
        NOW,
      ),
    ).toBe(null);
    expect(
      serverOperation(
        node({
          connected_at: ago(30),
          last_seen_at: ago(0).replace("T", " ").slice(0, 19),
        }),
        [reboot({ status: "done", finishedAt: ago(5) })],
        NOW,
      ),
    ).toBe(null);
  });

  it("is updating while an agent update is in flight", () => {
    expect(
      serverOperation(
        node({
          agent_version: "0.3.2",
          update_requested_version: "0.3.3",
          update_requested_at: ago(4),
          update_attempts: 2,
        }),
        [],
        NOW,
      ),
    ).toEqual({
      kind: "updating",
      version: "0.3.3",
      attempt: 2,
      since: NOW - 4 * 60_000,
    });
  });
});

describe("activity", () => {
  it("lists only running and waiting work and restarts not back yet", () => {
    const list = activity(
      [
        action({ id: "x1", status: "done", finishedAt: ago(70) }),
        action({ id: "x2", status: "failed", finishedAt: ago(5) }),
        action({ id: "x3", status: "done", finishedAt: ago(2) }),
        action({ id: "x4", action: "logs", status: "sent" }),
        action({ id: "x5", name: "redis", status: "queued" }),
        reboot({ status: "done", finishedAt: ago(1) }),
      ],
      [node()],
      NOW,
    );
    expect(list.map((item) => item.id)).toEqual(["x5", "r1"]);
    expect(list[0]).toMatchObject({
      nodeName: "pivox",
      by: "budi",
      label: "redis",
    });
  });
});

describe("elapsed time", () => {
  it("reads like a stopwatch, then in minutes and hours", () => {
    expect(elapsedText(42_000)).toBe("0:42");
    expect(elapsedText(72_000)).toBe("1:12");
    expect(elapsedText(65 * 60_000)).toBe("1h 5m");
  });
});

describe("maintenance spans", () => {
  it("covers planned work on a server, two minutes after it ends, ten after a restart, but not the auto-restart switch", () => {
    const spans = maintenanceSpans(
      [
        action({
          id: "m1",
          sentAt: ago(30),
          finishedAt: ago(29),
          status: "done",
        }),
        action({ id: "m2", nodeId: "other" }),
        action({ id: "m3", action: "logs", sentAt: ago(5) }),
        reboot({ sentAt: ago(20), finishedAt: ago(19), status: "done" }),
        action({ id: "m4", sentAt: ago(1) }),
        action({ id: "m5", action: "autorestart", sentAt: ago(3) }),
        action({ id: "m6", action: "manual", sentAt: ago(2) }),
      ],
      "n1",
    );
    expect(spans).toEqual([
      { from: NOW - 30 * 60_000, to: NOW - 27 * 60_000 },
      { from: NOW - 20 * 60_000, to: NOW - 9 * 60_000 },
      { from: NOW - 60_000, to: Infinity },
    ]);
  });
});

describe("planned work right now", () => {
  it("is true inside a span and false after it", () => {
    const spans = [{ from: NOW - 60_000, to: NOW + 60_000 }];
    expect(plannedNow(spans, NOW)).toBe(true);
    expect(plannedNow(spans, NOW + 60_000)).toBe(false);
    expect(plannedNow([], NOW)).toBe(false);
  });
});
