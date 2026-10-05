import { describe, expect, it } from "vitest";

import type { ActionRecord } from "../types";
import { byDay, historyText } from "./history";

const action = (overrides: Partial<ActionRecord>): ActionRecord => ({
  id: "a1",
  batchId: "b1",
  position: 0,
  mode: "rolling",
  nodeId: "n1",
  kind: "docker",
  name: "adguard",
  action: "restart",
  status: "done",
  requestedBy: "owner@example.test",
  requestedAt: "2026-09-29T10:00:00.000Z",
  deliverableAt: null,
  sentAt: null,
  finishedAt: null,
  exitCode: null,
  output: null,
  deviceId: null,
  ...overrides,
});

const local = (month: number, day: number, hour: number) =>
  new Date(2026, month, day, hour, 0).toISOString();

describe("history", () => {
  it("groups actions by the browser's day, newest first", () => {
    const now = new Date(2026, 9, 2, 15, 0).getTime();
    const groups = byDay(
      [
        action({ id: "1", requestedAt: local(9, 2, 14) }),
        action({ id: "2", requestedAt: local(9, 2, 0) }),
        action({ id: "3", requestedAt: local(9, 1, 23) }),
        action({ id: "4", requestedAt: local(8, 29, 8) }),
        action({ id: "5", requestedAt: local(8, 29, 7) }),
      ],
      now,
    );
    expect(
      groups.map((group) => [
        group.label,
        group.actions.map((entry) => entry.id),
      ]),
    ).toEqual([
      ["Today", ["1", "2"]],
      ["Yesterday", ["3"]],
      ["29 Sep", ["4", "5"]],
    ]);
  });

  it("says what was done in a few words", () => {
    expect(historyText(action({}))).toBe("Restart adguard");
    expect(historyText(action({ action: "logs" }))).toBe(
      "Read logs of adguard",
    );
    expect(
      historyText(action({ kind: "compose", name: "kuma", action: "purge" })),
    ).toBe("Delete kuma permanently");
    expect(
      historyText(
        action({ kind: "systemd", name: "nginx.service", action: "heal" }),
      ),
    ).toBe("Auto-restart nginx");
  });
});
