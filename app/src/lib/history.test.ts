import { describe, expect, it } from "vitest";

import type { ActionRecord, HistoryEntry } from "../types";
import {
  actionLine,
  causedText,
  dayGroups,
  failedLine,
  historyPath,
  historyText,
  incidentText,
  lastLines,
  logTargets,
  readShow,
  retryOf,
} from "./history";
import { errorLine } from "./services";

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

const at = (day: number, hour: number, minute = 0) =>
  new Date(2026, 9, day, hour, minute).toISOString();

const done = (
  id: string,
  when: string,
  overrides: Partial<ActionRecord> = {},
) =>
  ({
    type: "action",
    at: when,
    action: action({ id, requestedAt: when, ...overrides }),
  }) as const;

const incident = (
  event: "opened" | "resolved",
  checkName: string,
  startedAt: string,
  resolvedAt: string | null = null,
): Extract<HistoryEntry, { type: "incident" }> => ({
  type: "incident",
  at: event === "opened" ? startedAt : resolvedAt!,
  event,
  incident: {
    id: `${checkName}-${startedAt}`,
    checkId: "c1",
    checkName,
    nodeId: "n1",
    nodeName: "pivox",
    summary: "Container is not running",
    startedAt,
    resolvedAt,
  },
});

describe("history", () => {
  it("groups entries by the browser's day and counts what each day holds", () => {
    const groups = dayGroups(
      [
        done("1", at(24, 9, 58), { status: "failed" }),
        incident("opened", "Pi-hole", at(24, 9, 52)),
        incident("opened", "Umami", at(24, 9, 26)),
        done("2", at(24, 9, 24), { status: "expired" }),
        done("3", at(24, 8, 23)),
        done("4", at(23, 9, 38)),
        incident("resolved", "Blog", at(21, 7, 8), at(21, 7, 20)),
        done("5", at(21, 5, 28)),
      ],
      new Date(2026, 9, 24, 15, 0).getTime(),
    );
    expect(
      groups.map((group) => [group.label, group.counts, group.entries.length]),
    ).toEqual([
      ["Today", "3 actions · 2 failed · 2 incidents", 5],
      ["Yesterday", "1 action", 1],
      ["21 Oct", "1 action · 1 incident", 2],
    ]);
  });

  it("says an incident went down or recovered after how long", () => {
    expect(incidentText(incident("opened", "Pi-hole", at(24, 9, 52)))).toBe(
      "Pi-hole went down",
    );
    expect(
      incidentText(incident("resolved", "Blog", at(21, 7, 8), at(21, 7, 20))),
    ).toBe("Blog recovered after 12m");
  });

  it("names the incident a failed action caused", () => {
    expect(
      causedText(
        {
          id: "i1",
          checkName: "Umami",
          summary: "HTTP 502",
          startedAt: at(24, 9, 26),
        },
        new Date(2026, 9, 24, 10, 28).getTime(),
      ),
    ).toBe("Umami down since 09:26 · HTTP 502 · 1h 2m");
    expect(
      causedText(
        {
          id: "i1",
          checkName: "Umami",
          summary: null,
          startedAt: at(24, 9, 26),
        },
        new Date(2026, 9, 24, 9, 30).getTime(),
      ),
    ).toBe("Umami down since 09:26 · 4m");
  });

  it("asks the Worker for one filter and one search", () => {
    expect(historyPath({ show: "everything", q: "" })).toBe("/api/history");
    expect(historyPath({ show: "everything", q: " port 53 " })).toBe(
      "/api/history?q=port+53",
    );
    expect(historyPath({ node: "n1", show: "failed", q: "" })).toBe(
      "/api/history?node=n1&show=failed",
    );
  });

  it("opens on the filter a link names, or on Everything", () => {
    expect(readShow("incidents")).toBe("incidents");
    expect(readShow("failed")).toBe("failed");
    expect(readShow("bogus")).toBe("everything");
    expect(readShow(null)).toBe("everything");
  });
});

describe("a failed, not fixed card", () => {
  const inventory = {
    stacks: [{ project: "umami", containers: ["umami-umami-1", "umami-db-1"] }],
    services: [
      {
        kind: "docker" as const,
        name: "umami-db-1",
        state: "stopped" as const,
        since: null,
        system: false,
      },
      {
        kind: "docker" as const,
        name: "umami-umami-1",
        state: "running" as const,
        since: null,
        system: false,
      },
      {
        kind: "docker" as const,
        name: "pihole-pihole-1",
        state: "stopped" as const,
        since: null,
        system: false,
      },
    ],
  };

  it("offers the logs of every container the action touched", () => {
    expect(
      logTargets(
        action({ kind: "compose", name: "umami", action: "deploy" }),
        inventory,
      ),
    ).toEqual([
      { kind: "docker", name: "umami-db-1" },
      { kind: "docker", name: "umami-umami-1" },
    ]);
    expect(logTargets(action({ name: "pihole-pihole-1" }), inventory)).toEqual([
      { kind: "docker", name: "pihole-pihole-1" },
    ]);
    expect(
      logTargets(
        action({ kind: "systemd", name: "backup.service" }),
        inventory,
      ),
    ).toEqual([{ kind: "systemd", name: "backup.service" }]);
    expect(
      logTargets(
        action({ kind: "host", name: "firewall", action: "apply" }),
        inventory,
      ),
    ).toEqual([]);
  });

  it("tries again the way the action was asked", () => {
    expect(retryOf(action({ kind: "compose", action: "deploy" }))).toEqual({
      via: "deploy",
    });
    expect(retryOf(action({ kind: "compose", action: "rollback" }))).toEqual({
      via: "rollback",
    });
    expect(retryOf(action({ action: "restart" }))).toEqual({
      via: "run",
      action: "restart",
    });
    expect(retryOf(action({ kind: "systemd", action: "heal" }))).toEqual({
      via: "run",
      action: "restart",
    });
    expect(retryOf(action({ action: "stop" }))).toEqual({
      via: "confirm",
      action: "stop",
    });
    expect(retryOf(action({ kind: "compose", action: "stop" }))).toBeNull();
    expect(retryOf(action({ kind: "host", action: "apply" }))).toBeNull();
  });

  it("shows the last lines of an output first", () => {
    expect(lastLines("a\nb\nc\n", 2)).toEqual({ text: "b\nc", hidden: 1 });
    expect(lastLines("a", 5)).toEqual({ text: "a", hidden: 0 });
  });
});

describe("what an action says", () => {
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
    expect(
      historyText(
        action({ kind: "host", name: "server", action: "uninstall" }),
      ),
    ).toBe("Remove Krynodes from the server");
  });
});

describe("an error line", () => {
  it("is the last line a failure printed", () => {
    expect(
      errorLine(
        "Container umami-db-1 Starting\ndependency failed to start: container umami-db-1 exited (1)\n\n",
      ),
    ).toBe("dependency failed to start: container umami-db-1 exited (1)");
  });

  it("is nothing for no output", () => {
    for (const output of [null, "", "\n  \n"]) {
      expect(errorLine(output)).toBeNull();
    }
  });

  it("is cut to 200 characters", () => {
    expect(errorLine("x".repeat(600))).toHaveLength(200);
  });
});

describe("one action line", () => {
  const stacks = [{ project: "pihole", containers: ["pihole-pihole-1"] }];
  const failed = action({
    name: "pihole-pihole-1",
    status: "failed",
    exitCode: 1,
    output: "Error response from daemon\nport 53 is already allocated\n",
    requestedAt: "2026-10-24T02:24:00.000Z",
    sentAt: "2026-10-24T02:24:01.000Z",
    finishedAt: "2026-10-24T02:25:07.000Z",
  });

  it("names a container by its stack and carries the error, not the finishing time", () => {
    const line = actionLine(failed, { stacks });
    expect(line).toMatchObject({
      time: "09:24",
      mark: "✕",
      text: "Restart pihole",
      failure: "Exit 1 · port 53 is already allocated",
    });
    expect(JSON.stringify(line)).not.toContain("09:25");
  });

  it("gives an action from another day its date when told the time", () => {
    const sameDay = new Date(2026, 9, 24, 23, 0).getTime();
    expect(actionLine(failed, { stacks, now: sameDay }).time).toBe("09:24");
    expect(
      actionLine(failed, { stacks, now: sameDay + 5 * 86_400_000 }).time,
    ).toBe("24 Oct 09:24");
  });

  it("says a failure in the hourglass with its server, its stack and its date", () => {
    const later = new Date(2026, 9, 24, 23, 0).getTime() + 5 * 86_400_000;
    expect(failedLine(failed, { name: "pivox", stacks }, later)).toEqual({
      text: "Restart pihole on pivox",
      time: "24 Oct 09:24",
      failure: "Exit 1 · port 53 is already allocated",
    });
  });

  it("says the exit code alone when the output is empty", () => {
    expect(actionLine({ ...failed, output: "" }, { stacks }).failure).toBe(
      "Exit 1",
    );
  });

  it("shows the device and the duration of a done deploy", () => {
    const line = actionLine(
      action({
        kind: "compose",
        name: "umami",
        action: "deploy",
        deviceId: "d1",
        sentAt: "2026-10-24T02:24:00.000Z",
        finishedAt: "2026-10-24T02:24:30.000Z",
      }),
      { devices: [{ id: "d1", name: "Laptop" }] },
    );
    expect(line).toMatchObject({
      mark: "✓",
      text: "Deploy umami",
      device: "Laptop",
      duration: "30s",
      failure: null,
      server: null,
    });
  });

  it("names the server only when asked", () => {
    expect(
      actionLine(failed, { nodeName: "pivox", showServer: true }).server,
    ).toBe("pivox");
    expect(actionLine(failed, { nodeName: "pivox" }).server).toBeNull();
  });
});
