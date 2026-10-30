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
  name: "resolver",
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
    nodeName: "server-1",
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
        incident("opened", "Tracker", at(24, 9, 26)),
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

  it("shows an incident once: its recovery stands in for the time it went down", () => {
    const groups = dayGroups(
      [
        incident("resolved", "Blog", at(24, 7, 8), at(24, 7, 20)),
        incident("opened", "Blog", at(24, 7, 8), at(24, 7, 20)),
        incident("opened", "Tracker", at(24, 6, 0)),
      ],
      new Date(2026, 9, 24, 15, 0).getTime(),
    );
    expect(
      groups[0]!.entries.map((entry) =>
        entry.type === "incident" ? incidentText(entry) : entry.type,
      ),
    ).toEqual(["Blog recovered after 12m", "Tracker went down"]);
    expect(groups[0]!.counts).toBe("2 incidents");
  });

  it("shows It was me once, unless the accept it sent failed", () => {
    const said = (id: string, when: string) =>
      ({
        type: "network",
        at: when,
        change: {
          id,
          at: when,
          change: "It was me: the new port on server-1",
          detail: "43112/udp",
          requestedBy: "owner@example.test",
          deviceId: null,
        },
      }) as const;
    const accept = (id: string, when: string, status: ActionRecord["status"]) =>
      done(id, when, {
        kind: "host",
        name: "server",
        action: "accept",
        status,
      });
    const groups = dayGroups(
      [
        said("w1", at(24, 9, 0)),
        accept("a1", at(24, 9, 0), "done"),
        said("w2", at(24, 8, 0)),
        accept("a2", at(24, 8, 0), "failed"),
      ],
      new Date(2026, 9, 24, 15, 0).getTime(),
    );
    expect(
      groups[0]!.entries.map((entry) =>
        entry.type === "network"
          ? entry.change.id
          : entry.type === "action"
            ? entry.action.id
            : "",
      ),
    ).toEqual(["w1", "w2", "a2"]);
    expect(groups[0]!.counts).toBe("3 actions · 1 failed");
  });

  it("counts a private network change with the day's actions", () => {
    const groups = dayGroups(
      [
        {
          type: "network",
          at: at(24, 9, 0),
          change: {
            id: "c1",
            at: at(24, 9, 0),
            change: "Add vps-3 to the private network",
            detail: null,
            requestedBy: "owner@example.test",
            deviceId: null,
          },
        },
        done("1", at(24, 8, 0)),
      ],
      new Date(2026, 9, 24, 15, 0).getTime(),
    );
    expect(groups.map((group) => group.counts)).toEqual(["2 actions"]);
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
          checkName: "Tracker",
          summary: "HTTP 502",
          startedAt: at(24, 9, 26),
        },
        new Date(2026, 9, 24, 10, 28).getTime(),
      ),
    ).toBe("Tracker down since 09:26 · HTTP 502 · 1h 2m");
    expect(
      causedText(
        {
          id: "i1",
          checkName: "Tracker",
          summary: null,
          startedAt: at(24, 9, 26),
        },
        new Date(2026, 9, 24, 9, 30).getTime(),
      ),
    ).toBe("Tracker down since 09:26 · 4m");
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
    stacks: [
      { project: "tracker", containers: ["tracker-tracker-1", "tracker-db-1"] },
    ],
    services: [
      {
        kind: "docker" as const,
        name: "tracker-db-1",
        state: "stopped" as const,
        since: null,
        system: false,
      },
      {
        kind: "docker" as const,
        name: "tracker-tracker-1",
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
        action({ kind: "compose", name: "tracker", action: "deploy" }),
        inventory,
      ),
    ).toEqual([
      { kind: "docker", name: "tracker-db-1" },
      { kind: "docker", name: "tracker-tracker-1" },
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
    for (const verb of ["upgrade", "install", "remove", "purge"] as const) {
      expect(retryOf(action({ kind: "apt", action: verb }))).toEqual({
        via: "packages",
      });
    }
    expect(retryOf(action({ kind: "apt", action: "hold" }))).toBeNull();
  });

  it("shows the last lines of an output first", () => {
    expect(lastLines("a\nb\nc\n", 2)).toEqual({ text: "b\nc", hidden: 1 });
    expect(lastLines("a", 5)).toEqual({ text: "a", hidden: 0 });
  });
});

describe("what an action says", () => {
  it("says what was done in a few words", () => {
    expect(historyText(action({}))).toBe("Restart resolver");
    expect(historyText(action({ action: "logs" }))).toBe(
      "Read logs of resolver",
    );
    expect(
      historyText(action({ kind: "compose", name: "panel", action: "purge" })),
    ).toBe("Delete panel permanently");
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

  it("names the shared Docker network it creates or deletes", () => {
    expect(
      historyText(
        action({
          kind: "bridge",
          name: "default-env_public",
          action: "create",
        }),
      ),
    ).toBe("Create network default-env_public");
    expect(
      historyText(
        action({ kind: "bridge", name: "apps-inner", action: "remove" }),
      ),
    ).toBe("Delete network apps-inner");
  });

  it("names the SELinux or AppArmor steps", () => {
    expect(
      historyText(
        action({ kind: "host", name: "confinement", action: "containers" }),
      ),
    ).toBe("Change whether SELinux confines containers");
    expect(
      historyText(
        action({ kind: "host", name: "confinement", action: "apply" }),
      ),
    ).toBe("Turn on SELinux or AppArmor");
  });

  it("names the Tailscale steps, and the credential they use", () => {
    expect(
      historyText(action({ kind: "vault", name: "tailscale", action: "save" })),
    ).toBe("Save Tailscale rules");
    expect(
      historyText(
        action({ kind: "host", name: "tailscale", action: "join" }),
        [],
        "vps-2",
      ),
    ).toBe("Sign in vps-2 to Tailscale");
    expect(
      historyText(
        action({ kind: "vault", name: "tailscale", action: "forget" }),
      ),
    ).toMatch(/ the Tailscale credential$/u);
    expect(
      historyText(
        action({ kind: "vault", name: "cloudflare", action: "forget" }),
      ),
    ).toMatch(/ the Cloudflare token$/u);
  });

  it("names the stack whose reach a move changed, with its server beside it", () => {
    const reach = action({ kind: "compose", name: "shop", action: "reach" });
    expect(historyText(reach)).toBe("Change shop's reach");
    expect(
      failedLine({ ...reach, status: "failed" }, { name: "server-2" }, 0).text,
    ).toBe("Change shop's reach on server-2");
  });
});

describe("an error line", () => {
  it("is the last line a failure printed", () => {
    expect(
      errorLine(
        "Container tracker-db-1 Starting\ndependency failed to start: container tracker-db-1 exited (1)\n\n",
      ),
    ).toBe("dependency failed to start: container tracker-db-1 exited (1)");
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
    expect(failedLine(failed, { name: "server-1", stacks }, later)).toEqual({
      text: "Restart pihole on server-1",
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
        name: "tracker",
        action: "deploy",
        deviceId: "d1",
        sentAt: "2026-10-24T02:24:00.000Z",
        finishedAt: "2026-10-24T02:24:30.000Z",
      }),
      { devices: [{ id: "d1", name: "Laptop" }] },
    );
    expect(line).toMatchObject({
      mark: "✓",
      text: "Deploy tracker",
      device: "Laptop",
      duration: "30s",
      failure: null,
      server: null,
    });
  });

  it("names the server only when asked", () => {
    expect(
      actionLine(failed, { nodeName: "server-1", showServer: true }).server,
    ).toBe("server-1");
    expect(actionLine(failed, { nodeName: "server-1" }).server).toBeNull();
  });
});
