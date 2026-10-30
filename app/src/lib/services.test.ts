import { describe, expect, it } from "vitest";

import type { ActionRecord, NodeRecord, ServicesResponse } from "../types";
import { historyText } from "./history";
import {
  autoRestartBlocker,
  actionText,
  displayName,
  durationText,
  groupByServer,
  isPending,
  outcomeText,
  runningText,
  pollServices,
  primaryAction,
  refreshPending,
  resting,
  serviceForCheck,
  STATE_LABEL,
  verb,
} from "./services";

const node = (id: string, name: string, agent = "0.1.0") =>
  ({ id, name, agent_version: agent }) as NodeRecord;

const action = (overrides: Partial<ActionRecord>): ActionRecord => ({
  id: "a1",
  batchId: "b1",
  position: 0,
  mode: "rolling",
  nodeId: "n1",
  kind: "docker",
  name: "resolver",
  action: "restart",
  status: "queued",
  requestedBy: "owner@example.test",
  requestedAt: "2026-09-29T10:00:00.000Z",
  deliverableAt: "2026-09-29T10:00:00.000Z",
  sentAt: null,
  finishedAt: null,
  exitCode: null,
  output: null,
  deviceId: null,
  ...overrides,
});

const data: ServicesResponse = {
  nodes: [
    {
      id: "n1",
      inventoryAt: null,
      refreshRequestedAt: null,
      stacks: [],
      trust: null,
      services: [
        {
          kind: "docker",
          name: "resolver",
          state: "running",
          since: null,
          system: false,
        },
        {
          kind: "systemd",
          name: "nginx.service",
          state: "running",
          since: null,
          system: false,
        },
        {
          kind: "systemd",
          name: "cron.service",
          state: "running",
          since: null,
          system: true,
        },
      ],
    },
    {
      id: "n2",
      inventoryAt: null,
      refreshRequestedAt: null,
      stacks: [],
      trust: null,
      services: [
        {
          kind: "docker",
          name: "resolver",
          state: "stopped",
          since: null,
          system: false,
        },
      ],
    },
    {
      id: "n3",
      inventoryAt: null,
      refreshRequestedAt: null,
      stacks: [],
      trust: null,
      services: [
        {
          kind: "docker",
          name: "resolver",
          state: "running",
          since: null,
          system: false,
        },
      ],
    },
  ],
  actions: [
    action({
      id: "old-action",
      nodeId: "n1",
      status: "done",
      requestedAt: "2026-09-29T09:00:00.000Z",
    }),
    action({
      id: "new-action",
      nodeId: "n1",
      status: "sent",
      requestedAt: "2026-09-29T10:00:00.000Z",
    }),
  ],
};

const nodes = [
  node("n1", "SERVER-1"),
  node("n2", "vps-sg"),
  node("n3", "zeta"),
];

describe("grouping services by server", () => {
  const names = (groups: ReturnType<typeof groupByServer>) =>
    groups.map((group) => [
      group.node.name,
      group.members.map((member) => member.entry.name),
    ]);
  const all = { showSystem: false, query: "", notRunning: false };

  it("lists each server's services, troubled servers first, without system units", () => {
    const groups = groupByServer(data, nodes, all);
    expect(names(groups)).toEqual([
      ["vps-sg", ["resolver"]],
      ["SERVER-1", ["nginx.service", "resolver"]],
      ["zeta", ["resolver"]],
    ]);
    expect(groups[1]!.members[1]!.action?.id).toBe("new-action");
  });

  it("puts a server's stopped services first", () => {
    const stopped: ServicesResponse = {
      ...data,
      nodes: [
        {
          ...data.nodes[0]!,
          services: data.nodes[0]!.services.map((entry) =>
            entry.name === "nginx.service"
              ? { ...entry, state: "failed" as const }
              : entry,
          ),
        },
      ],
    };
    expect(names(groupByServer(stopped, nodes, all))).toEqual([
      ["SERVER-1", ["nginx.service", "resolver"]],
    ]);
  });

  it("shows system units, searches services or servers and filters on request", () => {
    expect(
      names(groupByServer(data, nodes, { ...all, showSystem: true }))[1],
    ).toEqual(["SERVER-1", ["cron.service", "nginx.service", "resolver"]]);
    expect(
      names(groupByServer(data, nodes, { ...all, query: "NGINX" })),
    ).toEqual([["SERVER-1", ["nginx.service"]]]);
    expect(
      names(groupByServer(data, nodes, { ...all, query: "zeta" })),
    ).toEqual([["zeta", ["resolver"]]]);
    expect(
      names(groupByServer(data, nodes, { ...all, notRunning: true })),
    ).toEqual([["vps-sg", ["resolver"]]]);
  });

  it("knows which servers trust a device", () => {
    const trusted: ServicesResponse = {
      ...data,
      nodes: data.nodes.map((entry) =>
        entry.id === "n3"
          ? {
              ...entry,
              trust: {
                version: 1,
                core: ["0123456789abcdef"],
                access: ["0123456789abcdef"],
              },
            }
          : entry,
      ),
    };
    expect(
      groupByServer(trusted, nodes, all).map((group) => group.trusted),
    ).toEqual([false, false, true]);
  });

  it("offers the likely action first", () => {
    expect(primaryAction("running")).toBe("restart");
    expect(primaryAction("starting")).toBe("restart");
    expect(primaryAction("stopped")).toBe("start");
    expect(primaryAction("failed")).toBe("start");
  });
});

describe("action labels", () => {
  it("describes every stage", () => {
    expect(actionText(action({}), "SERVER-1")).toBe(
      "Waiting for SERVER-1 to restart",
    );
    expect(actionText(action({ deliverableAt: null }), "SERVER-1")).toBe(
      "Waiting for its turn to restart",
    );
    expect(
      actionText(action({ kind: "compose", action: "restore" }), "server-1"),
    ).toBe("Waiting for server-1 to restore");
    expect(actionText(action({ action: "autorestart" }), "server-1")).toBe(
      "Waiting for server-1 to turn on auto-restart",
    );
    expect(actionText(action({ status: "sent" }), "SERVER-1")).toBe(
      "Restarting…",
    );
    expect(
      actionText(
        action({ status: "done", finishedAt: "2026-09-29T10:01:05.000Z" }),
        "SERVER-1",
      ),
    ).toMatch(/^✓ Restarted \d\d:\d\d$/u);
    expect(
      actionText(action({ status: "failed", exitCode: 1 }), "SERVER-1"),
    ).toBe("Failed · Exit 1");
    expect(actionText(action({ status: "failed" }), "SERVER-1")).toBe("Failed");
    expect(actionText(action({ status: "expired" }), "SERVER-1")).toBe(
      "Expired",
    );
    expect(actionText(action({ status: "skipped" }), "SERVER-1")).toBe(
      "Skipped",
    );
    expect(
      actionText(action({ action: "stop", status: "sent" }), "SERVER-1"),
    ).toBe("Stopping…");
  });

  it("measures how long a finished action took", () => {
    expect(
      durationText(
        action({
          sentAt: "2026-09-29T10:01:02.000Z",
          finishedAt: "2026-09-29T10:01:05.200Z",
        }),
      ),
    ).toBe("3s");
    expect(durationText(action({}))).toBeNull();
  });
});

describe("polling, checks and outcomes", () => {
  it("polls every 5 seconds while something is in flight", () => {
    const now = Date.parse("2026-09-29T10:00:30.000Z");
    expect(pollServices(data, now)).toBe(5_000);
    const quiet = { ...data, actions: [action({ status: "done" })] };
    expect(pollServices(quiet, now)).toBeGreaterThan(5_000);
    const reading = {
      ...data,
      actions: [action({ action: "logs", status: "sent" })],
    };
    expect(pollServices(reading, now)).toBeGreaterThan(5_000);
    const refreshing = (at: string) => ({
      ...quiet,
      nodes: [{ ...data.nodes[0]!, refreshRequestedAt: at }],
    });
    expect(pollServices(refreshing("2026-09-29T09:59:00.000Z"), now)).toBe(
      5_000,
    );
    expect(
      pollServices(refreshing("2026-09-29T09:57:00.000Z"), now),
    ).toBeGreaterThan(5_000);
    expect(pollServices(undefined, now)).toBeGreaterThan(5_000);
  });

  it("stops waiting for a refresh after three minutes", () => {
    const now = Date.parse("2026-09-29T10:00:30.000Z");
    expect(
      refreshPending({ refreshRequestedAt: "2026-09-29T09:59:00.000Z" }, now),
    ).toBe(true);
    expect(
      refreshPending({ refreshRequestedAt: "2026-09-29T09:57:00.000Z" }, now),
    ).toBe(false);
    expect(refreshPending({ refreshRequestedAt: null }, now)).toBe(false);
  });

  it("finds the unit behind a SERVICE check", () => {
    expect(
      serviceForCheck({ kind: "SERVICE", target: "nginx", node_id: "n1" }, data)
        ?.name,
    ).toBe("nginx.service");
    expect(
      serviceForCheck(
        { kind: "SERVICE", target: "nginx.service", node_id: "n1" },
        data,
      )?.name,
    ).toBe("nginx.service");
    expect(
      serviceForCheck({ kind: "HTTP", target: "nginx", node_id: "n1" }, data),
    ).toBeNull();
    expect(
      serviceForCheck(
        { kind: "SERVICE", target: "nginx", node_id: "n2" },
        data,
      ),
    ).toBeNull();
  });

  it("finds the container behind a CONTAINER check by its exact name", () => {
    expect(
      serviceForCheck(
        { kind: "CONTAINER", target: "resolver", node_id: "n2" },
        data,
      ),
    ).toMatchObject({ kind: "docker", name: "resolver", state: "stopped" });
    expect(
      serviceForCheck(
        { kind: "CONTAINER", target: "nginx", node_id: "n1" },
        data,
      ),
    ).toBeNull();
  });

  it("says what runs and how it ended, in words people read", () => {
    expect(runningText(action({ status: "sent" }), "SERVER-1")).toBe(
      "Restarting resolver on SERVER-1",
    );
    expect(runningText(action({ status: "sent" }))).toBe("Restarting resolver");
    expect(
      runningText(
        action({ kind: "host", name: "server", action: "reboot" }),
        "SERVER-1",
      ),
    ).toBe("Restarting SERVER-1");
    expect(isPending(action({ status: "sent" }))).toBe(true);
    expect(outcomeText(action({ status: "done" }), "SERVER-1")).toEqual({
      ok: true,
      text: "resolver restarted on SERVER-1",
    });
    expect(
      outcomeText(
        action({
          status: "failed",
          exitCode: 1,
          kind: "systemd",
          name: "nginx.service",
        }),
        "SERVER-1",
      ),
    ).toEqual({
      ok: false,
      text: "Could not restart nginx on SERVER-1 (exit 1)",
    });
    expect(outcomeText(action({ status: "cancelled" }), "SERVER-1")).toBeNull();
  });
});

describe("announcements and bulk order", () => {
  it("names a server restart", () => {
    const reboot = action({ kind: "host", name: "server", action: "reboot" });
    expect(`${verb("reboot")} ${displayName("host", "server")}`).toBe(
      "Restart server",
    );
    expect(actionText({ ...reboot, status: "sent" }, "SERVER-1")).toBe(
      "Restarting…",
    );
    expect(outcomeText({ ...reboot, status: "done" }, "SERVER-1")).toEqual({
      ok: true,
      text: "SERVER-1 restarted",
    });
  });
});

describe("words for agent 0.4.0 commands", () => {
  const unit = (overrides: Partial<ActionRecord>) =>
    action({ kind: "systemd", name: "nginx.service", ...overrides });

  it("reads an automatic restart and the switch plainly", () => {
    expect(
      outcomeText(unit({ action: "heal", status: "done" }), "server-1"),
    ).toEqual({ ok: true, text: "nginx restarted automatically on server-1" });
    expect(
      runningText(unit({ action: "heal", status: "sent" }), "server-1"),
    ).toBe("Restarting nginx on server-1");
    expect(
      outcomeText(unit({ action: "autorestart", status: "done" }), "server-1"),
    ).toEqual({
      ok: true,
      text: "nginx now restarts automatically on server-1",
    });
    expect(
      outcomeText(unit({ action: "manual", status: "done" }), "server-1"),
    ).toEqual({
      ok: true,
      text: "nginx no longer restarts automatically on server-1",
    });
  });

  it("names a permanent delete and a restore", () => {
    expect(
      outcomeText(
        action({
          kind: "compose",
          name: "panel",
          action: "purge",
          status: "failed",
          exitCode: 1,
        }),
        "server-1",
      ),
    ).toEqual({
      ok: false,
      text: "Could not delete panel permanently on server-1 (exit 1)",
    });
    expect(
      outcomeText(
        action({
          kind: "compose",
          name: "panel",
          action: "restore",
          status: "done",
        }),
        "server-1",
      ),
    ).toEqual({ ok: true, text: "panel restored on server-1" });
  });
});

describe("restart automatically", () => {
  const check = {
    kind: "SERVICE" as const,
    target: "nginx",
    node_id: "n1",
  };
  const entry = (
    overrides: Partial<ServicesResponse["nodes"][number]> = {},
  ) => ({
    ...data,
    nodes: [
      {
        ...data.nodes[0]!,
        services: [
          {
            kind: "systemd" as const,
            name: "nginx.service",
            state: "running" as const,
            since: null,
            system: false,
          },
        ],
        trust: {
          version: 1,
          core: ["0123456789abcdef"],
          access: ["0123456789abcdef"],
        },
        ...overrides,
      },
    ],
  });

  it("says why it cannot be turned on", () => {
    expect(
      autoRestartBlocker(check, node("n1", "server-1", "0.7.0"), entry()),
    ).toBeNull();
    expect(
      autoRestartBlocker(check, node("n1", "server-1", "0.4.1"), entry()),
    ).toBe("Needs agent 0.7.0");
    expect(autoRestartBlocker(check, undefined, entry())).toBe(
      "Server Not Found",
    );
    expect(
      autoRestartBlocker(
        check,
        { ...node("n1", "server-1", "0.7.0"), agent_version: null },
        entry(),
      ),
    ).toBe("Waiting for First Report");
    expect(
      autoRestartBlocker(
        { ...check, target: "ssh" },
        node("n1", "server-1", "0.7.0"),
        entry(),
      ),
    ).toBe("Krynodes never restarts this unit");
    expect(
      autoRestartBlocker(
        check,
        node("n1", "server-1", "0.7.0"),
        entry({ services: [] }),
      ),
    ).toBe("The unit is not on this server");
    expect(
      autoRestartBlocker(
        check,
        node("n1", "server-1", "0.7.0"),
        entry({ trust: null }),
      ),
    ).toBe("Not Trusted Yet");
  });
});

describe("words for private network work", () => {
  it("says what a network job does while it runs", () => {
    const job = (verb: ActionRecord["action"]) =>
      runningText(
        action({ kind: "network", name: "kry0", action: verb, status: "sent" }),
        "vps-2",
      );
    expect(job("prepare")).toBe(
      "Getting ready for the private network on vps-2",
    );
    expect(job("unprepare")).toBe(
      "Undoing the preparation for the private network on vps-2",
    );
    expect(job("rekey")).toBe(
      "Making a new key for the private network on vps-2",
    );
    expect(job("test")).toBe("Testing the private network on vps-2");
  });
});

describe("words for host work", () => {
  it("names Docker and a protection, and keeps the server short", () => {
    const install = action({ kind: "host", name: "docker", action: "install" });
    expect(historyText(install)).toBe("Install Docker");
    expect(runningText({ ...install, status: "sent" }, "server-1")).toBe(
      "Installing Docker on server-1",
    );
    expect(outcomeText({ ...install, status: "done" }, "server-1")).toEqual({
      ok: true,
      text: "Docker installed on server-1",
    });
    const recipe = action({ kind: "host", name: "fail2ban", action: "apply" });
    expect(runningText({ ...recipe, status: "sent" }, "server-1")).toBe(
      "Turning on block repeated login failures on server-1",
    );
    const reboot = action({
      kind: "host",
      name: "server",
      action: "reboot",
      status: "sent",
    });
    expect(runningText(reboot, "server-1")).toBe("Restarting server-1");
  });
});

describe("words for removing Krynodes and moving a stack into it", () => {
  const removal = (status: ActionRecord["status"]) =>
    action({
      kind: "host",
      name: "server",
      action: "uninstall",
      status,
      exitCode: null,
    });
  it("keeps the name Krynodes and says where", () => {
    expect(actionText(removal("queued"), "server-1")).toBe(
      "Waiting for server-1 to remove Krynodes",
    );
    expect(runningText(removal("sent"), "server-1")).toBe(
      "Removing Krynodes from server-1",
    );
    expect(outcomeText(removal("done"), "server-1")).toEqual({
      ok: true,
      text: "Krynodes removed from server-1",
    });
    expect(outcomeText(removal("failed"), "server-1")).toEqual({
      ok: false,
      text: "Could not remove Krynodes from server-1 (failed)",
    });
    expect(
      actionText(
        action({
          kind: "compose",
          name: "panel",
          action: "adopt",
          status: "queued",
        }),
        "server-1",
      ),
    ).toBe("Waiting for server-1 to move into Krynodes");
  });
});

describe("states a unit rests in", () => {
  it("labels boot and unneeded units and never counts them as trouble", () => {
    expect(STATE_LABEL.boot).toBe("Ran at Boot");
    expect(STATE_LABEL.unneeded).toBe("Not Needed Here");
    expect(STATE_LABEL.stopped).toBe("Stopped");
    expect(resting("boot") && resting("unneeded") && !resting("stopped")).toBe(
      true,
    );
    expect(primaryAction("boot")).toBe("start");
    const units: ServicesResponse = {
      nodes: [
        {
          ...data.nodes[0]!,
          services: (["boot", "running", "stopped", "unneeded"] as const).map(
            (state) => ({
              kind: "systemd" as const,
              name: `${state}.service`,
              state,
              since: null,
              system: false,
            }),
          ),
        },
      ],
      actions: [],
    };
    const names = (notRunning: boolean) =>
      groupByServer(units, nodes, {
        showSystem: true,
        query: "",
        notRunning,
      })[0]!.members.map((member) => member.entry.name);
    expect(names(false)).toEqual([
      "stopped.service",
      "running.service",
      "boot.service",
      "unneeded.service",
    ]);
    expect(names(true)).toEqual(["stopped.service"]);
  });

  it("words the admin user command and the new protection", () => {
    expect(
      historyText(
        action({ kind: "host", name: "server", action: "admin" }),
        [],
        "server-2",
      ),
    ).toBe("Get an admin user command for server-2");
    expect(displayName("host", "no-root-login")).toBe("no root login");
  });
});
