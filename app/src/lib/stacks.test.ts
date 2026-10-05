import { describe, expect, it } from "vitest";

import type {
  DockerState,
  NodeRecord,
  ServicesResponse,
  StackEntry,
} from "../types";
import { actionText, outcomeText } from "./services";
import {
  containersOf,
  daysLeft,
  deployBlocker,
  groupStacks,
  newStackBlocker,
  ownFolder,
  removedStacks,
  stackCommands,
  stackNameProblem,
} from "./stacks";

const node = (id: string, name: string, agent = "0.3.1") =>
  ({
    id,
    name,
    agent_version: agent,
    enrolled_at: "2026-09-29 09:00:00",
    disabled_at: null,
    last_seen_at: "2026-09-29 09:59:30",
    interval_seconds: 60,
  }) as NodeRecord;

const stack = (
  project: string,
  overrides: Partial<StackEntry> = {},
): StackEntry => ({
  project,
  directory: `/opt/${project}`,
  running: 2,
  total: 2,
  compose: true,
  rollback: false,
  ...overrides,
});

const trusted = {
  version: 1,
  core: ["0123456789abcdef"],
  access: ["0123456789abcdef"],
};

const data: ServicesResponse = {
  nodes: [
    {
      id: "n1",
      inventoryAt: null,
      refreshRequestedAt: null,
      services: [
        {
          kind: "docker",
          name: "listmonk_app",
          state: "running",
          since: null,
          system: false,
        },
        {
          kind: "docker",
          name: "listmonk-db-1",
          state: "running",
          since: null,
          system: false,
        },
        {
          kind: "docker",
          name: "adguard",
          state: "running",
          since: null,
          system: false,
        },
      ],
      stacks: [
        stack("listmonk", { rollback: true }),
        stack("shop", { running: 1 }),
      ],
      trust: trusted,
    },
    {
      id: "n2",
      inventoryAt: null,
      refreshRequestedAt: null,
      services: [],
      stacks: [stack("listmonk")],
      trust: null,
    },
  ],
  actions: [],
};

const nodes = [node("n1", "Callisto"), node("n2", "Pivox")];

describe("stacks", () => {
  it("groups one project across servers and puts unhealthy stacks first", () => {
    const groups = groupStacks(data, nodes, "");
    expect(groups.map((group) => group.project)).toEqual(["shop", "listmonk"]);
    expect(groups[1]!.members.map((member) => member.node.name)).toEqual([
      "Callisto",
      "Pivox",
    ]);
    expect(
      groupStacks(data, nodes, "PIVOX").map((group) => group.project),
    ).toEqual(["listmonk"]);
  });

  it("keeps reading logs out of a stack's last action", () => {
    const entry = (id: string, action: "deploy" | "logs") => ({
      id,
      batchId: id,
      position: 0,
      mode: "rolling" as const,
      nodeId: "n1",
      kind: "compose" as const,
      name: "listmonk",
      action,
      status: "done" as const,
      requestedBy: "owner@example.test",
      requestedAt: "2026-09-29T09:00:00.000Z",
      deliverableAt: "2026-09-29T09:00:00.000Z",
      deviceId: null,
      sentAt: null,
      finishedAt: null,
      exitCode: null,
      output: null,
    });
    const groups = groupStacks(
      { ...data, actions: [entry("a1", "deploy"), entry("a2", "logs")] },
      nodes,
      "",
    );
    const listmonk = groups.find((group) => group.project === "listmonk")!;
    expect(listmonk.members[0]!.action?.id).toBe("a1");
  });

  it("offers rollback only when a version is kept", () => {
    const [, listmonk] = groupStacks(data, nodes, "");
    expect(listmonk!.members.map((member) => member.stack.rollback)).toEqual([
      true,
      false,
    ]);
  });

  it("names why a stack cannot deploy yet", () => {
    const [, listmonk] = groupStacks(data, nodes, "");
    expect(deployBlocker(listmonk!.members[0]!)).toBeNull();
    expect(deployBlocker(listmonk!.members[1]!)).toBe("Not trusted yet");
    expect(
      deployBlocker({
        ...listmonk!.members[0]!,
        node: node("n1", "Callisto", "0.3.0"),
      }),
    ).toBe("Needs agent 0.3.1");
    expect(
      deployBlocker({
        ...listmonk!.members[0]!,
        stack: stack("listmonk", { compose: false }),
      }),
    ).toBe("Docker Compose is not installed");
  });

  it("lists a stack's containers", () => {
    expect(
      containersOf("listmonk", data.nodes[0]!.services).map(
        (entry) => entry.name,
      ),
    ).toEqual(["listmonk-db-1", "listmonk_app"]);
  });

  it("words deploys and rollbacks", () => {
    const deploy = {
      id: "a1",
      batchId: "b1",
      position: 0,
      mode: "rolling" as const,
      nodeId: "n1",
      kind: "compose" as const,
      name: "listmonk",
      action: "deploy" as const,
      status: "sent" as const,
      requestedBy: "owner@example.test",
      requestedAt: "2026-09-29T10:00:00.000Z",
      deliverableAt: "2026-09-29T10:00:00.000Z",
      sentAt: "2026-09-29T10:00:30.000Z",
      finishedAt: null,
      exitCode: null,
      output: null,
      deviceId: null,
    };
    expect(actionText(deploy, "Callisto")).toBe("Deploying…");
    expect(
      outcomeText(
        { ...deploy, status: "done", finishedAt: "2026-09-29T10:03:00.000Z" },
        "Callisto",
      ),
    ).toEqual({ ok: true, text: "listmonk deployed on Callisto" });
    expect(
      outcomeText(
        {
          ...deploy,
          action: "rollback",
          status: "done",
          finishedAt: "2026-09-29T10:03:00.000Z",
        },
        "Callisto",
      ),
    ).toEqual({ ok: true, text: "listmonk rolled back on Callisto" });
  });
});

describe("stack commands of agent 0.4.0", () => {
  const member = (running: number, total: number, agent = "0.4.0") => ({
    node: node("n1", "pivox", agent),
    stack: stack("kuma", { running, total }),
    trusted: true,
    trust: trusted,
    action: null,
  });

  it("offers start, stop and restart by what runs, and both removes", () => {
    expect(stackCommands(member(2, 2))).toEqual([
      "restart",
      "stop",
      "remove",
      "purge",
    ]);
    expect(stackCommands(member(1, 2))).toEqual([
      "start",
      "restart",
      "stop",
      "remove",
      "purge",
    ]);
    expect(stackCommands(member(0, 2))).toEqual(["start", "remove", "purge"]);
    expect(stackCommands(member(2, 2, "0.3.5"))).toEqual([]);
    expect(stackCommands({ ...member(2, 2), trusted: false })).toEqual([]);
  });

  it("says why a server cannot take a new stack", () => {
    const entry = (docker: DockerState | null) => ({
      id: "n1",
      inventoryAt: null,
      refreshRequestedAt: null,
      services: [],
      stacks: [],
      trust: trusted,
      docker,
    });
    expect(
      newStackBlocker(node("n1", "pivox", "0.4.0"), entry("ready")),
    ).toBeNull();
    expect(newStackBlocker(node("n1", "pivox", "0.3.5"), entry("ready"))).toBe(
      "Needs agent 0.4.0",
    );
    expect(
      newStackBlocker(node("n1", "pivox", "0.4.0"), entry("missing")),
    ).toBe("No Docker");
    expect(
      newStackBlocker(node("n1", "pivox", "0.4.0"), entry("no-compose")),
    ).toBe("Docker without Compose");
    expect(newStackBlocker(node("n1", "pivox", "0.4.0"), entry(null))).toBe(
      "Docker not reported yet",
    );
    expect(
      newStackBlocker(node("n1", "pivox", "0.4.0"), {
        ...entry("ready"),
        trust: null,
      }),
    ).toBe("Not trusted yet");
  });

  it("checks a stack name the way the server does", () => {
    expect(stackNameProblem("uptime-kuma", [])).toBeNull();
    expect(stackNameProblem("", [])).toBe("Give the stack a name.");
    expect(stackNameProblem("Kuma", [])).toBe(
      "Use lowercase letters, digits, - and _, starting with a letter or digit.",
    );
    expect(stackNameProblem("kuma", ["kuma"])).toBe(
      "This server already runs a stack named kuma.",
    );
    expect(stackNameProblem("kuma", [], ["kuma"])).toBe(
      "A stack named kuma waits in Removed. Restore it or delete it permanently first.",
    );
  });
});

describe("removed stacks", () => {
  const removed = (
    project: string,
    removedAt: string,
    directory = `/var/lib/kry-exec/compose/${project}`,
  ) => ({ project, directory, removedAt });
  const bin: ServicesResponse = {
    nodes: [
      {
        ...data.nodes[0]!,
        docker: "ready",
        removed: [
          removed("kuma", "2026-10-04T10:00:00.000Z"),
          removed("shop", "2026-10-05T08:00:00.000Z", "/home/alice/shop"),
        ],
      },
      {
        ...data.nodes[1]!,
        removed: [removed("ghost", "2026-10-03T10:00:00.000Z")],
      },
    ],
    actions: [
      {
        id: "a1",
        batchId: "b1",
        position: 0,
        mode: "parallel",
        nodeId: "n1",
        kind: "compose",
        name: "kuma",
        action: "restore",
        status: "queued",
        requestedBy: "owner@example.test",
        requestedAt: "2026-10-05T09:00:00.000Z",
        deliverableAt: null,
        sentAt: null,
        finishedAt: null,
        exitCode: null,
        output: null,
        deviceId: null,
      },
    ],
  };
  const fleet = [node("n1", "Callisto", "0.4.0"), node("n2", "Pivox", "0.4.0")];

  it("lists the newest first with what blocks a restore", () => {
    const list = removedStacks(bin, fleet, "");
    expect(
      list.map((item) => [item.project, item.node.name, item.blocker]),
    ).toEqual([
      ["shop", "Callisto", null],
      ["kuma", "Callisto", null],
      ["ghost", "Pivox", "Docker not reported yet"],
    ]);
    expect(list[1]!.action?.action).toBe("restore");
    expect(
      removedStacks(bin, fleet, "pivox").map((item) => item.project),
    ).toEqual(["ghost"]);
    expect(
      removedStacks(bin, fleet, "sho").map((item) => item.project),
    ).toEqual(["shop"]);
  });

  it("counts the days until it is deleted for good", () => {
    const at = Date.parse("2026-10-05T10:00:00.000Z");
    expect(daysLeft("2026-10-05T10:00:00.000Z", at)).toBe(7);
    expect(daysLeft("2026-10-04T09:00:00.000Z", at)).toBe(6);
    expect(daysLeft("2026-09-28T11:00:00.000Z", at)).toBe(1);
    expect(daysLeft("2026-09-20T10:00:00.000Z", at)).toBe(0);
  });

  it("knows which folders Krynodes made", () => {
    expect(ownFolder("/var/lib/kry-exec/compose/kuma")).toBe(true);
    expect(ownFolder("/var/lib/kry-exec/compose/kuma/sub")).toBe(false);
    expect(ownFolder("/home/alice/shop")).toBe(false);
  });
});
