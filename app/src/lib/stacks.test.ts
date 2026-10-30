import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  AttentionItem,
  DockerState,
  NodeRecord,
  ServicesResponse,
  StackEntry,
} from "../types";
import { actionText, outcomeText } from "./services";
import {
  containerNameProblem,
  containerNames,
  containersOf,
  daysLeft,
  deployBlocker,
  foldedText,
  groupStacks,
  moveBlocker,
  moveClash,
  moveConfirmed,
  nameOwner,
  newStackBlocker,
  ownFolder,
  removedStacks,
  parseHostPorts,
  serverBoxes,
  serverLists,
  servicesAttention,
  stackCommands,
  stackNameProblem,
  stackOf,
  stackSlug,
  stackState,
  sameTitle,
} from "./stacks";

describe("ports a Contained stack may reach on its server", () => {
  it("reads a list once each, in order", () => {
    expect(parseHostPorts(" 3000/tcp, 53/udp,3000/tcp ")).toEqual({
      ports: ["3000/tcp", "53/udp"],
      problem: null,
    });
    expect(parseHostPorts("")).toEqual({ ports: [], problem: null });
  });

  it("names what it cannot take", () => {
    expect(parseHostPorts("3000").problem).toBe(
      "3000 is not a port written as number/tcp.",
    );
    expect(parseHostPorts("70000/tcp").problem).toBe(
      "70000/tcp is not a port between 1 and 65535.",
    );
    expect(parseHostPorts("0/tcp").problem).toBe(
      "0/tcp is not a port between 1 and 65535.",
    );
    expect(
      parseHostPorts(
        Array.from({ length: 17 }, (_, index) => `${index + 1}/tcp`).join(","),
      ).problem,
    ).toBe("A stack may reach at most 16 ports on the server.");
  });
});

const node = (id: string, name: string, agent = "0.7.0") =>
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
          name: "resolver",
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

const nodes = [node("n1", "Server A"), node("n2", "Server B")];

describe("stacks", () => {
  it("groups one project across servers and puts unhealthy stacks first", () => {
    const groups = groupStacks(data, nodes, "");
    expect(groups.map((group) => group.project)).toEqual(["shop", "listmonk"]);
    expect(groups[1]!.members.map((member) => member.node.name)).toEqual([
      "Server A",
      "Server B",
    ]);
    expect(
      groupStacks(data, nodes, "SERVER B").map((group) => group.project),
    ).toEqual(["listmonk"]);
  });

  it("keeps reading logs or the compose file out of a stack's last action", () => {
    const entry = (
      id: string,
      action: "deploy" | "logs" | "read",
      status: "done" | "queued" = "done",
    ) => ({
      id,
      batchId: id,
      position: 0,
      mode: "rolling" as const,
      nodeId: "n1",
      kind: "compose" as const,
      name: "listmonk",
      action,
      status,
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
      {
        ...data,
        actions: [
          entry("a1", "deploy"),
          entry("a2", "logs"),
          entry("a3", "read", "queued"),
        ],
      },
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
    expect(deployBlocker(listmonk!.members[1]!)).toBe("Not Trusted Yet");
    expect(
      deployBlocker({
        ...listmonk!.members[0]!,
        node: node("n1", "Server A", "0.4.1"),
      }),
    ).toBe("Needs agent 0.7.0");
    expect(
      deployBlocker({
        ...listmonk!.members[0]!,
        node: { ...node("n1", "Server A", "0.7.0"), agent_version: null },
      }),
    ).toBe("Waiting for First Report");
    expect(
      deployBlocker({
        ...listmonk!.members[0]!,
        stack: stack("listmonk", { compose: false }),
      }),
    ).toBe("Docker Compose is not installed");
  });

  it("lists a stack's containers", () => {
    expect(
      containersOf({ project: "listmonk" }, data.nodes[0]!.services).map(
        (entry) => entry.name,
      ),
    ).toEqual(["listmonk-db-1", "listmonk_app"]);
  });

  it("takes a stack's containers from the agent when it names them", () => {
    const services = data.nodes[0]!.services;
    expect(
      containersOf(
        { project: "listmonk", containers: ["listmonk_app"] },
        services,
      ).map((entry) => entry.name),
    ).toEqual(["listmonk_app"]);
    expect(
      stackOf(
        [{ project: "listmonk", containers: ["listmonk_app"] }],
        "listmonk-db-1",
      ),
    ).toBeUndefined();
    expect(stackOf([{ project: "listmonk" }], "listmonk-db-1")).toBe(
      "listmonk",
    );
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
    expect(actionText(deploy, "Server A")).toBe("Deploying…");
    expect(
      outcomeText(
        { ...deploy, status: "done", finishedAt: "2026-09-29T10:03:00.000Z" },
        "Server A",
      ),
    ).toEqual({ ok: true, text: "listmonk deployed on Server A" });
    expect(
      outcomeText(
        {
          ...deploy,
          action: "rollback",
          status: "done",
          finishedAt: "2026-09-29T10:03:00.000Z",
        },
        "Server A",
      ),
    ).toEqual({ ok: true, text: "listmonk rolled back on Server A" });
  });
});

describe("stack commands", () => {
  const member = (running: number, total: number, agent = "0.7.0") => ({
    node: node("n1", "server-1", agent),
    stack: stack("panel", { running, total }),
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
    expect(stackCommands(member(2, 2, "0.4.1"))).toEqual([]);
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
      newStackBlocker(node("n1", "server-1", "0.7.0"), entry("ready")),
    ).toBeNull();
    expect(
      newStackBlocker(node("n1", "server-1", "0.4.1"), entry("ready")),
    ).toBe("Needs agent 0.7.0");
    expect(
      newStackBlocker(
        { ...node("n1", "server-1", "0.7.0"), agent_version: null },
        entry("ready"),
      ),
    ).toBe("Waiting for First Report");
    expect(
      newStackBlocker(node("n1", "server-1", "0.7.0"), entry("missing")),
    ).toBe("No Docker");
    expect(
      newStackBlocker(node("n1", "server-1", "0.7.0"), entry("no-compose")),
    ).toBe("Docker without Compose");
    expect(newStackBlocker(node("n1", "server-1", "0.7.0"), entry(null))).toBe(
      "Docker Not Reported Yet",
    );
    expect(
      newStackBlocker(node("n1", "server-1", "0.7.0"), {
        ...entry("ready"),
        trust: null,
      }),
    ).toBe("Not Trusted Yet");
  });

  it("checks a stack name the way the server does", () => {
    expect(stackNameProblem("panel", [])).toBeNull();
    expect(stackNameProblem("Resolver", [])).toBeNull();
    expect(stackNameProblem("", [])).toBe("Give the stack a name.");
    expect(stackNameProblem("!!!", [])).toBe(
      "Use at least one letter or digit.",
    );
    expect(stackNameProblem("k".repeat(65), [])).toBe(
      "Keep the name to 64 characters.",
    );
    expect(stackNameProblem("Panel", ["panel"])).toBe(
      "This server already runs a stack named panel.",
    );
    expect(stackNameProblem("panel", [], ["panel"])).toBe(
      "A stack named panel waits in Removed. Restore it or delete it permanently first.",
    );
  });
});

describe("stack and container names", () => {
  const one = "services:\n  resolver:\n    image: example/resolver\n";
  const three =
    "services:\n  broker:\n    image: redis:7\n  db:\n    image: postgres:17\n  webserver:\n    image: paperless\n";

  it("turns a display name into the folder and project name", () => {
    expect(stackSlug("Resolver")).toBe("resolver");
    expect(stackSlug("  Uptime   Panel! ")).toBe("uptime-panel");
    expect(stackSlug("my_app")).toBe("my_app");
    expect(stackSlug("Pi-hole · DNS")).toBe("pi-hole-dns");
    expect(stackSlug("!!!")).toBe("");
    const long = stackSlug(`${"a".repeat(62)} b`);
    expect(long.length).toBeLessThanOrEqual(63);
    expect(long.endsWith("-")).toBe(false);
  });

  it("names one container after the stack and several after their services", () => {
    expect(containerNames(one, "resolver")).toEqual([
      { service: "resolver", suggested: "resolver", value: "resolver" },
    ]);
    expect(containerNames(three, "paperless").map((row) => row.value)).toEqual([
      "paperless-broker",
      "paperless-db",
      "paperless-webserver",
    ]);
    expect(containerNames("", "paperless")).toEqual([]);
    expect(containerNames("services: [", "paperless")).toEqual([]);
  });

  it("starts from the file's own name, then the saved one, then what was typed", () => {
    const own = `${three}    container_name: paperless\n`;
    expect(containerNames(own, "paperless")[2]!.value).toBe("paperless");
    expect(
      containerNames(three, "paperless", { db: "postgres" })[1]!.value,
    ).toBe("postgres");
    const typed = containerNames(
      three,
      "paperless",
      {},
      {
        db: "pg",
        broker: "",
      },
    );
    expect(typed.map((row) => row.value)).toEqual([
      "paperless-broker",
      "pg",
      "paperless-webserver",
    ]);
  });

  it("keeps a name typed over the file's own until the file's own changes", () => {
    const own =
      "services:\n  web:\n    image: nginx\n    container_name: site\n";
    const saved = { web: "blog-web" };
    expect(containerNames(own, "blog", saved, {}, own)[0]!.value).toBe(
      "blog-web",
    );
    expect(
      containerNames(own.replace("site", "landing"), "blog", saved, {}, own)[0]!
        .value,
    ).toBe("landing");
    expect(
      containerNames(
        "services:\n  web:\n    image: nginx\n",
        "blog",
        saved,
        {},
        own,
      )[0]!.value,
    ).toBe("blog");
  });

  it("leaves a service with copies to Docker's numbers", () => {
    const copies = three.replace(
      "image: paperless\n",
      "image: paperless\n    deploy:\n      replicas: 2\n",
    );
    expect(
      containerNames(copies, "paperless").map((row) => row.service),
    ).toEqual(["broker", "db"]);
  });

  it("says what is wrong with a container name", () => {
    const rows = containerNames(
      three,
      "paperless",
      {},
      {
        broker: "redis",
        db: "redis",
        webserver: "my web",
      },
    );
    expect(containerNameProblem(rows, 2, () => null)).toBe(
      "Use letters, digits, dashes, dots and underscores, starting with a letter or digit.",
    );
    const fine = containerNames(three, "paperless");
    const free = () => null;
    expect(containerNameProblem(rows, 0, free)).toBe(
      "Another container in this stack has this name.",
    );
    expect(containerNameProblem(fine, 0, free)).toBeNull();
    expect(
      containerNameProblem(fine, 1, (name) =>
        name === "paperless-db" ? "taken" : null,
      ),
    ).toBe("taken");
  });

  const serverTwo = {
    stacks: [
      stack("monitoring", {
        title: "Monitoring",
        containers: ["status"],
        services: ["panel", "db"],
      }),
      stack("blog", { services: ["web"] }),
      stack("paperless", { containers: ["paperless-db"], services: ["db"] }),
    ],
    services: [
      {
        kind: "docker" as const,
        name: "status",
        state: "running" as const,
        since: null,
        system: false,
      },
      {
        kind: "docker" as const,
        name: "blog-web-1",
        state: "running" as const,
        since: null,
        system: false,
      },
      {
        kind: "docker" as const,
        name: "portainer",
        state: "running" as const,
        since: null,
        system: false,
      },
    ],
  };

  it("names the stack that owns a container name on the server", () => {
    const owner = nameOwner(serverTwo, "paperless", "server-2");
    expect(owner("panel")).toBe(
      "panel is a service of Monitoring on server-2.",
    );
    expect(owner("status")).toBe(
      "status is a container of Monitoring on server-2.",
    );
    expect(owner("blog-web-1")).toBe(
      "blog-web-1 is a container of blog on server-2.",
    );
    expect(owner("portainer")).toBe(
      "server-2 already runs a container named portainer.",
    );
    expect(owner("web.monitoring")).toBe(
      "Names ending in .monitoring are kept for the services of Monitoring.",
    );
    expect(owner("db.paperless")).toBe(
      "Names ending in .paperless are kept for the services of this stack.",
    );
    expect(owner("paperless-db")).toBeNull();
    expect(owner("db")).toBe("db is a service of Monitoring on server-2.");
    expect(
      nameOwner(undefined, "paperless", "server-2")("anything"),
    ).toBeNull();
  });

  it("refuses a display name another stack on the server has", () => {
    expect(sameTitle("monitoring", serverTwo.stacks, "server-2")).toBe(
      "Another stack on server-2 is called Monitoring.",
    );
    expect(sameTitle("Blog", serverTwo.stacks, "server-2")).toBe(
      "Another stack on server-2 is called blog.",
    );
    expect(
      sameTitle("Monitoring", serverTwo.stacks, "server-2", "monitoring"),
    ).toBeNull();
    expect(sameTitle("Status", serverTwo.stacks, "server-2")).toBeNull();
  });

  it("says why a server cannot take a stack that moves", () => {
    const moving = stack("panel", {
      title: "Panel",
      names: { web: "panel" },
    });
    expect(
      moveClash(moving, { ...serverTwo, leftovers: ["panel"] }, "server-2"),
    ).toBe(
      "Files left from an earlier panel are still on server-2. Delete them there first.",
    );
    expect(moveClash(moving, serverTwo, "server-2")).toBe(
      "panel is a service of Monitoring on server-2.",
    );
    expect(
      moveClash(
        { ...moving, names: {} },
        {
          ...serverTwo,
          stacks: [...serverTwo.stacks, stack("panel-2", { title: "Panel" })],
        },
        "server-2",
      ),
    ).toBe("Another stack on server-2 is called Panel.");
    expect(
      moveClash({ ...moving, names: {} }, serverTwo, "server-2"),
    ).toBeNull();
    expect(moveClash(moving, undefined, "server-2")).toBeNull();
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
          removed("panel", "2026-10-04T10:00:00.000Z"),
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
        name: "panel",
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
  const fleet = [node("n1", "Server A"), node("n2", "Server B")];

  it("lists the newest first with what blocks a restore", () => {
    const list = removedStacks(bin, fleet, "");
    expect(
      list.map((item) => [item.project, item.node.name, item.blocker]),
    ).toEqual([
      ["shop", "Server A", null],
      ["panel", "Server A", null],
      ["ghost", "Server B", "Docker Not Reported Yet"],
    ]);
    expect(list[1]!.action?.action).toBe("restore");
    expect(
      removedStacks(bin, fleet, "server b").map((item) => item.project),
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
    expect(ownFolder("/var/lib/kry-exec/compose/panel")).toBe(true);
    expect(ownFolder("/var/lib/kry-exec/compose/panel/sub")).toBe(false);
    expect(ownFolder("/home/alice/shop")).toBe(false);
  });
});

describe("one list per server", () => {
  const all = { showSystem: false, query: "", notRunning: false };
  const shape = (lists: ReturnType<typeof serverLists>) =>
    lists.map((list) => [
      list.node.name,
      list.stacks.map((item) => [
        item.member.stack.project,
        item.containers.map((member) => member.entry.name),
      ]),
      list.members.map((member) => member.entry.name),
    ]);

  it("puts each stack's containers under it and the rest beside it", () => {
    const lists = serverLists(data, nodes, all);
    expect(shape(lists)).toEqual([
      [
        "Server A",
        [
          ["shop", []],
          ["listmonk", ["listmonk-db-1", "listmonk_app"]],
        ],
        ["resolver"],
      ],
      ["Server B", [["listmonk", []]], []],
    ]);
    expect(lists[0]!.stacks[1]!.peers.map((peer) => peer.node.name)).toEqual([
      "Server A",
      "Server B",
    ]);
  });

  it("searches stacks, their containers and servers, and filters what is not running", () => {
    expect(shape(serverLists(data, nodes, { ...all, query: "db" }))).toEqual([
      ["Server A", [["listmonk", ["listmonk-db-1", "listmonk_app"]]], []],
    ]);
    expect(
      shape(serverLists(data, nodes, { ...all, query: "SERVER B" })),
    ).toEqual([["Server B", [["listmonk", []]], []]]);
    expect(
      shape(serverLists(data, nodes, { ...all, notRunning: true })),
    ).toEqual([["Server A", [["shop", []]], []]]);
  });

  it("finds a stack by its display name", () => {
    const titled: ServicesResponse = {
      ...data,
      nodes: [
        {
          ...data.nodes[0]!,
          stacks: [
            { ...data.nodes[0]!.stacks[0]!, title: "Weekly Newsletter" },
            data.nodes[0]!.stacks[1]!,
          ],
        },
        data.nodes[1]!,
      ],
    };
    expect(
      shape(serverLists(titled, nodes, { ...all, query: "weekly news" })),
    ).toEqual([
      ["Server A", [["listmonk", ["listmonk-db-1", "listmonk_app"]]], []],
    ]);
    expect(
      groupStacks(titled, nodes, "Weekly").map((group) => [
        group.project,
        group.members.length,
      ]),
    ).toEqual([["listmonk", 1]]);
  });

  it("sorts stacks by their display name", () => {
    const titled: ServicesResponse = {
      ...data,
      nodes: [
        {
          ...data.nodes[0]!,
          stacks: [stack("listmonk", { title: "Zine" }), stack("shop")],
        },
        data.nodes[1]!,
      ],
    };
    expect(
      serverLists(titled, nodes, all)[0]!.stacks.map(
        (item) => item.member.stack.project,
      ),
    ).toEqual(["shop", "listmonk"]);
    expect(
      groupStacks(titled, nodes, "").map((group) => group.project),
    ).toEqual(["shop", "listmonk"]);
  });

  it("gives every server one box with its count, and folds system services until asked", () => {
    const unit = (
      name: string,
      state: "running" | "failed",
      system = false,
    ) => ({ kind: "systemd" as const, name, state, since: null, system });
    const withUnits: ServicesResponse = {
      ...data,
      nodes: [
        {
          ...data.nodes[0]!,
          stacks: [
            ...data.nodes[0]!.stacks,
            stack("vault", { running: 0, total: 1, access: "contained" }),
            stack("proxy", { running: 1, total: 1, access: "full" }),
          ],
          services: [
            ...data.nodes[0]!.services,
            unit("nginx.service", "running"),
            unit("cron.service", "failed"),
            unit("systemd-journald.service", "running", true),
            unit("systemd-logind.service", "running", true),
            unit("dbus.service", "running", true),
          ],
        },
        data.nodes[1]!,
      ],
    };
    const options = { query: "", kind: "all" as const, showSystem: false };
    const boxes = serverBoxes(withUnits, nodes, options);
    expect(
      boxes.map((box) => [
        box.node.name,
        box.count,
        box.stacks.map((item) => item.member.stack.project),
        box.members.map((member) => member.entry.name),
        box.folded,
      ]),
    ).toEqual([
      [
        "Server A",
        "7 running · 1 partly · 1 stopped · 1 failed",
        ["shop", "vault", "listmonk", "proxy"],
        ["cron.service", "nginx.service", "resolver"],
        3,
      ],
      ["Server B", "1 running", ["listmonk"], [], 0],
    ]);
    expect(
      serverBoxes(withUnits, nodes, { ...options, showSystem: true })[0]!
        .members.length,
    ).toBe(6);
    expect(
      serverBoxes(withUnits, nodes, { ...options, kind: "systemd" }).map(
        (box) => [box.node.name, box.stacks.length, box.members.length],
      ),
    ).toEqual([["Server A", 0, 2]]);
    expect(
      serverBoxes(withUnits, nodes, { ...options, query: "server b" }).map(
        (box) => box.node.name,
      ),
    ).toEqual(["Server B"]);
    expect(
      serverBoxes(withUnits, nodes, { ...options, query: "nginx" }).map(
        (box) => [
          box.node.name,
          box.members.map((member) => member.entry.name),
        ],
      ),
    ).toEqual([["Server A", ["nginx.service"]]]);
    expect(foldedText(3)).toBe("+ 3 system services");
    expect(foldedText(1)).toBe("+ 1 system service");
  });

  it("marks only Full access on a stack's state", () => {
    expect(
      stackState(stack("vault", { running: 1, total: 2, access: "contained" })),
    ).toBe("1 of 2");
    expect(stackState(stack("proxy", { access: "full" }))).toBe(
      "2 of 2 · Full access",
    );
    expect(stackState(stack("blog"))).toBe("2 of 2");
  });

  it("gives a container to the stack with the longest matching name", () => {
    const nested: ServicesResponse = {
      ...data,
      nodes: [
        {
          ...data.nodes[0]!,
          stacks: [stack("listmonk"), stack("listmonk-db")],
        },
      ],
    };
    expect(shape(serverLists(nested, nodes, all))[0]![1]).toEqual([
      ["listmonk", ["listmonk_app"]],
      ["listmonk-db", ["listmonk-db-1"]],
    ]);
  });
});

describe("moving a stack with web addresses", () => {
  const address = {
    hostname: "listmonk-server-1.example.org",
    project: "listmonk",
    service: "app",
    port: 9000,
    mode: "allow" as const,
    path: null,
  };

  it("keeps the original until its addresses are closed", () => {
    expect(moveBlocker([address], "now")).toMatch(/Close web address/u);
    expect(moveBlocker([address], "later")).toMatch(/Close web address/u);
    expect(moveBlocker([address], "keep")).toBeNull();
    expect(moveBlocker([], "now")).toBeNull();
  });
});

describe("what needs attention on Services", () => {
  const now = Date.parse("2026-10-24T10:00:00.000Z");
  const ago = (minutes: number) =>
    new Date(now - minutes * 60_000).toISOString();
  const failed = (overrides: Partial<ActionRecord>): AttentionItem => ({
    action: {
      id: "f1",
      batchId: "b1",
      position: 0,
      mode: "rolling",
      nodeId: "pv",
      kind: "compose",
      name: "pihole",
      action: "restart",
      status: "failed",
      requestedBy: "owner@example.test",
      requestedAt: ago(31),
      deliverableAt: null,
      sentAt: ago(31),
      finishedAt: ago(30),
      exitCode: 1,
      output: null,
      deviceId: null,
      ...overrides,
    },
    incident: null,
  });
  const container = (
    name: string,
    state: "running" | "stopped",
    since: string | null = null,
  ) => ({ kind: "docker" as const, name, state, since, system: false });
  const servers = [
    node("pv", "server-1", "0.7.0"),
    node("server-2", "server-2", "0.7.0"),
    node("cl", "server-3", "0.7.0"),
  ];
  const estate: ServicesResponse = {
    nodes: [
      {
        id: "pv",
        inventoryAt: null,
        refreshRequestedAt: null,
        stacks: [
          stack("pihole", { running: 0, total: 1 }),
          stack("homeassistant", { running: 1, total: 1 }),
        ],
        services: [
          container("pihole-pihole-1", "stopped"),
          container("homeassistant-app-1", "running"),
        ],
        trust: trusted,
      },
      {
        id: "server-2",
        inventoryAt: null,
        refreshRequestedAt: null,
        stacks: [
          stack("tracker", { running: 1, total: 2, rollback: true }),
          stack("blog"),
        ],
        services: [
          container("tracker-app-1", "running"),
          container("tracker-db-1", "stopped"),
          container("blog-web-1", "running"),
          container("blog-db-1", "running"),
        ],
        trust: trusted,
      },
      {
        id: "cl",
        inventoryAt: null,
        refreshRequestedAt: null,
        stacks: [],
        services: [
          {
            kind: "systemd",
            name: "backup.service",
            state: "failed",
            since: ago(40),
            system: false,
          },
          container("portainer", "running"),
        ],
        trust: null,
      },
    ],
    actions: [],
  };
  const items = [
    failed({
      output: "Error response from daemon\nport 53 is already allocated\n",
    }),
    failed({
      id: "f2",
      kind: "docker",
      name: "pihole-pihole-1",
      finishedAt: ago(120),
      output: "an older failure",
    }),
    failed({
      id: "f3",
      nodeId: "server-2",
      name: "tracker",
      action: "deploy",
      finishedAt: ago(60),
      output:
        "Container tracker-db-1 Error\ndependency failed to start: container tracker-db-1 exited (1)",
    }),
    failed({
      id: "f4",
      nodeId: "server-2",
      name: "blog",
      action: "stop",
      finishedAt: ago(5),
    }),
    failed({ id: "f5", nodeId: "server-2", name: "newapp", action: "create" }),
    failed({ id: "f6", nodeId: "gone", name: "pihole" }),
  ];

  it("lists each broken thing once with its reason and the button that fits", () => {
    const problems = servicesAttention(estate, servers, items, now);
    expect(
      problems.map((problem) => [
        problem.node.name,
        problem.kind,
        problem.name,
        problem.state,
        problem.reason,
        problem.primary,
      ]),
    ).toEqual([
      [
        "server-1",
        "stack",
        "pihole",
        "0 of 1 running",
        "Restart failed 30m ago: port 53 is already allocated",
        "start",
      ],
      [
        "server-2",
        "stack",
        "blog",
        "2 of 2 running",
        "Stop failed 5m ago: exit 1",
        "restart",
      ],
      [
        "server-2",
        "stack",
        "tracker",
        "1 of 2 running",
        "Deploy failed 1h ago: dependency failed to start: container tracker-db-1 exited (1)",
        "rollback",
      ],
      ["server-3", "systemd", "backup", "Failed", "Failed 40m ago", "start"],
    ]);
    expect(problems[0]!.target).toEqual({
      nodeId: "pv",
      nodeName: "server-1",
      kind: "compose",
      name: "pihole",
    });
    expect(problems[0]!.stack?.stack.project).toBe("pihole");
    expect(problems[0]!.blocker).toBeNull();
    expect(problems[3]!.target.name).toBe("backup.service");
    expect(problems[3]!.stack).toBeNull();
    expect(problems[3]!.blocker).toBe("Not Trusted Yet");
  });

  it("says what stopped and when without a failed action", () => {
    const quiet: ServicesResponse = {
      ...estate,
      nodes: [
        {
          ...estate.nodes[0]!,
          services: [container("pihole-pihole-1", "stopped", ago(120))],
        },
      ],
    };
    expect(
      servicesAttention(quiet, servers, [], now).map((problem) => [
        problem.name,
        problem.reason,
        problem.primary,
      ]),
    ).toEqual([["pihole", "Stopped 2h ago", "start"]]);
  });

  it("knows the newest action on what it lists, to show one that runs", () => {
    const running = { ...items[0]!.action, id: "p1", status: "sent" as const };
    const problems = servicesAttention(
      { ...estate, actions: [running] },
      servers,
      items,
      now,
    );
    expect(
      problems.find((problem) => problem.name === "pihole")?.latest?.id,
    ).toBe("p1");
  });
});

describe("deleting the original of a move at once", () => {
  it("needs the stack's name typed, like Delete permanently", () => {
    expect(moveConfirmed("later", "", "listmonk")).toBe(true);
    expect(moveConfirmed("keep", "", "listmonk")).toBe(true);
    expect(moveConfirmed("now", "", "listmonk")).toBe(false);
    expect(moveConfirmed("now", "listmon", "listmonk")).toBe(false);
    expect(moveConfirmed("now", "listmonk", "listmonk")).toBe(true);
  });
});

describe("units that only run at boot", () => {
  it("leaves them out of the server count and of what needs attention", () => {
    const states = [
      ...Array.from({ length: 14 }, () => "running" as const),
      "stopped" as const,
      "boot" as const,
      "boot" as const,
      "unneeded" as const,
    ];
    const resting: ServicesResponse = {
      nodes: [
        {
          ...data.nodes[0]!,
          stacks: [],
          services: states.map((state, index) => ({
            kind: "systemd" as const,
            name: `unit-${index}.service`,
            state,
            since: null,
            system: false,
          })),
        },
      ],
      actions: [],
    };
    const options = { query: "", kind: "all" as const, showSystem: true };
    const box = serverBoxes(resting, nodes, options)[0]!;
    expect(box.count).toBe("14 running · 1 stopped");
    expect(box.members.slice(-3).map((member) => member.entry.state)).toEqual([
      "boot",
      "boot",
      "unneeded",
    ]);
    expect(
      serverLists(resting, nodes, {
        showSystem: true,
        query: "",
        notRunning: true,
      })[0]!.members.map((member) => member.entry.state),
    ).toEqual(["stopped"]);
  });
});
