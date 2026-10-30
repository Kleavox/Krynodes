import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  AttentionItem,
  CheckRecord,
  Incident,
  ServicesResponse,
} from "../types";
import {
  foldedStatesText,
  foldedUnitsText,
  incidentNote,
  whatRuns,
} from "./what-runs";

type ServiceNode = ServicesResponse["nodes"][number];

const serverTwo: ServiceNode = {
  id: "server-2",
  inventoryAt: null,
  refreshRequestedAt: null,
  trust: null,
  services: [
    {
      kind: "docker",
      name: "tracker-app-1",
      state: "running",
      since: null,
      system: false,
    },
    {
      kind: "docker",
      name: "tracker-db-1",
      state: "stopped",
      since: null,
      system: false,
    },
    {
      kind: "docker",
      name: "blog-web-1",
      state: "running",
      since: null,
      system: false,
    },
    {
      kind: "docker",
      name: "blog-db-1",
      state: "running",
      since: null,
      system: false,
    },
    {
      kind: "docker",
      name: "portainer",
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
      name: "ssh.service",
      state: "running",
      since: null,
      system: true,
    },
    {
      kind: "systemd",
      name: "docker.service",
      state: "running",
      since: null,
      system: true,
    },
    {
      kind: "systemd",
      name: "backup.service",
      state: "stopped",
      since: null,
      system: false,
    },
  ],
  stacks: [
    {
      project: "tracker",
      directory: "/srv/tracker",
      running: 1,
      total: 2,
      compose: true,
      rollback: true,
      containers: ["tracker-app-1", "tracker-db-1"],
    },
    {
      project: "blog",
      directory: "/srv/blog",
      running: 2,
      total: 2,
      compose: true,
      rollback: false,
      containers: ["blog-web-1", "blog-db-1"],
    },
  ],
  webAddresses: [
    {
      hostname: "tracker.example.org",
      project: "tracker",
      service: "app",
      port: 3000,
      mode: "allow",
      path: null,
    },
    {
      hostname: "blog.example.org",
      project: "blog",
      service: "web",
      port: 80,
      mode: "everyone",
      path: null,
    },
  ],
};

const check = (
  id: string,
  kind: CheckRecord["kind"],
  target: string,
  status: CheckRecord["status"] = "UP",
): CheckRecord => ({
  id,
  node_id: "server-2",
  name: id,
  kind,
  target,
  enabled: 1,
  status,
  timeout_seconds: 10,
  latency_ms: null,
  last_checked_at: null,
  consecutive_failures: 0,
  last_message: null,
  public: 0,
  public_note: null,
  created_at: "2026-09-01T00:00:00.000Z",
});

const checks = [
  check("Tracker", "HTTP", "https://tracker.example.org", "DOWN"),
  check("Blog", "HTTP", "https://blog.example.org/"),
  check("SSH", "TCP", "198.51.100.10:22"),
  check("nginx", "SERVICE", "nginx"),
  check("Elsewhere", "HTTP", "https://example.com"),
];

const incident = (
  id: string,
  checkId: string,
  started: string,
  resolved: string | null,
): Incident => ({
  id,
  check_id: checkId,
  node_id: "server-2",
  status: resolved ? "RESOLVED" : "OPEN",
  started_at: started,
  resolved_at: resolved,
  summary: "HTTP 502",
  check_name: checkId,
  node_name: "server-2",
});

const incidents = [
  incident("i1", "Tracker", "2026-10-24T02:26:00.000Z", null),
  incident(
    "i2",
    "Blog",
    "2026-10-21T00:08:00.000Z",
    "2026-10-21T00:20:00.000Z",
  ),
  incident(
    "i3",
    "Blog",
    "2026-10-15T00:08:00.000Z",
    "2026-10-15T00:10:00.000Z",
  ),
];

const failed = (over: Partial<ActionRecord>): AttentionItem => ({
  action: {
    id: "a1",
    batchId: "b1",
    position: 0,
    mode: "rolling",
    nodeId: "server-2",
    kind: "compose",
    name: "tracker",
    action: "deploy",
    status: "failed",
    requestedBy: "o",
    requestedAt: "2026-10-24T02:24:00.000Z",
    deliverableAt: null,
    sentAt: null,
    finishedAt: "2026-10-24T02:25:00.000Z",
    exitCode: 1,
    output: "tracker-db-1 exited (1)",
    deviceId: null,
    ...over,
  },
  incident: null,
});

const items = [
  failed({}),
  failed({ id: "a2", nodeId: "server-1", name: "blog" }),
];

describe("what runs on a server", () => {
  const { cards, other } = whatRuns(serverTwo, checks, incidents, items);
  const card = (kind: string, name: string) =>
    cards.find((each) => each.kind === kind && each.name === name);

  it("gives tracker one card with its failed deploy, its check and its open incident, first", () => {
    expect(cards[0]).toMatchObject({
      kind: "stack",
      name: "tracker",
      problem: true,
      incident: { id: "i1" },
      notFixed: { action: { id: "a1" } },
    });
    expect(cards[0]!.checks.map((each) => each.id)).toEqual(["Tracker"]);
  });

  it("gives blog its check and its last resolved incident", () => {
    expect(card("stack", "blog")).toMatchObject({
      problem: false,
      incident: { id: "i2" },
      notFixed: null,
    });
    expect(card("stack", "blog")!.checks.map((each) => each.id)).toEqual([
      "Blog",
    ]);
  });

  it("leaves a TCP check and a check on nothing here in Other checks", () => {
    expect(other.map((each) => each.id)).toEqual(["SSH", "Elsewhere"]);
  });

  it("folds the running units into one card with their checks", () => {
    expect(card("systemd", "")).toMatchObject({
      problem: false,
      units: ["nginx.service", "docker.service", "ssh.service"],
    });
    expect(card("systemd", "")!.checks.map((each) => each.id)).toEqual([
      "nginx",
    ]);
    expect(cards.at(-1)!.units.length).toBe(3);
  });

  it("gives a stopped unit its own card among the problems, grey unless it failed", () => {
    expect(card("systemd", "backup.service")).toMatchObject({
      problem: true,
      alarm: false,
      units: [],
    });
    const failedUnit = whatRuns(
      {
        ...serverTwo,
        services: serverTwo.services.map((service) =>
          service.name === "backup.service"
            ? { ...service, state: "failed" as const }
            : service,
        ),
      },
      checks,
      incidents,
      items,
    );
    expect(
      failedUnit.cards.find((each) => each.name === "backup.service"),
    ).toMatchObject({ problem: true, alarm: true });
    expect(cards[0]).toMatchObject({ name: "tracker", alarm: true });
    expect(cards.slice(0, 2).map((each) => each.name)).toEqual([
      "tracker",
      "backup.service",
    ]);
  });

  it("gives a container outside every stack its own card", () => {
    expect(card("docker", "portainer")).toMatchObject({ problem: false });
  });

  it("pulls a running unit with a down check out of the fold", () => {
    const down = whatRuns(
      serverTwo,
      [check("nginx", "SERVICE", "nginx.service", "DOWN")],
      [incident("i9", "nginx", "2026-10-24T02:00:00.000Z", null)],
      [],
    );
    expect(
      down.cards.find((each) => each.name === "nginx.service"),
    ).toMatchObject({ problem: true, alarm: true, incident: { id: "i9" } });
    expect(down.cards.find((each) => each.name === "")!.units).toEqual([
      "docker.service",
      "ssh.service",
    ]);
  });

  it("an old agent's stacks claim no container checks", () => {
    const old: ServiceNode = {
      ...serverTwo,
      stacks: serverTwo.stacks.map(({ containers: _, ...stack }) => stack),
    };
    const result = whatRuns(
      old,
      [check("app", "CONTAINER", "tracker-app-1")],
      [],
      [],
    );
    expect(
      result.cards.find((each) => each.name === "tracker")!.checks,
    ).toEqual([]);
    expect(result.other.map((each) => each.id)).toEqual(["app"]);
  });

  it("says nothing of a server with nothing reported", () => {
    expect(
      whatRuns(
        { ...serverTwo, services: [], stacks: [] },
        checks,
        incidents,
        [],
      ),
    ).toMatchObject({ cards: [] });
  });
});

describe("a card's words", () => {
  it("names a few running units and counts the rest", () => {
    expect(foldedUnitsText(["nginx.service", "ssh.service"])).toBe(
      "nginx · ssh",
    );
    expect(
      foldedUnitsText(
        ["a", "b", "c", "d", "e", "f", "g"].map((n) => `${n}.service`),
      ),
    ).toBe("a · b · c · d + 3 more");
  });

  it("says what the folded units are doing, never All Running over units that ran at boot", () => {
    expect(foldedStatesText(["running", "running"])).toBe("All Running");
    expect(foldedStatesText(["boot", "running", "boot", "unneeded"])).toBe(
      "1 Running · 2 Ran at Boot · 1 Not Needed Here",
    );
    expect(foldedStatesText(["boot", "boot"])).toBe("2 Ran at Boot");
  });

  it("says an open incident's length and the last resolved one's day", () => {
    const now = Date.parse("2026-10-24T03:28:00.000Z");
    expect(incidentNote(incidents[0]!, now)).toBe("Incident Open · Down 1h 2m");
    expect(incidentNote(incidents[1]!, now)).toMatch(
      /^Last Incident 21 Oct · 12m$/u,
    );
  });
});
