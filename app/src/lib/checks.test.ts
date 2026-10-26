import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  AttentionItem,
  CheckRecord,
  Incident,
  NodeRecord,
  ServiceEntry,
} from "../types";
import {
  autoRestartLine,
  checkLive,
  checksByServer,
  checkTargetProblem,
  failuresText,
  incidentLine,
  pickedKind,
  serverChecksText,
  shownTarget,
  targetOptions,
} from "./checks";

const service = (kind: ServiceEntry["kind"], name: string): ServiceEntry => ({
  kind,
  name,
  state: "running",
  since: null,
  system: false,
});

describe("picked targets", () => {
  const services = [
    service("systemd", "tailscaled.service"),
    service("docker", "adguard-adguard-1"),
    service("systemd", "nginx.service"),
    service("docker", "web-1"),
    service("systemd", "nginx.service"),
  ];

  it("lists only the chosen kind, sorted and once each", () => {
    expect(targetOptions(services, "SERVICE", "")).toEqual([
      { name: "nginx.service", seen: true },
      { name: "tailscaled.service", seen: true },
    ]);
    expect(targetOptions(services, "CONTAINER", "")).toEqual([
      { name: "adguard-adguard-1", seen: true },
      { name: "web-1", seen: true },
    ]);
    expect(targetOptions(services, "HTTP", "")).toEqual([]);
    expect(targetOptions(undefined, "CONTAINER", "")).toEqual([]);
  });

  it("keeps a current target the server no longer shows", () => {
    expect(targetOptions(services, "CONTAINER", "old-db")).toEqual([
      { name: "old-db", seen: false },
      { name: "adguard-adguard-1", seen: true },
      { name: "web-1", seen: true },
    ]);
    expect(targetOptions(services, "CONTAINER", "web-1")).toHaveLength(2);
  });

  it("knows which kinds are picked rather than typed", () => {
    expect(pickedKind("SERVICE")).toBe(true);
    expect(pickedKind("CONTAINER")).toBe(true);
    expect(pickedKind("HTTP")).toBe(false);
    expect(pickedKind("TCP")).toBe(false);
  });

  it("asks for a pick instead of a typed name", () => {
    expect(checkTargetProblem("CONTAINER", "")).toBe("Choose a container.");
    expect(checkTargetProblem("SERVICE", "")).toBe("Choose a service.");
    expect(checkTargetProblem("CONTAINER", "adguard-adguard-1")).toBeNull();
  });
});

describe("check targets", () => {
  it("accepts what the Worker accepts", () => {
    expect(checkTargetProblem("HTTP", "https://example.com/health")).toBeNull();
    expect(checkTargetProblem("HTTP", " http://10.0.0.2:8080 ")).toBeNull();
    expect(checkTargetProblem("TCP", "db.internal:5432")).toBeNull();
    expect(checkTargetProblem("SERVICE", "nginx.service")).toBeNull();
    expect(checkTargetProblem("SERVICE", "getty@tty1.service")).toBeNull();
  });

  it("says what is wrong for each kind", () => {
    expect(checkTargetProblem("HTTP", "")).toBe("Enter a target.");
    expect(checkTargetProblem("HTTP", "example.com")).toBe(
      "Use a full URL starting with http:// or https://.",
    );
    expect(checkTargetProblem("HTTP", "ftp://example.com")).toBe(
      "Use a full URL starting with http:// or https://.",
    );
    expect(checkTargetProblem("TCP", "example.com")).toBe(
      "Use host:port, such as 127.0.0.1:5432.",
    );
    expect(checkTargetProblem("TCP", "example.com:70000")).toBe(
      "The port must be between 1 and 65535.",
    );
    expect(checkTargetProblem("SERVICE", "nginx service")).toBe(
      "Use a systemd unit name, such as nginx.service.",
    );
  });
});

const NOW = Date.parse("2026-10-24T10:00:00Z");
const before = (milliseconds: number) =>
  new Date(NOW - milliseconds).toISOString();
const check = (
  kind: CheckRecord["kind"],
  values: Partial<CheckRecord> = {},
): CheckRecord => ({
  id: "c1",
  node_id: "n1",
  name: "web",
  kind,
  target: "https://example.test",
  enabled: 1,
  status: "UP",
  timeout_seconds: 10,
  latency_ms: null,
  last_checked_at: null,
  consecutive_failures: 0,
  last_message: null,
  public: 0,
  public_note: null,
  created_at: "2026-10-01 00:00:00",
  since: null,
  ...values,
});

describe("checks by server", () => {
  const server = (id: string, name: string, seenAgo = 30_000) =>
    ({
      id,
      name,
      agent_version: "0.6.14",
      enrolled_at: "2026-10-01 00:00:00",
      disabled_at: null,
      last_seen_at: before(seenAgo),
      interval_seconds: 60,
    }) as NodeRecord;
  const nodes = [
    server("io", "io"),
    server("pv", "pivox"),
    server("cl", "calisto"),
    server("old", "old", 86_400_000),
    server("spare", "spare"),
  ];
  const checks = [
    check("HTTP", { id: "blog", node_id: "io", name: "Blog" }),
    check("HTTP", {
      id: "umami",
      node_id: "io",
      name: "Umami",
      status: "DOWN",
    }),
    check("TCP", { id: "ssh", node_id: "io", name: "SSH" }),
    check("SERVICE", { id: "tail", node_id: "pv", name: "tailscaled" }),
    check("SERVICE", {
      id: "pihole",
      node_id: "pv",
      name: "Pi-hole",
      status: "DOWN",
    }),
    check("SERVICE", { id: "pg", node_id: "cl", name: "postgresql" }),
    check("HTTP", {
      id: "minio",
      node_id: "cl",
      name: "MinIO console",
      status: "DOWN",
      enabled: 0,
    }),
    check("HTTP", { id: "gone", node_id: "old", name: "Old", status: "DOWN" }),
  ];

  it("keeps Fleet's server order, down checks first", () => {
    expect(
      checksByServer(checks, nodes, NOW).map((group) => [
        group.node.name,
        group.checks.map((item) => item.name),
      ]),
    ).toEqual([
      ["io", ["Umami", "Blog", "SSH"]],
      ["pivox", ["Pi-hole", "tailscaled"]],
      ["calisto", ["MinIO console", "postgresql"]],
      ["old", ["Old"]],
    ]);
  });

  it("heads each server with its count", () => {
    expect(serverChecksText(3, 1)).toBe("3 checks · 1 down");
    expect(serverChecksText(2, 0)).toBe("2 checks");
    expect(serverChecksText(1, 0)).toBe("1 check");
  });

  it("shows the target only when it says more than the name", () => {
    expect(
      shownTarget(
        check("SERVICE", { name: "tailscaled", target: "tailscaled" }),
      ),
    ).toBeNull();
    expect(
      shownTarget(
        check("SERVICE", { name: "tailscaled", target: "tailscaled.service" }),
      ),
    ).toBeNull();
    expect(
      shownTarget(check("CONTAINER", { name: "pihole", target: "pihole" })),
    ).toBeNull();
    expect(
      shownTarget(
        check("HTTP", { name: "Umami", target: "https://umami.kleavox.xyz/" }),
      ),
    ).toBe("umami.kleavox.xyz");
    expect(
      shownTarget(check("HTTP", { target: "http://10.0.0.2:8080/health" })),
    ).toBe("10.0.0.2:8080/health");
    expect(
      shownTarget(check("TCP", { name: "SSH", target: "51.79.0.10:22" })),
    ).toBe("51.79.0.10:22");
  });
});

describe("the Down box", () => {
  const heal = (overrides: Partial<ActionRecord> = {}): AttentionItem => ({
    action: {
      id: "h1",
      batchId: "b1",
      position: 0,
      mode: "rolling",
      nodeId: "pv",
      kind: "systemd",
      name: "pihole-FTL.service",
      action: "heal",
      status: "failed",
      requestedBy: "Krynodes",
      requestedAt: before(31 * 60_000),
      deliverableAt: null,
      sentAt: before(31 * 60_000),
      finishedAt: before(30 * 60_000),
      exitCode: 1,
      output: "Job for pihole-FTL.service failed\nport 53 is already allocated",
      deviceId: null,
      ...overrides,
    },
    incident: null,
  });
  const pihole = check("SERVICE", {
    node_id: "pv",
    name: "Pi-hole",
    target: "pihole-FTL",
    status: "DOWN",
    auto_restart: 1,
  });

  it("counts failures in a row from two", () => {
    expect(failuresText(12)).toBe("12 failures in a row");
    expect(failuresText(1)).toBeNull();
  });

  it("names an open incident with its updates", () => {
    expect(incidentLine(0)).toBe("Incident Open →");
    expect(incidentLine(1)).toBe("Incident Open · 1 update →");
    expect(incidentLine(3)).toBe("Incident Open · 3 updates →");
  });

  it("tells a failed auto-restart of the check's unit, with its first error", () => {
    expect(autoRestartLine(pihole, [heal()], NOW)).toBe(
      "Auto-restart failed 30m ago: port 53 is already allocated",
    );
    expect(
      autoRestartLine({ ...pihole, auto_restart: 0 }, [heal()], NOW),
    ).toBeNull();
    expect(autoRestartLine(pihole, [heal({ nodeId: "io" })], NOW)).toBeNull();
    expect(
      autoRestartLine(pihole, [heal({ action: "restart" })], NOW),
    ).toBeNull();
  });
});

describe("a check's live status", () => {
  const latest = (latencyMs: number) => ({
    results: [
      { t: before(60_000), status: "UP" as const, latencyMs, message: null },
    ],
  });
  const opened = { started_at: before(36 * 60_000) } as Incident;
  const live = (values: Partial<Parameters<typeof checkLive>[0]>) =>
    checkLive({ check: check("HTTP"), display: "UP", now: NOW, ...values });

  it("says latency for HTTP and TCP, and how long a container or unit has run", () => {
    expect(live({ latest: latest(130) })).toEqual({
      label: "130ms",
      tone: "ok",
    });
    expect(live({ check: check("TCP"), latest: latest(4) }).label).toBe("4ms");
    expect(
      live({ check: check("CONTAINER", { since: before(4 * 60_000) }) }).label,
    ).toBe("Running 4m");
    expect(
      live({
        check: check("SERVICE", { since: before(37 * 86_400_000) }),
        latest: latest(9),
      }).label,
    ).toBe("Active 37d");
    expect(live({ check: check("CONTAINER") }).label).toBe("Running");
    expect(live({ check: check("SERVICE"), latest: latest(9) }).label).toBe(
      "Active",
    );
  });

  it("counts down from the open incident, amber until one opens, and names an auto-restart", () => {
    expect(live({ display: "DOWN", incident: opened })).toEqual({
      label: "Down 36m",
      tone: "bad",
    });
    expect(live({ display: "DOWN" })).toEqual({ label: "Down", tone: "warn" });
    expect(
      live({ display: "DOWN", incident: opened, healing: true }).label,
    ).toBe("Down 36m · Auto-Restarting");
  });

  it("names work by you instead of down, unless an incident is open", () => {
    const work = [{ from: NOW - 60_000, to: Infinity, label: "Roll Back" }];
    expect(live({ display: "DOWN", work })).toEqual({
      label: "Roll Back by You",
      tone: "work",
    });
    expect(
      live({ display: "OFFLINE", work, lastSeen: before(60_000) }).label,
    ).toBe("Roll Back by You");
    expect(live({ display: "DOWN", work, incident: opened }).label).toBe(
      "Down 36m",
    );
    expect(
      live({
        display: "DOWN",
        work: [{ from: NOW - 600_000, to: NOW - 60_000, label: "Restart" }],
      }).label,
    ).toBe("Down");
    expect(live({ work, latest: latest(4) }).label).toBe("4ms");
  });

  it("tells a server that went offline from its routine restart", () => {
    expect(live({ display: "OFFLINE", lastSeen: before(12 * 60_000) })).toEqual(
      { label: "Offline 12m", tone: "off" },
    );
    expect(live({ display: "OFFLINE", lastSeen: null }).label).toBe("Offline");
    expect(
      live({
        display: "OFFLINE",
        lastSeen: before(3 * 60_000),
        quiet: [{ from: before(3 * 60_000), to: null, why: "routine" }],
      }),
    ).toEqual({ label: "Routine Restart", tone: "info" });
    expect(
      live({
        display: "OFFLINE",
        lastSeen: before(15 * 60_000),
        quiet: [
          { from: before(15 * 60_000), to: before(5 * 60_000), why: "routine" },
          { from: before(5 * 60_000), to: null, why: "offline" },
        ],
      }).label,
    ).toBe("Offline 15m");
  });

  it("says paused, or nothing before a first result", () => {
    expect(
      live({ check: check("HTTP", { enabled: 0 }), display: "PAUSED" }),
    ).toEqual({ label: "Paused", tone: "idle" });
    expect(live({})).toEqual({ label: "--", tone: "ok" });
    expect(live({ display: "UNKNOWN" })).toEqual({ label: "--", tone: "idle" });
    expect(live({ display: "STALE" })).toEqual({ label: "--", tone: "idle" });
  });
});
