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
  checkFigure,
  checksByServer,
  checkTargetProblem,
  containerChecksReady,
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

  it("offers container checks from agent 0.6.4", () => {
    expect(containerChecksReady("0.6.4")).toBe(true);
    expect(containerChecksReady("0.6.3")).toBe(false);
    expect(containerChecksReady("0.7.0")).toBe(true);
    expect(containerChecksReady("0.6.2")).toBe(false);
    expect(containerChecksReady(null)).toBe(false);
    expect(containerChecksReady("dev")).toBe(false);
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

  it("keeps Fleet's server order, down checks first, and counts only what is down now", () => {
    expect(
      checksByServer(checks, nodes, NOW).map((group) => [
        group.node.name,
        group.checks.map((item) => item.name),
        group.down,
      ]),
    ).toEqual([
      ["io", ["Umami", "Blog", "SSH"], 1],
      ["pivox", ["Pi-hole", "tailscaled"], 1],
      ["calisto", ["MinIO console", "postgresql"], 0],
      ["old", ["Old"], 0],
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
    expect(incidentLine(0)).toBe("Incident open →");
    expect(incidentLine(1)).toBe("Incident open · 1 update →");
    expect(incidentLine(3)).toBe("Incident open · 3 updates →");
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

describe("a check's last column", () => {
  const latest = (latencyMs: number) => ({
    results: [
      { t: before(60_000), status: "UP" as const, latencyMs, message: null },
    ],
  });
  const opened = { started_at: before(36 * 60_000) } as Incident;

  it("says latency for HTTP and TCP", () => {
    expect(checkFigure(check("HTTP"), "UP", undefined, latest(130), NOW)).toBe(
      "130ms",
    );
    expect(checkFigure(check("TCP"), "UP", undefined, latest(4), NOW)).toBe(
      "4ms",
    );
  });

  it("says how long a container has run and a unit has been active", () => {
    expect(
      checkFigure(
        check("CONTAINER", { since: before(4 * 60_000) }),
        "UP",
        undefined,
        undefined,
        NOW,
      ),
    ).toBe("running 4m");
    expect(
      checkFigure(
        check("SERVICE", { since: before(37 * 86_400_000) }),
        "UP",
        undefined,
        latest(9),
        NOW,
      ),
    ).toBe("active 37d");
  });

  it("says running or active alone when an older agent sent no start", () => {
    expect(
      checkFigure(check("CONTAINER"), "UP", undefined, undefined, NOW),
    ).toBe("running");
    expect(checkFigure(check("SERVICE"), "UP", undefined, latest(9), NOW)).toBe(
      "active",
    );
  });

  it("counts down from the open incident, or says down alone", () => {
    expect(
      checkFigure(
        check("HTTP", { status: "DOWN" }),
        "DOWN",
        opened,
        latest(1),
        NOW,
      ),
    ).toBe("down 36m");
    expect(
      checkFigure(
        check("CONTAINER", { status: "DOWN" }),
        "DOWN",
        undefined,
        undefined,
        NOW,
      ),
    ).toBe("down");
  });

  it("says nothing before a first result or for an offline server's check", () => {
    expect(checkFigure(check("HTTP"), "UP", undefined, undefined, NOW)).toBe(
      "--",
    );
    expect(
      checkFigure(
        check("HTTP", { status: "UNKNOWN" }),
        "UNKNOWN",
        undefined,
        undefined,
        NOW,
      ),
    ).toBe("--");
    expect(
      checkFigure(
        check("CONTAINER", { since: before(60_000) }),
        "offline",
        undefined,
        latest(1),
        NOW,
      ),
    ).toBe("--");
  });
});
