import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  CheckResult,
  Incident,
  IncidentDetail,
} from "../types";
import {
  downLatest,
  foldResults,
  incidentRowLine,
  incidentsRedirect,
  incidentState,
  incidentStrip,
  last30Parts,
  lastIncidentLine,
  latestLine,
  ownerLink,
  recentIncidents,
  runText,
  timeline,
} from "./incidents";

const at = (hour: number, minute: number) =>
  new Date(2026, 9, 24, hour, minute).toISOString();

const result = (
  hour: number,
  minute: number,
  status: "UP" | "DOWN",
  message: string | null = status === "DOWN" ? "HTTP 502" : null,
): CheckResult => ({
  t: at(hour, minute),
  status,
  latencyMs: status === "UP" ? 192 : null,
  message,
});

const twelveDown = Array.from({ length: 12 }, (_, index) =>
  result(9 + Math.floor((30 + index * 5) / 60), (30 + index * 5) % 60, "DOWN"),
);

const action = (overrides: Partial<ActionRecord>): ActionRecord => ({
  id: "a1",
  batchId: "b1",
  position: 0,
  mode: "rolling",
  nodeId: "io",
  kind: "compose",
  name: "umami",
  action: "deploy",
  status: "failed",
  requestedBy: "owner@example.test",
  requestedAt: at(9, 24),
  deliverableAt: null,
  sentAt: at(9, 24),
  finishedAt: at(9, 25),
  exitCode: 1,
  output:
    "Container umami-db-1  Error\ndependency failed to start: container umami-db-1 exited (1)",
  deviceId: null,
  ...overrides,
});

describe("folding a check's results", () => {
  it("makes one run of the same status and message", () => {
    expect(foldResults(twelveDown)).toEqual([
      {
        status: "DOWN",
        message: "HTTP 502",
        from: at(9, 30),
        to: at(10, 25),
        count: 12,
      },
    ]);
    expect(runText(foldResults(twelveDown)[0]!, Date.parse(at(12, 0)))).toEqual(
      {
        title: "Still Down",
        when: "09:30 – 10:25",
        body: "12 checks in a row · HTTP 502",
      },
    );
  });

  it("folds results sent newest first, as the Worker sends them", () => {
    expect(foldResults([...twelveDown].reverse())).toEqual(
      foldResults(twelveDown),
    );
  });

  it("dates a run from another day once, at its start", () => {
    const run = foldResults([result(9, 30, "DOWN"), result(9, 35, "DOWN")])[0]!;
    const later = new Date(2026, 9, 29, 12, 0).getTime();
    expect(runText(run, later).when).toBe("24 Oct 09:30 – 09:35");
  });

  it("starts a new run when the message changes", () => {
    const runs = foldResults([
      result(9, 30, "DOWN", "HTTP 502"),
      result(9, 35, "DOWN", "HTTP 502"),
      result(9, 40, "DOWN", "Timed out after 10s"),
      result(9, 45, "UP"),
    ]);
    expect(runs.map((run) => [run.status, run.message, run.count])).toEqual([
      ["DOWN", "HTTP 502", 2],
      ["DOWN", "Timed out after 10s", 1],
      ["UP", null, 1],
    ]);
    expect(runText(runs[2]!, Date.parse(at(12, 0)))).toEqual({
      title: "Up",
      when: "09:45",
      body: "1 check",
    });
  });
});

describe("one incident's timeline", () => {
  const detail: IncidentDetail = {
    incident: {
      id: "i1",
      check_id: "c1",
      node_id: "io",
      status: "OPEN",
      started_at: at(9, 26),
      resolved_at: null,
      summary: "HTTP 502",
      check_name: "Umami",
      node_name: "io",
      check_kind: "HTTP",
      check_target: "https://umami.kleavox.xyz",
    },
    results: [result(9, 20, "UP"), result(9, 25, "UP"), ...twelveDown],
    updates: [
      {
        id: "u1",
        status: "investigating",
        message: "The database container exits on start; looking at its logs.",
        author: "owner@example.test",
        createdAt: at(9, 48),
      },
    ],
    actions: [action({})],
    lastGood: { t: at(9, 25), latencyMs: 192 },
  };

  it("tells it newest first: runs, updates, opened, last good check, actions", () => {
    expect(timeline(detail).map((event) => [event.type, event.at])).toEqual([
      ["run", at(10, 25)],
      ["update", at(9, 48)],
      ["opened", at(9, 26)],
      ["lastGood", at(9, 25)],
      ["action", at(9, 24)],
    ]);
  });

  it("ends with Resolved once it resolved", () => {
    const resolved = timeline({
      ...detail,
      incident: {
        ...detail.incident,
        status: "RESOLVED",
        resolved_at: at(10, 30),
      },
      results: [...detail.results, result(10, 30, "UP")],
    });
    expect(resolved.map((event) => event.type).slice(0, 3)).toEqual([
      "resolved",
      "run",
      "run",
    ]);
  });
});

describe("an incident's header", () => {
  it("says open and for how long, or how long it lasted", () => {
    expect(
      incidentState(
        { started_at: at(9, 26), resolved_at: null },
        Date.parse(at(10, 28)),
      ),
    ).toBe("Open · Down 1h 2m");
    expect(
      incidentState(
        { started_at: at(7, 8), resolved_at: at(7, 20) },
        Date.parse(at(10, 28)),
      ),
    ).toBe("Resolved · Lasted 12m");
  });

  it("links what its check watches to Services", () => {
    expect(ownerLink({ kind: "stack", project: "umami" })).toEqual({
      label: "Stack umami",
      to: "/services?q=umami",
    });
    expect(ownerLink({ kind: "container", name: "pihole" })).toEqual({
      label: "Container pihole",
      to: "/services?q=pihole",
    });
    expect(ownerLink({ kind: "systemd", unit: "pihole-FTL.service" })).toEqual({
      label: "Unit pihole-FTL.service",
      to: "/services?q=pihole-FTL.service&system=1",
    });
  });
});

describe("an incident's strip", () => {
  it("runs from an hour before it opened until now, in whole windows", () => {
    const strip = incidentStrip(
      { started_at: at(9, 26), resolved_at: null },
      [],
      300,
      Date.parse(at(10, 28)),
    );
    expect(strip.since).toBe(Date.parse(at(8, 26)));
    expect(strip.until).toBe(Date.parse(at(10, 28)));
    expect(strip.slotSeconds).toBe(300);
    expect(strip.count).toBe(26);
  });

  it("widens its slots for a long incident and stops where it resolved", () => {
    const strip = incidentStrip(
      { started_at: at(9, 0), resolved_at: at(14, 0) },
      [],
      300,
      Date.parse(at(18, 0)),
    );
    expect(strip.until).toBe(Date.parse(at(14, 0)));
    expect(strip.slotSeconds).toBe(600);
    expect(strip.count).toBe(37);
  });

  it("lets a down result win a slot it shares with an up one", () => {
    const strip = incidentStrip(
      { started_at: at(9, 26), resolved_at: null },
      [result(9, 30, "DOWN"), result(9, 35, "UP")],
      300,
      Date.parse(at(10, 28)),
    );
    expect(strip.results.at(-1)?.status).toBe("DOWN");
  });

  it("measures nothing before the first result still kept", () => {
    const incident = { started_at: at(9, 26), resolved_at: at(9, 40) };
    const now = Date.parse(at(18, 0));
    expect(incidentStrip(incident, [], 300, now).measuredFrom).toBe(Infinity);
    expect(
      incidentStrip(
        incident,
        [result(9, 35, "DOWN"), result(9, 0, "UP")],
        300,
        now,
      ).measuredFrom,
    ).toBe(Date.parse(at(9, 0)));
  });
});

describe("the incident list", () => {
  it("says the latest line: an update or what was done on what it watches", () => {
    expect(
      latestLine({
        at: at(9, 48),
        updates: 1,
        update: {
          status: "investigating",
          message:
            "The database container exits on start; looking at its logs.",
        },
        action: null,
      }),
    ).toBe(
      "Investigating: The database container exits on start; looking at its logs.",
    );
    expect(
      latestLine({
        at: at(9, 58),
        updates: 0,
        update: null,
        action: action({
          kind: "systemd",
          name: "pihole-FTL.service",
          action: "heal",
          output: "port 53 is already allocated",
        }),
      }),
    ).toBe("Auto-restart failed: port 53 is already allocated");
    expect(
      latestLine({
        at: at(9, 58),
        updates: 0,
        update: null,
        action: action({ status: "done", output: null }),
      }),
    ).toBe("Deploy umami: done");
  });
});

describe("incidents on the Checks page", () => {
  const MINUTE = 60_000;
  const on = (day: number, hour: number, minute: number) =>
    new Date(2026, 9, day, hour, minute).getTime();
  const now = on(26, 16, 6);
  const incident = (
    id: string,
    checkId: string,
    started: number,
    lasted: number | null,
    summary: string | null,
  ): Incident => ({
    id,
    check_id: checkId,
    node_id: "io",
    status: lasted === null ? "OPEN" : "RESOLVED",
    started_at: new Date(started).toISOString(),
    resolved_at:
      lasted === null ? null : new Date(started + lasted).toISOString(),
    summary,
    check_name: checkId,
    node_name: "io",
  });

  it("gives each row its start, open or how long it lasted, and why", () => {
    expect(
      incidentRowLine(
        incident("p", "pihole", on(26, 15, 30), null, "down"),
        now,
      ),
    ).toBe("Today 15:30 · open · 36m");
    expect(
      incidentRowLine(
        incident(
          "b",
          "blog",
          on(21, 12, 46),
          12 * MINUTE,
          "timed out after 10s",
        ),
        now,
      ),
    ).toBe("21 Oct 12:46 · 12m · timed out after 10s");
    expect(
      incidentRowLine(
        incident("b", "blog", on(21, 12, 46), 12 * MINUTE, null),
        now,
      ),
    ).toBe("21 Oct 12:46 · 12m");
  });

  it("names a check's last resolved incident only while none is open", () => {
    const resolved = incident(
      "b",
      "blog",
      on(21, 12, 46),
      12 * MINUTE,
      "timed out",
    );
    expect(lastIncidentLine("blog", [resolved])).toBe(
      "Last incident 21 Oct · 12m · timed out",
    );
    expect(lastIncidentLine("blog", [{ ...resolved, summary: null }])).toBe(
      "Last incident 21 Oct · 12m",
    );
    expect(
      lastIncidentLine("blog", [
        incident("o", "blog", on(26, 15, 30), null, "down"),
        resolved,
      ]),
    ).toBeNull();
    expect(lastIncidentLine("blog", [])).toBeNull();
    expect(
      lastIncidentLine("blog", [
        incident("old", "blog", on(10, 9, 0), MINUTE, "older"),
        resolved,
        incident("x", "umami", on(25, 9, 0), MINUTE, "other"),
      ]),
    ).toBe("Last incident 21 Oct · 12m · timed out");
  });

  it("keeps the last 30 days, newest first", () => {
    const old = incident("old", "blog", now - 40 * 86_400_000, MINUTE, null);
    const b = incident("b", "blog", on(20, 9, 0), MINUTE, null);
    const a = incident("a", "blog", on(25, 9, 0), MINUTE, null);
    expect(recentIncidents([old, b, a], now).map((entry) => entry.id)).toEqual([
      "a",
      "b",
    ]);
  });

  it("sums up the last 30 days", () => {
    expect(last30Parts({ count: 5, downMs: 145 * MINUTE })).toEqual({
      count: "5",
      noun: "incidents",
      down: "2h 25m",
    });
    expect(last30Parts({ count: 1, downMs: 4 * MINUTE })).toEqual({
      count: "1",
      noun: "incident",
      down: "4m",
    });
    expect(last30Parts({ count: 0, downMs: 0 })).toBeNull();
  });

  it("puts the newest of an update or an action on a Down card, else the auto-restart line", () => {
    const update = {
      at: new Date(2026, 9, 26, 15, 26).toISOString(),
      updates: 1,
      update: {
        status: "investigating" as const,
        message: "The database container exits on start.",
      },
      action: null,
    };
    expect(downLatest(update, "Auto-restart failed")).toEqual({
      time: "15:26",
      text: "Investigating: The database container exits on start.",
      failed: false,
    });
    const restart = {
      at: new Date(2026, 9, 26, 15, 36).toISOString(),
      updates: 0,
      update: null,
      action: action({
        kind: "docker",
        name: "pihole-pihole-1",
        action: "restart",
        output: "port 53 is already allocated",
      }),
    };
    expect(downLatest(restart, null)).toEqual({
      time: "15:36",
      text: "Restart failed: port 53 is already allocated",
      failed: true,
    });
    expect(downLatest(undefined, "Auto-restart failed 2m ago")).toEqual({
      time: null,
      text: "Auto-restart failed 2m ago",
      failed: true,
    });
    expect(downLatest(undefined, null)).toBeNull();
  });

  it("sends an old /incidents link to Checks", () => {
    expect(incidentsRedirect("?status=open")).toBe("/checks?status=down");
    expect(incidentsRedirect("?status=resolved")).toBe("/checks");
    expect(incidentsRedirect("")).toBe("/checks");
  });
});
