import { describe, expect, it } from "vitest";

import {
  barTone,
  incidentDuring,
  findGaps,
  heartbeatSummary,
  isLonePoint,
  layoutReportSlots,
  seriesSummary,
  slotTip,
  sparklineSegments,
  untilWindowSettles,
  uptimeTip,
  withGapBreaks,
} from "./series";

describe("findGaps", () => {
  const range = { from: 0, to: 600_000 };

  it("treats the whole range as a gap when there is no data", () => {
    expect(findGaps([], 180, range)).toEqual([{ from: 0, to: 600_000 }]);
  });

  it("ignores spacing within the limit, so jitter is not an outage", () => {
    expect(
      findGaps([0, 120_000, 240_000, 360_000, 480_000, 600_000], 180, range),
    ).toEqual([]);
  });

  it("allows the bucket still in progress at the right edge", () => {
    expect(findGaps([0, 300_000], 300, { from: 0, to: 700_000 }, 300)).toEqual(
      [],
    );
    expect(
      findGaps([0, 300_000], 300, { from: 0, to: 1_000_000 }, 300),
    ).toEqual([{ from: 300_000, to: 1_000_000 }]);
  });

  it("marks leading, interior and trailing silences longer than the limit", () => {
    expect(findGaps([200_000, 260_000, 500_000], 180, range)).toEqual([
      { from: 0, to: 200_000 },
      { from: 260_000, to: 500_000 },
    ]);
    expect(findGaps([0, 60_000], 180, range)).toEqual([
      { from: 60_000, to: 600_000 },
    ]);
  });
});

describe("withGapBreaks", () => {
  it("inserts one blank row inside each interior gap so the line breaks", () => {
    const rows: { time: number; v: number | null }[] = [
      { time: 0, v: 1 },
      { time: 60_000, v: 2 },
      { time: 400_000, v: 3 },
    ];
    const gaps = [
      { from: 60_000, to: 400_000 },
      { from: 400_000, to: 600_000 },
    ];
    expect(withGapBreaks(rows, gaps, (time) => ({ time, v: null }))).toEqual([
      { time: 0, v: 1 },
      { time: 60_000, v: 2 },
      { time: 230_000, v: null },
      { time: 400_000, v: 3 },
    ]);
  });
});

describe("layoutReportSlots", () => {
  const minute = 60_000;
  const now = 100 * minute + 30_000;

  it("ends at the newest slot the data can judge", () => {
    const sample = { t: new Date(99 * minute).toISOString() };
    const laid = layoutReportSlots({
      slots: [sample],
      slotSeconds: 60,
      graceSeconds: 180,
      since: 0,
      now,
    });
    expect(laid).toHaveLength(30);
    expect(laid[29]!.start).toBe(99 * minute);
    expect(laid[29]!.state).toBe("received");
    expect(laid[29]!.sample).toBe(sample);
  });

  it("moves on only when the new slot has its report", () => {
    const laid = layoutReportSlots({
      slots: [{ t: new Date(100 * minute + 5_000).toISOString() }],
      slotSeconds: 60,
      graceSeconds: 180,
      since: 0,
      now,
    });
    expect(laid[29]!.start).toBe(100 * minute);
    expect(laid[29]!.state).toBe("received");
  });

  it("leaves silence off the strip until it counts as missed", () => {
    const laid = layoutReportSlots({
      slots: [],
      slotSeconds: 60,
      graceSeconds: 180,
      since: 0,
      now,
    });
    expect(laid).toHaveLength(30);
    expect(laid[29]!.start).toBe(97 * minute);
    expect(laid.every((slot) => slot.state === "missed")).toBe(true);
  });

  it("judges silence against the age of the data, not the clock", () => {
    const laid = layoutReportSlots({
      slots: [],
      slotSeconds: 60,
      graceSeconds: 180,
      since: 0,
      now,
      asOf: 97 * minute + 10_000,
    });
    expect(laid[29]!.start).toBe(94 * minute);
    expect(laid[29]!.state).toBe("missed");
  });

  it("keeps a gap between two reports as pending while it is young", () => {
    const laid = layoutReportSlots({
      slots: [
        { t: new Date(98 * minute).toISOString() },
        { t: new Date(100 * minute).toISOString() },
      ],
      slotSeconds: 60,
      graceSeconds: 180,
      since: 0,
      now,
    });
    expect(laid[29]!.state).toBe("received");
    expect(laid[28]!.state).toBe("pending");
    expect(laid[27]!.state).toBe("received");
  });

  it("waits for the window to end on a live connection, whose row is written then", () => {
    const window = 300_000;
    const start = 1_000 * window;
    const live = (asOf: number, slots: { t: string }[] = []) =>
      layoutReportSlots({
        slots,
        slotSeconds: 300,
        graceSeconds: 180,
        settleSeconds: 300,
        since: 0,
        now: asOf,
        asOf,
      });
    const young = live(start + 400_000, [
      { t: new Date(start - window).toISOString() },
    ]);
    expect(young[29]!.start).toBe(start - window);
    expect(young[29]!.state).toBe("received");
    const late = live(start + window + 200_000);
    expect(late[29]!.start).toBe(start);
    expect(late[29]!.state).toBe("missed");
  });

  it("shows slots before enrollment as none", () => {
    const laid = layoutReportSlots({
      slots: [],
      slotSeconds: 60,
      graceSeconds: 180,
      since: 95 * minute,
      now,
    });
    expect(laid[0]!.start).toBe(68 * minute);
    expect(laid[26]!.state).toBe("none");
    expect(laid[27]!.state).toBe("missed");
    expect(laid[29]!.start).toBe(97 * minute);
  });

  it("shows every slot as none for a node that never enrolled", () => {
    const laid = layoutReportSlots({
      slots: [],
      slotSeconds: 60,
      graceSeconds: 180,
      since: null,
      now,
    });
    expect(laid.every((slot) => slot.state === "none")).toBe(true);
    expect(laid[29]!.start).toBe(100 * minute);
  });

  it("spans 30 hours for a node reporting hourly", () => {
    const hour = 3_600_000;
    const laid = layoutReportSlots({
      slots: [{ t: new Date(80 * hour).toISOString() }],
      slotSeconds: 3600,
      graceSeconds: 10_800,
      since: 0,
      now: 100 * hour + 1,
    });
    expect(laid[0]!.start).toBe(68 * hour);
    expect(laid.findIndex((slot) => slot.state === "received")).toBe(12);
  });
});

describe("untilWindowSettles", () => {
  const window = 300_000;
  const boundary = 1_000 * window;

  it("fetches after agents report at the top of each window and live windows are written", () => {
    expect(untilWindowSettles(boundary + 10_000)).toBe(35_000);
    expect(untilWindowSettles(boundary + 100_000)).toBe(245_000);
  });

  it("never schedules a fetch for the moment it is called", () => {
    expect(untilWindowSettles(boundary + 45_000)).toBe(window);
  });

  it("aligns to shorter windows too", () => {
    expect(untilWindowSettles(boundary + 20_000, 60_000)).toBe(25_000);
  });
});

describe("incidentDuring", () => {
  const MIN = 60_000;
  const at = (clock: string) => Date.parse(`2026-09-28T${clock}:00Z`);
  const incidents = [
    {
      id: "i1",
      started_at: "2026-09-28T12:00:30.000Z",
      resolved_at: "2026-09-28 12:20:00",
    },
    { id: "i2", started_at: "2026-09-28T13:00:00.000Z", resolved_at: null },
  ];

  it("counts the window of the first failure, one report before the incident opened", () => {
    expect(incidentDuring(at("11:55"), 5 * MIN, incidents)?.id).toBe("i1");
    expect(incidentDuring(at("11:50"), 5 * MIN, incidents)).toBeUndefined();
  });

  it("ends at the report that resolved the incident", () => {
    expect(incidentDuring(at("12:15"), 5 * MIN, incidents)?.id).toBe("i1");
    expect(incidentDuring(at("12:20"), 5 * MIN, incidents)).toBeUndefined();
  });

  it("keeps an open incident running", () => {
    expect(incidentDuring(at("15:00"), 5 * MIN, incidents)?.id).toBe("i2");
  });

  it("treats a failure with no incident as brief", () => {
    expect(incidentDuring(at("12:00"), 5 * MIN, [])).toBeUndefined();
  });
});

describe("summaries", () => {
  it("summarises heartbeat windows, counting the empty ones", () => {
    expect(heartbeatSummary([null, null], "4 hours")).toBe(
      "No results in the last 4 hours",
    );
    expect(heartbeatSummary(["UP", "DOWN", null, "UP"], "4 hours")).toBe(
      "2 up, 1 down, 1 without results in the last 4 hours",
    );
  });

  it("summarises a series without inventing data", () => {
    expect(seriesSummary([null, null], (value) => `${value}%`)).toBe(
      "No data in this range",
    );
    expect(seriesSummary([10, null, 30, 20], (value) => `${value}%`)).toBe(
      "now 20%, min 10%, max 30%, average 20%",
    );
  });
});

describe("sparklineSegments", () => {
  it("scales values to the box and breaks at nulls", () => {
    expect(sparklineSegments([0, 100, null, 50, 50], 100, 100, 28)).toEqual([
      "0,28 25,0",
      "75,14 100,14",
    ]);
  });

  it("draws a lone point as a zero-length segment so it shows as a dot", () => {
    expect(sparklineSegments([null, 40, null], 100, 100, 28)).toEqual([
      "50,16.8 50,16.8",
    ]);
  });

  it("clamps out-of-range values and handles an empty series", () => {
    expect(sparklineSegments([], 100)).toEqual([]);
    expect(sparklineSegments([150, -5], 100, 100, 28)).toEqual(["0,0 100,28"]);
  });
});

describe("isLonePoint", () => {
  it("is true only for a value with no measured neighbour", () => {
    const values = [null, 5, null, 1, 2];
    expect(values.map((_, index) => isLonePoint(values, index))).toEqual([
      false,
      true,
      false,
      false,
      false,
    ]);
    expect(isLonePoint([7], 0)).toBe(true);
  });
});

describe("uptime tooltip", () => {
  const result = (t: string, status: "UP" | "DOWN") => ({
    t,
    status,
    latencyMs: 20,
    message: null,
  });
  const clock = (value: string) => `at ${value.slice(11, 16)}`;

  it("says since when, how many reports were up and when it was last down", () => {
    expect(
      uptimeTip(
        [
          result("2026-09-30T06:10:00.000Z", "UP"),
          result("2026-09-30T06:15:00.000Z", "DOWN"),
          result("2026-09-30T06:20:00.000Z", "DOWN"),
          result("2026-09-30T06:25:00.000Z", "UP"),
        ],
        clock,
      ),
    ).toBe("Since at 06:10\n2 of 4 reports up\nLast down at 06:20");
  });

  it("says when nothing went down or nothing was reported", () => {
    expect(uptimeTip([result("2026-09-30T06:10:00.000Z", "UP")], clock)).toBe(
      "Since at 06:10\n1 of 1 reports up\nNo downtime recorded",
    );
    expect(uptimeTip([], clock)).toBe("No reports yet");
  });
});

describe("bar tooltips", () => {
  const clock = () => "06:10";
  const result = (status: "UP" | "DOWN", latencyMs: number | null) => ({
    t: "2026-09-30T06:10:00.000Z",
    status,
    latencyMs,
    message:
      status === "DOWN"
        ? "dial tcp 10.0.0.5:443: connect: connection refused"
        : null,
  });

  it("shows a failed window like a good one, without its error", () => {
    expect(slotTip(0, result("UP", 41), false, clock)).toBe(
      "06:10 · UP · 41ms",
    );
    expect(slotTip(0, result("DOWN", null), false, clock)).toBe("06:10 · DOWN");
    expect(slotTip(0, result("DOWN", null), true, clock)).toBe(
      "06:10 · DOWN, no incident",
    );
    expect(slotTip(0, null, false, clock)).toBe("06:10 · no result");
  });
});

describe("bar tones", () => {
  it("paints a window with no result red once the check existed", () => {
    expect(barTone("missed", null, false)).toBe("missed");
    expect(barTone("none", null, false)).toBe("empty");
    expect(barTone("pending", null, false)).toBe("empty");
    expect(barTone("received", "UP", false)).toBe("up");
    expect(barTone("received", "DOWN", true)).toBe("down");
    expect(barTone("received", "DOWN", false)).toBe("brief");
  });
});

describe("maintenance", () => {
  it("paints a silent or failing window during planned work as maintenance", () => {
    const now = Date.parse("2026-10-01T12:00:00.000Z");
    const laid = layoutReportSlots({
      slots: [{ t: "2026-10-01T11:40:00.000Z" }],
      slotSeconds: 300,
      graceSeconds: 120,
      since: now - 3_600_000,
      now,
      count: 4,
      maintenance: [{ from: now - 15 * 60_000, to: now - 12 * 60_000 }],
    });
    expect(laid.map((slot) => slot.state)).toEqual([
      "received",
      "maintenance",
      "missed",
      "missed",
    ]);
    expect(barTone("maintenance", null, false)).toBe("maintenance");
    expect(barTone("received", "DOWN", false, true)).toBe("maintenance");
    expect(barTone("received", "DOWN", true, true)).toBe("down");
    expect(barTone("received", "UP", false, true)).toBe("up");
  });
});
