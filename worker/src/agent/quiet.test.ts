import { describe, expect, it } from "vitest";

import { quietByNode, quietSpans } from "./quiet";

const WINDOW = 300_000;
const at = (time: string) => Date.parse(`2026-10-24T${time}:00.000Z`);
const iso = (time: string) => new Date(at(time)).toISOString();
const DAYS = 37 * 86_400;

const reported = (from: string, to: string, uptimeSeconds = DAYS) => {
  const windows = [];
  for (let start = at(from); start <= at(to); start += WINDOW) {
    windows.push({ start, uptimeSeconds });
  }
  return windows;
};

const base = {
  windowMs: WINDOW,
  from: at("02:00"),
  graceMs: 180_000,
  rebootHour: 3,
  rebootPending: false,
};

describe("when a server went quiet", () => {
  it("finds nothing while the server reported every window", () => {
    expect(
      quietSpans({
        ...base,
        windows: reported("02:00", "03:55"),
        now: at("04:00") + 30_000,
        lastSeen: at("04:00") + 10_000,
      }),
    ).toEqual([]);
  });

  it("calls a silence without a reboot offline", () => {
    expect(
      quietSpans({
        ...base,
        windows: [...reported("02:00", "02:25"), ...reported("02:50", "03:55")],
        now: at("04:00") + 30_000,
        lastSeen: at("04:00") + 10_000,
      }),
    ).toEqual([{ from: iso("02:30"), to: iso("02:50"), why: "offline" }]);
  });

  it("calls a reboot in the restart hour a routine restart, for 10 minutes at most", () => {
    expect(
      quietSpans({
        ...base,
        windows: [
          ...reported("02:00", "02:55"),
          ...reported("03:20", "03:20", 180),
          ...reported("03:25", "03:55", 480),
        ],
        now: at("04:00") + 30_000,
        lastSeen: at("04:00") + 10_000,
      }),
    ).toEqual([
      { from: iso("03:00"), to: iso("03:10"), why: "routine" },
      { from: iso("03:10"), to: iso("03:20"), why: "offline" },
    ]);
  });

  it("calls a reboot outside the restart hour offline, like a pulled plug", () => {
    expect(
      quietSpans({
        ...base,
        rebootHour: 5,
        windows: [
          ...reported("02:00", "02:55"),
          ...reported("03:10", "03:55", 400),
        ],
        now: at("04:00") + 30_000,
        lastSeen: at("04:00") + 10_000,
      }),
    ).toEqual([{ from: iso("03:00"), to: iso("03:10"), why: "offline" }]);
  });

  it("keeps an ongoing silence open, routine only while a restart waits in its hour", () => {
    const quiet = {
      ...base,
      windows: reported("02:00", "02:55"),
      lastSeen: at("03:00") - 20_000,
    };
    expect(quietSpans({ ...quiet, now: at("03:02") })).toEqual([]);
    expect(quietSpans({ ...quiet, now: at("03:06") })).toEqual([
      { from: iso("03:00"), to: null, why: "offline" },
    ]);
    expect(
      quietSpans({ ...quiet, rebootPending: true, now: at("03:06") }),
    ).toEqual([{ from: iso("03:00"), to: iso("03:10"), why: "routine" }]);
    expect(
      quietSpans({ ...quiet, rebootPending: true, now: at("03:30") }),
    ).toEqual([
      { from: iso("03:00"), to: iso("03:10"), why: "routine" },
      { from: iso("03:10"), to: null, why: "offline" },
    ]);
  });

  it("calls the start of the range quiet when the server came back inside it", () => {
    expect(
      quietSpans({
        ...base,
        windows: reported("02:30", "03:55"),
        now: at("04:00") + 30_000,
        lastSeen: at("04:00") + 10_000,
      }),
    ).toEqual([{ from: iso("02:00"), to: iso("02:30"), why: "offline" }]);
  });
});

describe("quarantined spans", () => {
  const node = (quarantines?: string | null) => ({
    id: "n1",
    interval_seconds: 60,
    last_seen_at: "2026-10-24 03:59:50",
    security: null,
    ...(quarantines === undefined ? {} : { quarantines }),
  });
  const windows = reported("02:00", "03:55").map((window) => ({
    node_id: "n1",
    window_start: new Date(window.start).toISOString(),
    uptime_seconds: window.uptimeSeconds,
  }));
  const quiet = (quarantines?: string | null) =>
    quietByNode(windows, [node(quarantines)], at("02:00"), at("04:00"))["n1"]!
      .quiet;

  it("runs from the start of the range while a quarantine opened before it is open", () => {
    expect(
      quiet(JSON.stringify([{ at: "2026-10-23 22:00:00", releasedAt: null }])),
    ).toEqual([{ from: iso("02:00"), to: null, why: "quarantined" }]);
  });

  it("runs from its start to its release inside the range", () => {
    expect(
      quiet(
        JSON.stringify([
          { at: "2026-10-24 02:30:00", releasedAt: "2026-10-24 03:10:00" },
        ]),
      ),
    ).toEqual([{ from: iso("02:30"), to: iso("03:10"), why: "quarantined" }]);
  });

  it("leaves out one released before the range, and a node without the column", () => {
    expect(
      quiet(
        JSON.stringify([
          { at: "2026-10-23 20:00:00", releasedAt: "2026-10-23 21:00:00" },
        ]),
      ),
    ).toEqual([]);
    expect(quiet()).toEqual([]);
    expect(quiet(null)).toEqual([]);
    expect(quiet("not json")).toEqual([]);
  });
});
