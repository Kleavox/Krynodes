import { describe, expect, it } from "vitest";

import {
  checkDisplayStatus,
  clockTime,
  countdown,
  dayLabel,
  displayHandle,
  formatBytes,
  formatDuration,
  formatUptime,
  graceSeconds,
  metricText,
  nodeState,
  parseTimestamp,
  percentage,
  publicLabel,
  shortDate,
  stampTime,
  timeAgo,
} from "./format";

const NOW = Date.parse("2026-09-27T12:00:00Z");

describe("parseTimestamp", () => {
  it("reads a zoneless SQLite timestamp as UTC", () => {
    expect(parseTimestamp("2026-09-27 08:00:00")).toBe(
      Date.parse("2026-09-27T08:00:00Z"),
    );
  });

  it("reads ISO timestamps as given", () => {
    expect(parseTimestamp("2026-09-27T08:00:00.000Z")).toBe(
      Date.parse("2026-09-27T08:00:00Z"),
    );
  });
});

describe("nodeState", () => {
  const base = {
    disabled_at: null,
    enrolled_at: "2026-09-01 00:00:00",
    last_seen_at: "2026-09-27 11:58:00",
    interval_seconds: 60,
  };

  it("checks disabled, then pending, then liveness", () => {
    expect(
      nodeState({ ...base, disabled_at: "2026-09-02 00:00:00" }, NOW),
    ).toBe("disabled");
    expect(nodeState({ ...base, enrolled_at: null }, NOW)).toBe("pending");
    expect(nodeState({ ...base, last_seen_at: null }, NOW)).toBe("offline");
  });

  it("is online within max(90s, 3 x interval) and offline after", () => {
    expect(
      nodeState({ ...base, last_seen_at: "2026-09-27 11:57:01" }, NOW),
    ).toBe("online");
    expect(
      nodeState({ ...base, last_seen_at: "2026-09-27 11:56:59" }, NOW),
    ).toBe("offline");
    expect(graceSeconds(15)).toBe(90);
    expect(graceSeconds(600)).toBe(1800);
  });

  it("honours a wider grace the server sends for a live connection", () => {
    expect(
      nodeState(
        { ...base, last_seen_at: "2026-09-27 11:54:00", grace_seconds: 420 },
        NOW,
      ),
    ).toBe("online");
    expect(
      nodeState(
        { ...base, last_seen_at: "2026-09-27 11:52:59", grace_seconds: 420 },
        NOW,
      ),
    ).toBe("offline");
  });

  it("treats a last_seen_at slightly in the future as online", () => {
    expect(
      nodeState({ ...base, last_seen_at: "2026-09-27 12:00:04" }, NOW),
    ).toBe("online");
  });
});

describe("numbers", () => {
  it("never turns a missing or zero total into a percentage", () => {
    expect(percentage(4, 0)).toBeNull();
    expect(percentage(null, 8)).toBeNull();
    expect(percentage(4, null)).toBeNull();
    expect(percentage(2, 8)).toBe(25);
  });

  it("renders unmeasured values as --", () => {
    expect(metricText(null)).toBe("--");
    expect(metricText(Number.NaN, "%")).toBe("--");
    expect(metricText(34.26, "%")).toBe("34%");
    expect(metricText(0.414)).toBe("0.4");
    expect(metricText(0, "%")).toBe("0.0%");
  });

  it("formats bytes in binary units", () => {
    expect(formatBytes(null)).toBe("--");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(6_120_000_000)).toBe("5.7 GB");
    expect(formatBytes(126_701_535_232)).toBe("118 GB");
  });
});

describe("durations", () => {
  it("formats compact durations", () => {
    expect(formatDuration(45_000)).toBe("45s");
    expect(formatDuration(18 * 60_000)).toBe("18m");
    expect(formatDuration(125 * 60_000)).toBe("2h 5m");
    expect(formatDuration(2 * 3_600_000)).toBe("2h");
    expect(formatDuration((4 * 24 + 4) * 3_600_000)).toBe("4d 4h");
    expect(formatDuration(-5_000)).toBe("0s");
    expect(formatUptime(null)).toBe("--");
    expect(formatUptime(1_051_200)).toBe("12d 4h");
  });

  it("says how long ago, and never a negative age", () => {
    expect(timeAgo(null, NOW)).toBe("never");
    expect(timeAgo("2026-09-27 11:59:18", NOW)).toBe("42s ago");
    expect(timeAgo("2026-09-27 12:00:03", NOW)).toBe("just now");
    expect(timeAgo("2026-09-27T09:00:00Z", NOW)).toBe("3h ago");
  });

  it("counts down in mm:ss", () => {
    expect(countdown(29 * 60_000 + 41_000)).toBe("29:41");
    expect(countdown(5_000)).toBe("00:05");
    expect(countdown(-1)).toBe("00:00");
  });
});

describe("dates", () => {
  it("labels days relative to now in local time", () => {
    const now = new Date(2026, 8, 27, 12, 0).getTime();
    expect(dayLabel(new Date(2026, 8, 27, 1, 0).toISOString(), now)).toBe(
      "Today",
    );
    expect(dayLabel(new Date(2026, 8, 26, 23, 0).toISOString(), now)).toBe(
      "Yesterday",
    );
    expect(dayLabel(new Date(2026, 8, 23, 9, 0).toISOString(), now)).toBe(
      "23 Sep",
    );
  });

  it("formats clock times and short dates", () => {
    const at = new Date(2026, 8, 23, 14, 2).toISOString();
    expect(clockTime(at)).toBe("14:02");
    expect(shortDate(at)).toBe("23 Sep");
  });

  it("stamps a time with its day unless it is today", () => {
    const now = new Date(2026, 9, 24, 13, 0).getTime();
    expect(stampTime(new Date(2026, 9, 24, 0, 5).toISOString(), now)).toBe(
      "00:05",
    );
    expect(stampTime(new Date(2026, 9, 19, 12, 39).toISOString(), now)).toBe(
      "19 Oct 12:39",
    );
  });
});

describe("checkDisplayStatus", () => {
  it("trusts a check result only while its node is online", () => {
    expect(checkDisplayStatus("UP", "online")).toBe("UP");
    expect(checkDisplayStatus("DOWN", "online")).toBe("DOWN");
    expect(checkDisplayStatus("UP", "offline")).toBe("STALE");
    expect(checkDisplayStatus("DOWN", "disabled")).toBe("STALE");
    expect(checkDisplayStatus("UNKNOWN", "pending")).toBe("UNKNOWN");
  });

  it("shows a paused check as paused whatever it last reported", () => {
    expect(checkDisplayStatus("DOWN", "online", false)).toBe("PAUSED");
    expect(checkDisplayStatus("UP", "offline", false)).toBe("PAUSED");
    expect(checkDisplayStatus("UP", "online", true)).toBe("UP");
  });
});

describe("displayHandle", () => {
  it("returns the username when present", () => {
    expect(displayHandle("ada_lovelace")).toBe("ada_lovelace");
  });

  it("falls back to the email local part", () => {
    expect(displayHandle(null, "norm@example.com")).toBe("norm");
    expect(displayHandle("", "norm@example.com")).toBe("norm");
  });

  it("falls back to a generic label", () => {
    expect(displayHandle(null, null)).toBe("Account");
    expect(displayHandle(undefined, undefined)).toBe("Account");
  });
});

describe("publicLabel", () => {
  it("marks public checks and says when the page hides a paused one", () => {
    expect(publicLabel({ public: 0, enabled: 1 })).toBeNull();
    expect(publicLabel({ public: 1, enabled: 1 })).toBe("public");
    expect(publicLabel({ public: 1, enabled: 0 })).toBe("public · paused");
  });
});
