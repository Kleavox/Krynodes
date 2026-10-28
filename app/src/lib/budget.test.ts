import { describe, expect, it } from "vitest";

import {
  budgetLevel,
  estimateDailyUse,
  formatBytes,
  formatThousands,
  quotaLine,
} from "./budget";

const node = (
  id: string,
  interval = 60,
  extra: Partial<{
    disabled_at: string | null;
    enrolled_at: string | null;
  }> = {},
) => ({
  id,
  interval_seconds: interval,
  disabled_at: null,
  enrolled_at: "2026-09-01 00:00:00",
  ...extra,
});

const SHARE = { requests: 20_000, writes: 30_000, reads: 1_000_000 };

describe("estimateDailyUse", () => {
  it("charges a live connection a server row per window and almost no requests", () => {
    const nodes = ["a", "b", "c", "d", "e"].map((id) => node(id));
    expect(estimateDailyUse(nodes)).toEqual({
      writes: 4_320,
      requests: 3_120,
    });
  });

  it("charges nothing for pending and disabled nodes", () => {
    expect(
      estimateDailyUse([
        node("pending", 60, { enrolled_at: null }),
        node("off", 60, { disabled_at: "2026-09-02 00:00:00" }),
      ]),
    ).toEqual({ writes: 0, requests: 3_000 });
  });

  it("scales with the node interval", () => {
    expect(estimateDailyUse([node("slow", 600)])).toEqual({
      writes: 432,
      requests: 3_024,
    });
  });
});

describe("budget presentation", () => {
  it("warns from 80% of any share and flags going over", () => {
    expect(budgetLevel({ writes: 10_000, requests: 5_000 }, SHARE)).toBe("ok");
    expect(budgetLevel({ writes: 24_480, requests: 10_200 }, SHARE)).toBe(
      "warn",
    );
    expect(budgetLevel({ writes: 12_000, requests: 20_001 }, SHARE)).toBe(
      "over",
    );
    expect(budgetLevel({ writes: 1, requests: 1, reads: 900_000 }, SHARE)).toBe(
      "warn",
    );
    expect(
      budgetLevel(
        { writes: 24_480, requests: 10_200 },
        { ...SHARE, writes: 60_000 },
      ),
    ).toBe("ok");
  });

  it("formats thousands compactly", () => {
    expect(formatThousands(24_480)).toBe("24.5k");
    expect(formatThousands(30_000)).toBe("30k");
    expect(formatThousands(950)).toBe("950");
    expect(formatThousands(1_200_000)).toBe("1.2M");
  });
});

describe("quotaLine", () => {
  it("names whichever share is closer to its limit", () => {
    expect(quotaLine({ writes: 24_480, requests: 10_200 }, SHARE)).toEqual({
      percent: 82,
      detail: "24.5k of 30k writes",
    });
    expect(quotaLine({ writes: 6_000, requests: 15_000 }, SHARE)).toEqual({
      percent: 75,
      detail: "15k of 20k requests",
    });
    expect(
      quotaLine({ writes: 6_000, requests: 1_000, reads: 950_000 }, SHARE),
    ).toEqual({ percent: 95, detail: "950k of 1M reads" });
  });
});

describe("database size", () => {
  it("reads in KB below a megabyte and in MB above", () => {
    expect(formatBytes(800_000)).toBe("800 KB");
    expect(formatBytes(1_212_416)).toBe("1.2 MB");
    expect(formatBytes(25_400_000)).toBe("25 MB");
    expect(formatBytes(500_000_000)).toBe("500 MB");
  });
});
