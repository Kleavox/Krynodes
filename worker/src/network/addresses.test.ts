import { describe, expect, it } from "vitest";

import { nextAddresses, type AddressRow } from "./addresses";

describe("nextAddresses", () => {
  it("gives never-used addresses first, in order", () => {
    expect(
      nextAddresses(
        "10.88.0.0/24",
        [
          { address: "10.88.0.1", state: "used", freed_at: null },
          {
            address: "10.88.0.2",
            state: "freed",
            freed_at: "2026-10-20T00:00:00Z",
          },
        ],
        2,
      ),
    ).toEqual(["10.88.0.3", "10.88.0.4"]);
  });

  it("never gives a held or used address, and freed ones last in the order they were freed", () => {
    const rows: AddressRow[] = Array.from({ length: 254 }, (_, index) => ({
      address: `10.88.3.${index + 1}`,
      state: "used",
      freed_at: null,
    }));
    rows[4] = {
      address: "10.88.3.5",
      state: "freed",
      freed_at: "2026-10-22T00:00:00Z",
    };
    rows[9] = {
      address: "10.88.3.10",
      state: "freed",
      freed_at: "2026-10-21T00:00:00Z",
    };
    rows[2] = { address: "10.88.3.3", state: "held", freed_at: null };
    expect(nextAddresses("10.88.3.0/24", rows, 2)).toEqual([
      "10.88.3.10",
      "10.88.3.5",
    ]);
  });

  it("refuses with a sentence when the range is full", () => {
    const rows = Array.from({ length: 254 }, (_, index) => ({
      address: `10.88.0.${index + 1}`,
      state: index === 7 ? ("held" as const) : ("used" as const),
      freed_at: null,
    }));
    expect(() => nextAddresses("10.88.0.0/24", rows, 1)).toThrow(
      "No address left in 10.88.0.0/24.",
    );
  });
});
