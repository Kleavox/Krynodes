import { describe, expect, it } from "vitest";

import { split } from "./shamir";

const secret = new TextEncoder().encode("cf-token-0123456789abcdef");

describe("splitting the Cloudflare token", () => {
  it("makes one numbered piece per holder, none showing the token", () => {
    const pieces = split(secret, 3);
    expect(pieces.map((piece) => piece[0])).toEqual([1, 2, 3]);
    for (const piece of pieces) {
      expect(piece.length).toBe(secret.length + 1);
      expect(new TextDecoder().decode(piece)).not.toContain("cf-token");
    }
  });

  it("keeps the whole token with a single holder", () => {
    const [piece] = split(secret, 1);
    expect(piece![0]).toBe(0);
    expect(piece!.slice(1)).toEqual(secret);
  });

  it("refuses an empty token or too many holders", () => {
    expect(() => split(new Uint8Array(), 2)).toThrow();
    expect(() => split(secret, 0)).toThrow();
    expect(() => split(secret, 256)).toThrow();
  });
});
