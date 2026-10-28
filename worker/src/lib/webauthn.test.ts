import { describe, expect, it } from "vitest";

import { testPassphrase, testPasskey } from "../test/passkeys";
import { fromB64url, toB64url } from "./b64url";
import { assertionSynced, fingerprint, verifyAssertion } from "./webauthn";

const ORIGIN = "https://kry.example.test";
const RP = "kry.example.test";
const challenge = new Uint8Array(32).fill(7);

describe("webauthn", () => {
  it("verifies an assertion and reports user verification", async () => {
    const laptop = await testPasskey("bGFwdG9w");
    const signed = await laptop.sign({ challenge, origin: ORIGIN, rpId: RP });
    await expect(
      verifyAssertion(laptop, signed, { origin: ORIGIN, rpId: RP, challenge }),
    ).resolves.toEqual({ uv: true });
    const touch = await laptop.sign({
      challenge,
      origin: ORIGIN,
      rpId: RP,
      verified: false,
    });
    await expect(
      verifyAssertion(laptop, touch, { origin: ORIGIN, rpId: RP, challenge }),
    ).resolves.toEqual({ uv: false });
  });

  it("tells a synced passkey from one that stays on its device", () => {
    const data = (flags: number) => {
      const bytes = new Uint8Array(37);
      bytes[32] = flags;
      return toB64url(bytes);
    };
    expect(assertionSynced(data(0x1d))).toBe(true);
    expect(assertionSynced(data(0x05))).toBe(false);
  });

  it("refuses another challenge, origin, rp id or key", async () => {
    const laptop = await testPasskey("bGFwdG9w");
    const phone = await testPasskey("cGhvbmU");
    const signed = await laptop.sign({ challenge, origin: ORIGIN, rpId: RP });
    const expected = { origin: ORIGIN, rpId: RP, challenge };
    await expect(
      verifyAssertion(laptop, signed, {
        ...expected,
        challenge: new Uint8Array(32),
      }),
    ).rejects.toThrow(/challenge/u);
    await expect(
      verifyAssertion(laptop, signed, {
        ...expected,
        origin: "https://evil.test",
      }),
    ).rejects.toThrow(/origin/u);
    await expect(
      verifyAssertion(
        laptop,
        await laptop.sign({ challenge, origin: ORIGIN, rpId: "evil.test" }),
        expected,
      ),
    ).rejects.toThrow(/rp id/u);
    await expect(verifyAssertion(phone, signed, expected)).rejects.toThrow(
      /signature/u,
    );
  });

  it("fingerprints a key the way the agent does", async () => {
    const laptop = await testPasskey("bGFwdG9w");
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", fromB64url(laptop.publicKey)),
    );
    const hex = Array.from(digest, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    await expect(fingerprint(laptop.publicKey)).resolves.toBe(hex.slice(0, 16));
  });
});
