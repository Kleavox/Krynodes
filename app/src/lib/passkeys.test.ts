import { afterEach, describe, expect, it, vi } from "vitest";

import type { RegisterOptions } from "../types";
import {
  b64url,
  failure,
  fromB64url,
  nameFor,
  registerDevice,
} from "./passkeys";

const OPTIONS: RegisterOptions = {
  challenge: "c2VydmVyLWNoYWxsZW5nZQ",
  rpId: "kry.example.test",
  user: { id: "user-1", name: "owner@example.test" },
  exclude: ["b2xk"],
  expiresAt: "2026-11-22T10:05:00.000Z",
};

const authData = (flags: number) => {
  const bytes = new Uint8Array(37);
  bytes[32] = flags;
  return bytes.buffer;
};

function browser({
  created = 0x45,
  asserted = 0x05,
  transports = ["internal"],
} = {}) {
  const seen: {
    create?: CredentialCreationOptions;
    get?: CredentialRequestOptions;
  } = {};
  vi.stubGlobal("navigator", {
    credentials: {
      create: async (options: CredentialCreationOptions) => {
        seen.create = options;
        return {
          id: "bmV3",
          authenticatorAttachment: "platform",
          response: {
            getAuthenticatorData: () => authData(created),
            getPublicKey: () => new Uint8Array([9, 9]).buffer,
            getPublicKeyAlgorithm: () => -7,
            getTransports: () => transports,
          },
        };
      },
      get: async (options: CredentialRequestOptions) => {
        seen.get = options;
        return {
          id: "bmV3",
          authenticatorAttachment: "platform",
          response: {
            authenticatorData: authData(asserted),
            clientDataJSON: new TextEncoder().encode("{}").buffer,
            signature: new Uint8Array([4, 5]).buffer,
          },
        };
      },
    },
  });
  return seen;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("registering a passkey", () => {
  it("b64url round-trips without padding", () => {
    const bytes = new Uint8Array([0, 251, 255, 1]);
    expect(b64url(bytes)).toBe("APv_AQ");
    expect(fromB64url("APv_AQ")).toEqual(bytes);
  });

  it("creates the key, then signs one assertion over the server's challenge with it", async () => {
    const seen = browser();
    const body = await registerDevice(OPTIONS, "Laptop");
    const create = seen.create!.publicKey!;
    expect(create.rp.id).toBe("kry.example.test");
    expect(create.authenticatorSelection?.userVerification).toBe("required");
    expect(create.hints?.[0]).toBe("client-device");
    expect(
      create.excludeCredentials?.map((entry) => b64url(entry.id as Uint8Array)),
    ).toEqual(["b2xk"]);
    const get = seen.get!.publicKey!;
    expect(new Uint8Array(get.challenge as ArrayBuffer)).toEqual(
      fromB64url(OPTIONS.challenge),
    );
    expect(get.rpId).toBe("kry.example.test");
    expect(get.userVerification).toBe("required");
    expect(
      get.allowCredentials?.map((entry) => b64url(entry.id as Uint8Array)),
    ).toEqual(["bmV3"]);
    expect(body).toEqual({
      id: "bmV3",
      name: "Laptop",
      alg: -7,
      publicKey: b64url(new Uint8Array([9, 9])),
      challenge: OPTIONS.challenge,
      assertion: {
        credentialId: "bmV3",
        authenticatorData: b64url(new Uint8Array(authData(0x05))),
        clientDataJSON: b64url(new TextEncoder().encode("{}")),
        signature: b64url(new Uint8Array([4, 5])),
      },
    });
  });

  it("refuses a passkey that only takes a touch, when created or when it signs", async () => {
    browser({ created: 0x41 });
    await expect(registerDevice(OPTIONS, "Laptop")).rejects.toThrow(
      /was opened without your fingerprint, face or PIN/u,
    );
    browser({ asserted: 0x01 });
    await expect(registerDevice(OPTIONS, "Laptop")).rejects.toThrow(
      /was opened without your fingerprint, face or PIN/u,
    );
    browser({ created: 0x40 });
    await expect(registerDevice(OPTIONS, "Laptop")).rejects.toThrow(
      /was not touched/u,
    );
  });

  it("names a passkey after where it lives when the name was only guessed", async () => {
    expect(nameFor(["hybrid", "internal"], "Laptop")).toBe("Phone");
    expect(nameFor(["usb"], "Laptop")).toBe("Security Key");
    expect(nameFor(["internal"], "Laptop")).toBe("Laptop");
    browser({ transports: ["hybrid"] });
    await expect(
      registerDevice(OPTIONS, "Laptop", { guessed: true }),
    ).resolves.toMatchObject({ name: "Phone" });
    browser({ transports: ["hybrid"] });
    await expect(registerDevice(OPTIONS, "Work Laptop")).resolves.toMatchObject(
      { name: "Work Laptop" },
    );
  });
});

describe("failure", () => {
  it("says a passkey this browser already holds is registered", () => {
    expect(
      failure(new DOMException("previously registered", "InvalidStateError")),
    ).toBe("This passkey is already registered.");
  });

  it("points a cancelled or failed fingerprint to another way", () => {
    expect(failure(new DOMException("cancelled", "NotAllowedError"))).toMatch(
      /^The passkey was not confirmed/u,
    );
  });
});
