import { afterEach, describe, expect, it, vi } from "vitest";

import {
  b64url,
  createSession,
  registerDevice,
  actionCommand,
  fromB64url,
  signCommand,
  signIntent,
  signTargets,
  approveChange,
  nameFor,
  thisBrowser,
} from "./passkeys";

const T = Date.parse("2026-09-29T10:00:00.000Z");
const MINUTE = 60_000;
const decode = (text: string) =>
  JSON.parse(new TextDecoder().decode(fromB64url(text))) as Record<
    string,
    unknown
  >;

const authData = (flags: number) => {
  const bytes = new Uint8Array(37);
  bytes[32] = flags;
  return bytes.buffer;
};

function authenticator(flags = 0x05, attachment = "platform") {
  const seen: Uint8Array[] = [];
  vi.stubGlobal("navigator", {
    credentials: {
      get: async (options: CredentialRequestOptions) => {
        seen.push(new Uint8Array(options.publicKey!.challenge as ArrayBuffer));
        return {
          id: "ZGV2aWNl",
          authenticatorAttachment: attachment,
          response: {
            authenticatorData: authData(flags),
            clientDataJSON: new TextEncoder().encode("{}").buffer,
            signature: new Uint8Array([4, 5]).buffer,
          },
        };
      },
    },
  });
  return seen;
}

const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("passkeys", () => {
  it("b64url round-trips without padding", () => {
    const bytes = new Uint8Array([0, 251, 255, 1]);
    expect(b64url(bytes)).toBe("APv_AQ");
    expect(fromB64url("APv_AQ")).toEqual(bytes);
  });

  it("builds a grant whose challenge is the SHA-256 of its bytes", async () => {
    const seen = authenticator();
    const session = await createSession(["ZGV2aWNl"], "kry.example.test", T);
    const grantBytes = fromB64url(session.grant.grant);
    expect(seen[0]).toEqual(await sha256(grantBytes));
    expect(decode(session.grant.grant)).toMatchObject({
      v: 1,
      rpId: "kry.example.test",
      issuedAt: new Date(T).toISOString(),
      expiresAt: new Date(T + 5 * MINUTE).toISOString(),
    });
    expect(session.grant).toMatchObject({
      credentialId: "ZGV2aWNl",
      authenticatorData: b64url(authData(0x05)),
      clientDataJSON: "e30",
      signature: "BAU",
    });
    expect(session.expiresAt).toBe(T + 5 * MINUTE);
  });

  it("signs a command the session key verifies (P1363)", async () => {
    authenticator();
    const session = await createSession(["ZGV2aWNl"], "kry.example.test", T);
    const command = actionCommand(
      {
        id: "55555555-5555-4555-8555-555555555555",
        nodeId: "11111111-1111-4111-8111-111111111111",
        kind: "compose",
        name: "listmonk",
        action: "deploy",
      },
      session,
      T + MINUTE,
    );
    const signed = await signCommand(session, command);
    const key = await crypto.subtle.importKey(
      "spki",
      fromB64url(decode(session.grant.grant).sessionKey as string),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const signature = fromB64url(signed.signature);
    expect(signature).toHaveLength(64);
    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        signature,
        fromB64url(signed.command),
      ),
    ).toBe(true);
    expect(decode(signed.command)).toEqual({
      v: 1,
      id: "55555555-5555-4555-8555-555555555555",
      nodeId: "11111111-1111-4111-8111-111111111111",
      kind: "compose",
      name: "listmonk",
      action: "deploy",
      issuedAt: new Date(T + MINUTE).toISOString(),
      expiresAt: new Date(T + 65 * MINUTE).toISOString(),
    });
    expect(signed.grant).toBe(session.grant);
  });

  it("approves a change with an assertion over its exact bytes", async () => {
    const seen = authenticator();
    const change = b64url(new TextEncoder().encode('{"v":2}'));
    const approval = await approveChange(
      change,
      ["ZGV2aWNl"],
      "kry.example.test",
    );
    expect(seen[0]).toEqual(await sha256(fromB64url(change)));
    expect(approval).toEqual({
      credentialId: "ZGV2aWNl",
      authenticatorData: b64url(authData(0x05)),
      clientDataJSON: "e30",
      signature: "BAU",
    });
  });

  it("remembers the passkeys this browser used", async () => {
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => store.set(key, value),
    });
    expect(thisBrowser()).toEqual([]);
    authenticator();
    await createSession(["ZGV2aWNl"], "kry.example.test", T);
    await createSession(["ZGV2aWNl"], "kry.example.test", T);
    expect(thisBrowser()).toEqual(["ZGV2aWNl"]);
    store.clear();
    authenticator(0x05, "cross-platform");
    await createSession(["ZGV2aWNl"], "kry.example.test", T);
    expect(thisBrowser()).toEqual([]);
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    });
    expect(thisBrowser()).toEqual([]);
    await expect(
      createSession(["ZGV2aWNl"], "kry.example.test", T),
    ).resolves.toBeDefined();
  });

  it("signs every target before anything is sent", async () => {
    authenticator();
    const session = await createSession(["ZGV2aWNl"], "kry.example.test", T);
    const targets = await signTargets(
      session,
      "rollback",
      [
        {
          nodeId: "11111111-1111-4111-8111-111111111111",
          kind: "compose",
          name: "listmonk",
        },
      ],
      T + MINUTE,
    );
    expect(targets).toHaveLength(1);
    const [target] = targets;
    expect(target).toMatchObject({
      nodeId: "11111111-1111-4111-8111-111111111111",
      kind: "compose",
      name: "listmonk",
    });
    expect(decode(target!.signed.command)).toMatchObject({
      id: target!.id,
      action: "rollback",
      name: "listmonk",
    });
    expect(target).not.toHaveProperty("session");
  });

  it("signs a service action with its own kind", async () => {
    authenticator();
    const session = await createSession(["ZGV2aWNl"], "kry.example.test", T);
    const [target] = await signTargets(
      session,
      "restart",
      [
        {
          nodeId: "11111111-1111-4111-8111-111111111111",
          kind: "docker",
          name: "adguard",
        },
      ],
      T + MINUTE,
    );
    expect(target).toMatchObject({ kind: "docker", name: "adguard" });
    expect(decode(target!.signed.command)).toMatchObject({
      id: target!.id,
      nodeId: "11111111-1111-4111-8111-111111111111",
      kind: "docker",
      name: "adguard",
      action: "restart",
    });
  });

  it("signs a new stack's compose file into its command, and nothing else carries one", async () => {
    authenticator();
    const session = await createSession(["ZGV2aWNl"], "kry.example.test", T);
    const compose = "services:\n  web:\n    image: nginx\n";
    const [created, restarted] = await Promise.all([
      signTargets(
        session,
        "create",
        [
          {
            nodeId: "11111111-1111-4111-8111-111111111111",
            kind: "compose",
            name: "web",
            compose,
          },
        ],
        T + MINUTE,
      ),
      signTargets(
        session,
        "restart",
        [
          {
            nodeId: "11111111-1111-4111-8111-111111111111",
            kind: "docker",
            name: "adguard",
          },
        ],
        T + MINUTE,
      ),
    ]);
    expect(decode(created[0]!.signed.command)).toMatchObject({
      action: "create",
      compose,
    });
    expect(created[0]).not.toHaveProperty("compose");
    expect(decode(restarted[0]!.signed.command)).not.toHaveProperty("compose");
  });

  it("always asks for a fingerprint, the device's own first", async () => {
    const asked: CredentialRequestOptions[] = [];
    vi.stubGlobal("navigator", {
      credentials: {
        get: async (options: CredentialRequestOptions) => {
          asked.push(options);
          return {
            id: "ZGV2aWNl",
            authenticatorAttachment: "platform",
            response: {
              authenticatorData: authData(0x01),
              clientDataJSON: new TextEncoder().encode("{}").buffer,
              signature: new Uint8Array([4, 5]).buffer,
            },
          };
        },
      },
    });
    await createSession(["ZGV2aWNl"], "kry.example.test", T).catch(() => null);
    expect(asked[0]?.publicKey?.userVerification).toBe("required");
    expect(asked[0]?.publicKey?.hints?.[0]).toBe("client-device");
  });

  it("refuses a passkey that reports presence without verification", async () => {
    authenticator(0x19);
    await expect(
      createSession(["ZGV2aWNl"], "kry.example.test", T),
    ).rejects.toThrow(/did not verify a fingerprint/u);
  });

  it("stops at once when the passkey was not touched", async () => {
    authenticator(0x00);
    await expect(
      createSession(["ZGV2aWNl"], "kry.example.test", T),
    ).rejects.toThrow(/was not touched.*flags 0x00, platform/u);
  });

  it("refuses to set up a passkey that was not touched", async () => {
    const created = (flags: number) => ({
      create: async () => ({
        id: "bmV3",
        response: {
          getAuthenticatorData: () => authData(flags),
          getPublicKey: () => new Uint8Array([9, 9]).buffer,
          getPublicKeyAlgorithm: () => -7,
        },
      }),
    });
    const user = { id: "operator", name: "operator" };
    vi.stubGlobal("navigator", { credentials: created(0x40) });
    await expect(
      registerDevice("Laptop", "kry.example.test", user, []),
    ).rejects.toThrow(/was not touched/u);
    vi.stubGlobal("navigator", { credentials: created(0x59) });
    await expect(
      registerDevice("Laptop", "kry.example.test", user, []),
    ).rejects.toThrow(/did not verify a fingerprint/u);
    vi.stubGlobal("navigator", { credentials: created(0x45) });
    await expect(
      registerDevice("Laptop", "kry.example.test", user, []),
    ).resolves.toMatchObject({ id: "bmV3", alg: -7, verifies: true });
  });
});

describe("fingerprint, always", () => {
  it("requires verification and refuses a touch-only answer", async () => {
    const asked: CredentialRequestOptions[] = [];
    const answer = (flags: number) =>
      vi.stubGlobal("navigator", {
        credentials: {
          get: async (options: CredentialRequestOptions) => {
            asked.push(options);
            return {
              id: "ZGV2aWNl",
              authenticatorAttachment: "platform",
              response: {
                authenticatorData: authData(flags),
                clientDataJSON: new TextEncoder().encode("{}").buffer,
                signature: new Uint8Array([4, 5]).buffer,
              },
            };
          },
        },
      });
    answer(0x01);
    await expect(
      createSession(["ZGV2aWNl"], "kry.example.test", T),
    ).rejects.toThrow(/did not verify a fingerprint/u);
    expect(asked[0]?.publicKey?.userVerification).toBe("required");
    await expect(
      approveChange(
        b64url(new Uint8Array([1])),
        ["ZGV2aWNl"],
        "kry.example.test",
      ),
    ).rejects.toThrow(/did not verify a fingerprint/u);
    answer(0x05);
    const approval = await approveChange(
      b64url(new Uint8Array([1])),
      ["ZGV2aWNl"],
      "kry.example.test",
    );
    expect(approval.credentialId).toBe("ZGV2aWNl");
  });

  it("names a passkey after where it lives and refuses a touch-only one", async () => {
    expect(nameFor(["hybrid", "internal"], "Laptop")).toBe("Phone");
    expect(nameFor(["usb"], "Laptop")).toBe("Security key");
    expect(nameFor(["nfc"], "Phone")).toBe("Security key");
    expect(nameFor(["internal"], "Laptop")).toBe("Laptop");
    const created = (flags: number, transports: string[]) => ({
      create: async (options: CredentialCreationOptions) => {
        expect(
          options.publicKey?.authenticatorSelection?.userVerification,
        ).toBe("required");
        expect(options.publicKey?.hints?.[0]).toBe("client-device");
        return {
          id: "bmV3",
          authenticatorAttachment: "cross-platform",
          response: {
            getAuthenticatorData: () => authData(flags),
            getPublicKey: () => new Uint8Array([9, 9]).buffer,
            getPublicKeyAlgorithm: () => -7,
            getTransports: () => transports,
          },
        };
      },
    });
    const user = { id: "operator", name: "operator" };
    vi.stubGlobal("navigator", { credentials: created(0x01, ["internal"]) });
    await expect(
      registerDevice("Laptop", "kry.example.test", user, [], {
        guessed: true,
      }),
    ).rejects.toThrow(/did not verify a fingerprint/u);
    vi.stubGlobal("navigator", { credentials: created(0x05, ["hybrid"]) });
    await expect(
      registerDevice("Laptop", "kry.example.test", user, [], {
        guessed: true,
      }),
    ).resolves.toMatchObject({ name: "Phone", verifies: true });
  });
});

describe("dashboard intents", () => {
  it("signs what is about to happen with the session key", async () => {
    authenticator();
    const session = await createSession(["ZGV2aWNl"], "kry.example.test", T);
    const header = await signIntent(
      session,
      "node.delete",
      "n1",
      "https://kry.example.test",
      T + MINUTE,
    );
    const signed = decode(header) as {
      grant: { grant: string };
      command: string;
      signature: string;
    };
    expect(signed.grant.grant).toBe(session.grant.grant);
    expect(decode(signed.command)).toEqual({
      v: 1,
      op: "node.delete",
      target: "n1",
      at: new Date(T + MINUTE).toISOString(),
      origin: "https://kry.example.test",
    });
    const key = await crypto.subtle.importKey(
      "spki",
      fromB64url(decode(session.grant.grant).sessionKey as string),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        fromB64url(signed.signature),
        fromB64url(signed.command),
      ),
    ).toBe(true);
  });
});
