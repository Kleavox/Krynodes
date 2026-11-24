import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import fixture from "../../../packages/protocol/src/fixtures/browser-signed.json";
import { b64url, fromB64url } from "./passkeys";
import {
  activeSession,
  buildChange,
  buildCommand,
  createSession,
  endSession,
  openSession,
  signChange,
  signCommand,
  signDocument,
} from "./sign";

const SIGNED_AT = Date.parse("2026-11-22T10:00:00.000Z");
const MINUTE = 60_000;
const text = (encoded: string) => new TextDecoder().decode(fromB64url(encoded));
const committedChange = JSON.parse(fixture.change.signed) as {
  change: string;
  approvals: Record<string, string>[];
};
const committedCommand = JSON.parse(fixture.command.signed) as {
  grant: Record<string, string>;
  command: string;
  signature: string;
};

const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

interface Asked {
  challenge: Uint8Array;
  allow: string[];
  rpId: string | undefined;
  userVerification: string | undefined;
}

function authenticator(id = "AAECAwQFBgcICQoLDA0ODw") {
  const asked: Asked[] = [];
  vi.stubGlobal("navigator", {
    credentials: {
      get: async ({ publicKey }: CredentialRequestOptions) => {
        asked.push({
          challenge: new Uint8Array(publicKey!.challenge as ArrayBuffer),
          allow: (publicKey!.allowCredentials ?? []).map((entry) =>
            b64url(entry.id as Uint8Array),
          ),
          rpId: publicKey!.rpId,
          userVerification: publicKey!.userVerification,
        });
        const authData = new Uint8Array(37);
        authData[32] = 0x05;
        return {
          id,
          authenticatorAttachment: "platform",
          response: {
            authenticatorData: authData.buffer,
            clientDataJSON: new TextEncoder().encode("{}").buffer,
            signature: new Uint8Array([1, 2]).buffer,
          },
        };
      },
    },
  });
  return asked;
}

const page = { visibilityState: "visible", listeners: [] as (() => void)[] };
const fakeDocument = {
  get visibilityState() {
    return page.visibilityState;
  },
  addEventListener: (_: string, listener: () => void) => {
    page.listeners.push(listener);
  },
};

beforeEach(() => {
  page.visibilityState = "visible";
  vi.stubGlobal("document", fakeDocument);
  vi.stubGlobal("location", { hostname: "kry.example.org" });
  endSession();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("what the browser signs", () => {
  it("a command is the committed fixture's command, signed by the session key", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(SIGNED_AT + 10_000);
    const asked = authenticator("EBESExQVFhcYGRobHB0eHw");
    const session = await createSession(
      ["EBESExQVFhcYGRobHB0eHw"],
      fixture.rpId,
      SIGNED_AT,
    );
    const command = buildCommand(
      session,
      {
        id: fixture.command.id,
        nodeId: fixture.nodeId,
        kind: "host",
        name: "server-1",
        action: "restart",
      },
      SIGNED_AT + 10_000,
    );
    const signed = JSON.parse(await signCommand(session, command)) as {
      grant: Record<string, string>;
      command: string;
      signature: string;
    };

    expect(Object.keys(signed)).toEqual(Object.keys(committedCommand));
    expect(Object.keys(signed.grant).sort()).toEqual(
      Object.keys(committedCommand.grant).sort(),
    );
    expect(text(signed.command)).toBe(text(committedCommand.command));

    const grant = JSON.parse(text(signed.grant.grant!)) as Record<
      string,
      string
    >;
    const committedGrant = JSON.parse(
      text(committedCommand.grant.grant!),
    ) as Record<string, string>;
    expect(Object.keys(grant)).toEqual(Object.keys(committedGrant));
    expect({ ...grant, sessionKey: "-", nonce: "-" }).toEqual({
      ...committedGrant,
      sessionKey: "-",
      nonce: "-",
    });
    expect(fromB64url(grant.nonce!)).toHaveLength(16);
    expect(asked[0]!.challenge).toEqual(
      await sha256(fromB64url(signed.grant.grant!)),
    );
    expect(asked[0]!.allow).toEqual(["EBESExQVFhcYGRobHB0eHw"]);
    expect(asked[0]!.userVerification).toBe("required");

    const key = await crypto.subtle.importKey(
      "spki",
      fromB64url(grant.sessionKey!),
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
  });

  it("a trust change is the committed fixture's change, approved over its exact bytes", async () => {
    const committed = JSON.parse(text(committedChange.change)) as {
      version: number;
      core: { id: string; name: string; alg: number; publicKey: string }[];
      access: Record<string, string[]>;
    };
    const asked = authenticator();
    const change = buildChange(
      {
        origin: fixture.origin,
        version: committed.version,
        core: committed.core,
        access: committed.access,
      },
      SIGNED_AT,
    );
    expect(new TextDecoder().decode(change)).toBe(text(committedChange.change));

    const envelope = JSON.parse(
      await signChange(change, ["AAECAwQFBgcICQoLDA0ODw"], fixture.rpId),
    ) as typeof committedChange;
    expect(Object.keys(envelope)).toEqual(Object.keys(committedChange));
    expect(envelope.change).toBe(committedChange.change);
    expect(envelope.approvals).toHaveLength(1);
    expect(Object.keys(envelope.approvals[0]!)).toEqual(
      Object.keys(committedChange.approvals[0]!),
    );
    expect(asked[0]!.challenge).toEqual(await sha256(change));
    expect(asked[0]!.allow).toEqual(["AAECAwQFBgcICQoLDA0ODw"]);
    expect(asked[0]!.rpId).toBe(fixture.rpId);
  });

  it("leaves args out of a command that has none and keeps them when given", async () => {
    authenticator();
    const session = await createSession(
      ["AAECAwQFBgcICQoLDA0ODw"],
      "kry.example.org",
    );
    const target = {
      id: "a1",
      nodeId: "n1",
      kind: "agent" as const,
      name: "server-1",
      action: "update",
    };
    expect(buildCommand(session, target)).not.toHaveProperty("args");
    expect(
      buildCommand(session, { ...target, args: { version: "0.8.1" } }).args,
    ).toEqual({ version: "0.8.1" });
  });
});

describe("a network document", () => {
  it("signDocument signs the exact document bytes", async () => {
    authenticator();
    const session = await createSession(
      ["AAECAwQFBgcICQoLDA0ODw"],
      "kry.example.org",
    );
    const document = {
      v: 1 as const,
      version: 1,
      range: "10.88.37.0/24",
      port: 51820,
      mtu: 1420,
      members: [],
      blocked: [],
      allow: [],
    };
    const signed = JSON.parse(await signDocument(session, document)) as {
      grant: { grant: string };
      document: string;
      signature: string;
    };
    expect(Object.keys(signed)).toEqual(["grant", "document", "signature"]);
    expect(signed.grant).toEqual(session.grant);
    expect(text(signed.document)).toBe(JSON.stringify(document));

    const grant = JSON.parse(text(signed.grant.grant)) as {
      sessionKey: string;
    };
    const key = await crypto.subtle.importKey(
      "spki",
      fromB64url(grant.sessionKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const bytes = fromB64url(signed.document);
    const tag = new TextEncoder().encode("krynodes-document-v1\n");
    const tagged = new Uint8Array(tag.length + bytes.length);
    tagged.set(tag);
    tagged.set(bytes, tag.length);
    const signature = fromB64url(signed.signature);
    expect(signature).toHaveLength(64);
    const verify = (data: Uint8Array<ArrayBuffer>) =>
      crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        signature,
        data,
      );
    expect(await verify(tagged)).toBe(true);
    expect(await verify(bytes)).toBe(false);
  });
});

describe("the signing session", () => {
  it("is reused for five minutes by a server its passkey reaches", async () => {
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    vi.setSystemTime(SIGNED_AT);
    const asked = authenticator();
    const first = await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    expect(await openSession(["other", "AAECAwQFBgcICQoLDA0ODw"])).toBe(first);
    expect(asked).toHaveLength(1);
    vi.advanceTimersByTime(5 * MINUTE);
    expect(activeSession()).toBeNull();
    await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    expect(asked).toHaveLength(2);
  });

  it("asks again for a server its passkey does not reach", async () => {
    const asked = authenticator();
    await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    await openSession(["EBESExQVFhcYGRobHB0eHw"]);
    expect(asked).toHaveLength(2);
    expect(asked[1]!.allow).toEqual(["EBESExQVFhcYGRobHB0eHw"]);
  });

  it("ends when the page is hidden", async () => {
    authenticator();
    await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    page.visibilityState = "hidden";
    for (const listener of page.listeners) listener();
    expect(activeSession()).toBeNull();
  });

  it("is not kept when the page was hidden while the passkey answered", async () => {
    authenticator();
    page.visibilityState = "hidden";
    await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    expect(activeSession()).toBeNull();
  });

  it("drops an older session when a later prompt fails on a hidden page", async () => {
    authenticator();
    await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    vi.stubGlobal("navigator", {
      credentials: {
        get: async () => {
          page.visibilityState = "hidden";
          for (const listener of page.listeners) listener();
          throw new DOMException("cancelled", "NotAllowedError");
        },
      },
    });
    await expect(openSession(["EBESExQVFhcYGRobHB0eHw"])).rejects.toThrow();
    expect(activeSession()).toBeNull();
  });

  it("drops an older session too when a later prompt ends on a hidden page", async () => {
    authenticator();
    await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    expect(activeSession()).not.toBeNull();
    const get = navigator.credentials.get.bind(navigator.credentials);
    vi.stubGlobal("navigator", {
      credentials: {
        get: async (options: CredentialRequestOptions) => {
          page.visibilityState = "hidden";
          for (const listener of page.listeners) listener();
          return get(options);
        },
      },
    });
    await openSession(["EBESExQVFhcYGRobHB0eHw"]);
    expect(activeSession()).toBeNull();
  });
});

describe("a session that is over", () => {
  const document = {
    v: 1 as const,
    version: 1,
    range: "10.88.37.0/24",
    port: 51820,
    mtu: 1420,
    members: [],
    blocked: [],
    allow: [],
  };
  const over = "Your passkey session has ended. Start again; nothing was sent.";

  it("signs no command and no document once it has expired", async () => {
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    vi.setSystemTime(SIGNED_AT);
    authenticator();
    const session = await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    await expect(signDocument(session, document)).resolves.toBeTypeOf("string");
    vi.advanceTimersByTime(5 * MINUTE);
    await expect(signDocument(session, document)).rejects.toThrow(over);
    await expect(signCommand(session, { v: 1 })).rejects.toThrow(over);
  });

  it("signs nothing once the page was hidden", async () => {
    authenticator();
    const session = await openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    page.visibilityState = "hidden";
    for (const listener of page.listeners) listener();
    await expect(signDocument(session, document)).rejects.toThrow(over);
    await expect(signCommand(session, { v: 1 })).rejects.toThrow(over);
    page.visibilityState = "visible";
    const hiddenWhileAsked = await (async () => {
      page.visibilityState = "hidden";
      return openSession(["AAECAwQFBgcICQoLDA0ODw"]);
    })();
    await expect(signCommand(hiddenWhileAsked, { v: 1 })).rejects.toThrow(over);
  });
});
