import { describe, expect, it } from "vitest";

import vector from "../../../packages/protocol/src/fixtures/sealed-output.json";
import { b64url, fromB64url } from "./passkeys";
import { oneTimeKey, openFromNode, seal } from "./seal";
import { open, recipient, sealFromNode } from "./seal-test-utils";

describe("sealing for a server", () => {
  it("seals so that only the server's key opens it", async () => {
    const server = await recipient();
    const sealed = await seal(server.public, "SMTP_PASSWORD=hunter2");
    expect(await open(server, sealed)).toEqual({
      version: 1,
      text: "SMTP_PASSWORD=hunter2",
    });
    const other = await recipient();
    await expect(open(other, sealed)).rejects.toThrow();
    expect(await seal(server.public, "SMTP_PASSWORD=hunter2")).not.toBe(sealed);
  });

  it("refuses a key that is not a server key", async () => {
    await expect(seal("short", "x")).rejects.toThrow();
  });
});

describe("opening what the node sealed", () => {
  const vectorKey = () =>
    crypto.subtle.importKey(
      "jwk",
      vector.jwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );

  const envelope = () =>
    JSON.parse(new TextDecoder().decode(fromB64url(vector.sealed))) as {
      v: number;
      epk: string;
      iv: string;
      ct: string;
    };

  const pack = (body: object) =>
    b64url(new TextEncoder().encode(JSON.stringify(body)));

  it("openFromNode opens the Go vector", async () => {
    expect(
      await openFromNode(
        await vectorKey(),
        fromB64url(vector.to),
        vector.node,
        vector.sealed,
      ),
    ).toBe(vector.plaintext);
    expect(envelope().v).toBe(2);
  });

  it("refuses another key, another public half, another node key, a changed message and a malformed one", async () => {
    const key = await vectorKey();
    const raw = fromB64url(vector.to);
    const other = await oneTimeKey();
    const stranger = await recipient();
    await expect(
      openFromNode(
        other.privateKey,
        other.publicRaw,
        vector.node,
        vector.sealed,
      ),
    ).rejects.toThrow();
    await expect(
      openFromNode(key, other.publicRaw, vector.node, vector.sealed),
    ).rejects.toThrow();
    await expect(
      openFromNode(key, raw, stranger.public, vector.sealed),
    ).rejects.toThrow();
    await expect(
      openFromNode(key, raw, vector.to, vector.sealed),
    ).rejects.toThrow();
    await expect(
      openFromNode(key, raw, "not a key", vector.sealed),
    ).rejects.toThrow();
    const body = envelope();
    const ct = fromB64url(body.ct);
    ct[0] = ct[0]! ^ 1;
    await expect(
      openFromNode(key, raw, vector.node, pack({ ...body, ct: b64url(ct) })),
    ).rejects.toThrow();
    await expect(
      openFromNode(key, raw, vector.node, pack({ ...body, v: 1 })),
    ).rejects.toThrow();
    await expect(
      openFromNode(key, raw, vector.node, pack({ ...body, iv: undefined })),
    ).rejects.toThrow();
    await expect(
      openFromNode(key, raw, vector.node, "not sealed"),
    ).rejects.toThrow();
    await expect(openFromNode(key, raw, vector.node, "")).rejects.toThrow();
  });

  it("an output sealed to to without the node's key is refused", async () => {
    const one = await oneTimeKey();
    const node = await recipient();
    const forger = await recipient();
    const forged = await seal(one.to, "services:\n  evil:\n    image: x\n");
    await expect(
      openFromNode(one.privateKey, one.publicRaw, node.public, forged),
    ).rejects.toThrow();
    const impostor = await sealFromNode(forger, one.to, "TOKEN=forged");
    await expect(
      openFromNode(one.privateKey, one.publicRaw, node.public, impostor),
    ).rejects.toThrow();
  });

  it("a one-time key opens what the node seals to its public half, and its private half cannot leave", async () => {
    const one = await oneTimeKey();
    const node = await recipient();
    expect(one.to).toBe(b64url(one.publicRaw));
    expect(one.to).toHaveLength(87);
    expect(one.publicRaw).toHaveLength(65);
    const sealed = await sealFromNode(node, one.to, "line one\nline two\n");
    expect(
      await openFromNode(one.privateKey, one.publicRaw, node.public, sealed),
    ).toBe("line one\nline two\n");
    expect(one.privateKey.extractable).toBe(false);
    await expect(
      crypto.subtle.exportKey("pkcs8", one.privateKey),
    ).rejects.toThrow();
    expect((await oneTimeKey()).to).not.toBe(one.to);
  });
});
