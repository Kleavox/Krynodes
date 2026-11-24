import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { toB64url } from "../lib/b64url";
import { MAX_SIGNED, readSigned } from "./document";

const fixture = (name: string): unknown =>
  JSON.parse(
    readFileSync(
      new URL(
        `../../../packages/protocol/src/fixtures/${name}`,
        import.meta.url,
      ),
      "utf8",
    ),
  );

const grant = {
  grant: "e30",
  credentialId: "cGsx",
  authenticatorData: toB64url(new Uint8Array(37)),
  clientDataJSON: "e30",
  signature: "c2ln",
};

describe("network documents", () => {
  it("takes a signed document of up to 524288 characters, as the agent does", () => {
    expect(MAX_SIGNED).toBe(524288);
  });

  it("reads the document out of a signed envelope", async () => {
    const document = fixture("network-document.json");
    const body = new TextEncoder().encode(JSON.stringify(document));
    const read = readSigned(
      JSON.stringify({ grant, document: toB64url(body), signature: "c2ln" }),
    );
    expect(read?.document).toEqual(document);
    expect(read?.body).toEqual(body);
  });

  it("refuses an envelope that is not one", () => {
    const body = toB64url(new TextEncoder().encode('{"v":1}'));
    for (const text of [
      "not json",
      JSON.stringify({ grant, document: body, signature: "c2ln" }),
      JSON.stringify({ grant, document: "%%", signature: "c2ln" }),
      JSON.stringify({ grant, document: body }),
      JSON.stringify({ grant, document: body, signature: "c2ln", extra: 1 }),
      JSON.stringify({
        grant: { ...grant, authenticatorData: "A" },
        document: body,
        signature: "c2ln",
      }),
      JSON.stringify({
        grant: { ...grant, authenticatorData: toB64url(new Uint8Array(36)) },
        document: body,
        signature: "c2ln",
      }),
    ]) {
      expect(readSigned(text)).toBeNull();
    }
  });
});
