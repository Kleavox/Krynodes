import { documentHash } from "@krynodes/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";

import document from "../../../packages/protocol/src/fixtures/network-document.json";
import { currentDocument } from "./api";
import { b64url } from "./passkeys";

function answer(status: number, payload: unknown) {
  const paths: string[] = [];
  vi.stubGlobal("fetch", (path: string) => {
    paths.push(path);
    return Promise.resolve(
      new Response(JSON.stringify(payload), {
        status,
        headers: { "content-type": "application/json" },
      }),
    );
  });
  return paths;
}

const bytes = new TextEncoder().encode(JSON.stringify(document));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the current network document", () => {
  it("is read from its exact bytes once their hash matches", async () => {
    const hash = await documentHash(bytes);
    const paths = answer(200, { version: 3, hash, document: b64url(bytes) });
    expect(await currentDocument()).toEqual({ document, hash });
    expect(paths).toEqual(["/api/network/current"]);
  });

  it("a mismatched hash is refused", async () => {
    answer(200, { version: 3, hash: "q".repeat(43), document: b64url(bytes) });
    await expect(currentDocument()).rejects.toThrow(
      "The network document does not match its hash. Nothing was changed.",
    );
  });

  it("a document that does not parse is refused", async () => {
    const broken = new TextEncoder().encode('{"v":1}');
    answer(200, {
      version: 1,
      hash: await documentHash(broken),
      document: b64url(broken),
    });
    await expect(currentDocument()).rejects.toThrow(
      "The network document cannot be read. Nothing was changed.",
    );
  });

  it("a document that is not base64url is refused", async () => {
    for (const document of ["%%%", "a"]) {
      answer(200, { version: 1, hash: "q".repeat(43), document });
      await expect(currentDocument()).rejects.toThrow(
        "The network document cannot be read. Nothing was changed.",
      );
    }
  });

  it("is null when there is no network", async () => {
    answer(404, {
      code: "NO_NETWORK",
      message: "There is no private network.",
    });
    expect(await currentDocument()).toBeNull();
  });
});
