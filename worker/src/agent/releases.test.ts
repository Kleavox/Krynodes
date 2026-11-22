import { afterEach, describe, expect, it, vi } from "vitest";

import { testEnv } from "../test/env";
import { checkAgentRelease, readAgentRelease } from "./releases";

const stub = (answer: (request: Request) => Response | Promise<Response>) => {
  const seen: Request[] = [];
  vi.stubGlobal(
    "fetch",
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      seen.push(request);
      return answer(request);
    },
  );
  return seen;
};

const redirect = (to: string) =>
  new Response(null, { status: 302, headers: { location: to } });

const FEED = "https://github.com/Kleavox/Krynodes/releases.atom";

const feed = (tags: string[]) =>
  new Response(
    `<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><id>tag:github.com,2008:https://github.com/Kleavox/Krynodes/releases</id><link type="text/html" rel="alternate" href="https://github.com/Kleavox/Krynodes/releases"/>${tags
      .map(
        (tag) =>
          `<entry><id>tag:github.com,2008:Repository/1/${tag}</id><link rel="alternate" type="text/html" href="https://github.com/Kleavox/Krynodes/releases/tag/${tag}"/><title>${tag}</title><content type="html">&lt;a href=&quot;https://github.com/Kleavox/Krynodes/releases/tag/agent-v9.9.9&quot;&gt;notes&lt;/a&gt;</content></entry>`,
      )
      .join("")}</feed>`,
    { headers: { "content-type": "application/atom+xml; charset=utf-8" } },
  );

const quiet = () => vi.spyOn(console, "error").mockImplementation(() => {});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("agent release", () => {
  it("reads releases/latest in production", async () => {
    const { env, db } = testEnv();
    const seen = stub(() =>
      redirect(
        "https://github.com/Kleavox/Krynodes/releases/tag/agent-v0.7.25",
      ),
    );
    const release = await checkAgentRelease(env);
    expect(release.version).toBe("0.7.25");
    expect(seen[0]!.url).toBe(
      "https://github.com/Kleavox/Krynodes/releases/latest",
    );
    expect(seen[0]!.headers.get("user-agent")).toBe("kry-worker");
    expect(await readAgentRelease(db)).toEqual(release);
  });

  it("the test deployment offers a pre-release from the releases feed", async () => {
    const { env } = testEnv({ RELEASES: "any" });
    const seen = stub(() =>
      feed([
        "web-v9.9.9",
        "agent-v0.7.91-rc1",
        "agent-v0.7.90",
        "agent-v0.7.25",
      ]),
    );
    expect((await checkAgentRelease(env)).version).toBe("0.7.90");
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(FEED);
    expect(seen[0]!.headers.get("user-agent")).toBe("kry-worker");
    expect(seen[0]!.headers.get("authorization")).toBeNull();
  });

  it("the feed's first agent release wins and notes are not read as releases", async () => {
    const { env } = testEnv({ RELEASES: "any" });
    stub(() => feed(["agent-v0.7.91", "agent-v0.7.90"]));
    expect((await checkAgentRelease(env)).version).toBe("0.7.91");
  });

  it("keeps what it knew when GitHub does not answer and says why", async () => {
    const log = quiet();
    const { env } = testEnv();
    stub(() =>
      redirect(
        "https://github.com/Kleavox/Krynodes/releases/tag/agent-v0.7.25",
      ),
    );
    const known = await checkAgentRelease(env);
    stub(() => new Response("rate limited", { status: 403 }));
    expect(await checkAgentRelease(env)).toEqual(known);
    stub(() => {
      throw new Error("offline");
    });
    expect(await checkAgentRelease(env)).toEqual(known);
    stub(() => redirect("https://github.com/Kleavox/Krynodes/releases"));
    expect(await checkAgentRelease(env)).toEqual(known);
    const said = log.mock.calls.map((call) => call.join(" "));
    expect(said).toHaveLength(3);
    expect(said[0]).toContain("403");
    expect(said[1]).toContain("offline");
    expect(said[2]).toContain("no agent release");
  });

  it("the test deployment keeps what it knew and says why when the feed fails", async () => {
    const log = quiet();
    const { env } = testEnv({ RELEASES: "any" });
    stub(() => feed(["agent-v0.7.90"]));
    const known = await checkAgentRelease(env);
    stub(() => new Response("busy", { status: 503 }));
    expect(await checkAgentRelease(env)).toEqual(known);
    stub(() => feed(["web-v1.0.0"]));
    expect(await checkAgentRelease(env)).toEqual(known);
    stub(() => {
      throw new Error("offline");
    });
    expect(await checkAgentRelease(env)).toEqual(known);
    const said = log.mock.calls.map((call) => call.join(" "));
    expect(said).toHaveLength(3);
    expect(said[0]).toContain("503");
    expect(said[1]).toContain("no agent release");
    expect(said[2]).toContain("offline");
    expect(known.version).toBe("0.7.90");
  });

  it("is unknown before the first check", async () => {
    const { db } = testEnv();
    expect(await readAgentRelease(db)).toEqual({
      version: null,
      checkedAt: null,
    });
  });

  it("tells dashboards only when the version changed", async () => {
    const { env, hub } = testEnv();
    const latest = (version: string) =>
      stub(() =>
        redirect(
          `https://github.com/Kleavox/Krynodes/releases/tag/agent-v${version}`,
        ),
      );
    latest("0.7.25");
    await checkAgentRelease(env);
    await checkAgentRelease(env);
    latest("0.7.26");
    await checkAgentRelease(env);
    expect(hub.calls.filter((call) => call.path === "/announce")).toHaveLength(
      2,
    );
  });
});
