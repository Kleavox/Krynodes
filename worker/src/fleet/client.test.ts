import { describe, expect, it, vi } from "vitest";

import type { Env } from "../env";
import { announce, dropNode, onlineNodes, sendCommand } from "./client";

const envWith = (fetch: (request: Request) => Promise<Response>) =>
  ({
    FLEET: {
      idFromName: (name: string) => name,
      get: (id: string) => ({
        fetch: (input: string, init?: RequestInit) =>
          fetch(new Request(`${input}?hub=${id}`, init)),
      }),
    },
  }) as unknown as Env;

describe("announce", () => {
  it("posts the topics to the one hub", async () => {
    const seen: Request[] = [];
    await announce(
      envWith(async (request) => {
        seen.push(request);
        return new Response(null, { status: 204 });
      }),
      ["fleet"],
    );
    expect(seen.map((request) => request.url)).toEqual([
      "https://fleet/announce?hub=fleet",
    ]);
    expect(await seen[0]!.json()).toEqual({ topics: ["fleet"] });
  });

  it("logs a hub that cannot be reached instead of failing the route", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(
      announce(
        envWith(async () => {
          throw new Error("down");
        }),
        ["fleet"],
      ),
    ).resolves.toBeUndefined();
    expect(logged).toHaveBeenCalled();
    logged.mockRestore();
  });
});

const answer = (status: number, body: unknown = null) =>
  new Response(body === null ? null : JSON.stringify(body), { status });

describe("onlineNodes", () => {
  it("reads the node ids the hub holds sockets for", async () => {
    const env = envWith(async (request) => {
      expect(new URL(request.url).pathname).toBe("/online");
      return answer(200, ["n1", "n2"]);
    });
    expect(await onlineNodes(env)).toEqual(new Set(["n1", "n2"]));
  });
});

describe("sendCommand", () => {
  const command = {
    type: "command",
    id: "a1",
    kind: "host",
    name: "server-1",
    action: "restart",
    signed: "c2lnbmVk",
  } as const;

  it("posts the node and the command, and says whether it was sent", async () => {
    const seen: Request[] = [];
    const env = envWith(async (request) => {
      seen.push(request);
      return answer(200, { sent: true });
    });
    expect(await sendCommand(env, "n1", command)).toBe(true);
    expect(await seen[0]!.json()).toEqual({ nodeId: "n1", command });
  });

  it("is false for an offline node", async () => {
    const env = envWith(async () => answer(409, { code: "OFFLINE" }));
    expect(await sendCommand(env, "n1", command)).toBe(false);
  });

  it("throws on any other answer", async () => {
    const env = envWith(async () => answer(400, { code: "INVALID_COMMAND" }));
    await expect(sendCommand(env, "n1", command)).rejects.toThrow(/400/u);
  });
});

describe("dropNode", () => {
  it("tells the hub to close the node's sockets", async () => {
    const seen: Request[] = [];
    await dropNode(
      envWith(async (request) => {
        seen.push(request);
        return answer(204);
      }),
      "n1",
    );
    expect(new URL(seen[0]!.url).pathname).toBe("/drop");
    expect(await seen[0]!.json()).toEqual({ nodeId: "n1" });
  });
});
