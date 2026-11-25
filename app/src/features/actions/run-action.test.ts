import { QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { watch } from "@/lib/live";
import { endSession } from "@/lib/sign";
import type { ActionRow, FleetNode } from "@/types";

import { runAction } from "./run-action";

const PASSKEY = "AAECAwQFBgcICQoLDA0ODw";

const node: FleetNode = {
  id: "node-1",
  name: "server-1",
  hostname: null,
  os: "Debian 13",
  arch: "amd64",
  version: "0.8.0",
  online: true,
  lastSeenAt: null,
  trust: { version: 2, core: [PASSKEY], access: [PASSKEY] },
  update: "0.8.1",
  kind: "server",
  address: null,
  via: null,
  ms: null,
  request: null,
};

const row = (id: string, patch: Partial<ActionRow> = {}): ActionRow => ({
  id,
  nodeId: node.id,
  kind: "host",
  name: node.name,
  action: "restart",
  title: "Restart Server",
  status: "sent",
  message: null,
  output: null,
  createdAt: "2026-11-22T10:00:00.000Z",
  finishedAt: null,
  ...patch,
});

class FakeSocket {
  static all: FakeSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor() {
    FakeSocket.all.push(this);
  }
  send() {}
  close() {}
}

function authenticator() {
  const get = vi.fn(async () => {
    const authData = new Uint8Array(37);
    authData[32] = 0x05;
    return {
      id: PASSKEY,
      authenticatorAttachment: "platform",
      response: {
        authenticatorData: authData.buffer,
        clientDataJSON: new TextEncoder().encode("{}").buffer,
        signature: new Uint8Array([1]).buffer,
      },
    };
  });
  vi.stubGlobal("navigator", { credentials: { get } });
  return get;
}

interface Call {
  method: string;
  url: string;
  body?: Record<string, unknown>;
}

function api(answer: (call: Call) => { status: number; body: unknown }) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit = {}) => {
      const call: Call = {
        method: init.method ?? "GET",
        url,
        ...(typeof init.body === "string"
          ? { body: JSON.parse(init.body) as Record<string, unknown> }
          : {}),
      };
      calls.push(call);
      const { status, body } = answer(call);
      return new Response(JSON.stringify(body), { status });
    }),
  );
  return calls;
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  FakeSocket.all = [];
  vi.stubGlobal("location", { hostname: "kry.example.test" });
  endSession();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("running a signed action", () => {
  it("an offline server's action shows the refusal at once", async () => {
    authenticator();
    const calls = api(() => ({
      status: 409,
      body: { code: "OFFLINE", message: "server-1 is offline." },
    }));
    await expect(
      runAction(new QueryClient(), node, {
        kind: "host",
        action: "restart",
        title: "Restart Server",
      }),
    ).rejects.toThrow("server-1 is offline.");
    expect(calls.map((call) => call.method)).toEqual(["POST"]);
  });

  it("does not ask for the passkey when the fleet already shows the server offline", async () => {
    const get = authenticator();
    const calls = api(() => ({ status: 500, body: {} }));
    await expect(
      runAction(
        new QueryClient(),
        { ...node, online: false },
        {
          kind: "host",
          action: "restart",
          title: "Restart Server",
        },
      ),
    ).rejects.toThrow("server-1 is offline.");
    expect(get).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it("refuses at once a server no passkey can act on", async () => {
    const get = authenticator();
    await expect(
      runAction(
        new QueryClient(),
        { ...node, trust: { version: 1, core: [PASSKEY], access: [] } },
        { kind: "host", action: "restart", title: "Restart Server" },
      ),
    ).rejects.toThrow("No passkey can act on server-1.");
    expect(get).not.toHaveBeenCalled();
  });

  it("says a server that has not reported its trust has not, instead of blaming the passkeys", async () => {
    const get = authenticator();
    await expect(
      runAction(
        new QueryClient(),
        { ...node, trust: null },
        { kind: "host", action: "restart", title: "Restart Server" },
      ),
    ).rejects.toThrow("server-1 has not reported its trust yet.");
    expect(get).not.toHaveBeenCalled();
  });

  it("stops waiting and polling when the dialog lets go", async () => {
    authenticator();
    const calls = api((call) =>
      call.method === "POST"
        ? { status: 201, body: row(String(call.body!.id)) }
        : { status: 200, body: [] },
    );
    const client = new QueryClient();
    const quit = new AbortController();
    const waiting = runAction(
      client,
      node,
      { kind: "host", action: "restart", title: "Restart Server" },
      undefined,
      quit.signal,
    );
    while (calls.filter((call) => call.method === "GET").length === 0) {
      await settle();
    }
    quit.abort();
    await expect(waiting).rejects.toThrow();
    const asked = calls.length;
    await client.invalidateQueries();
    await settle();
    expect(calls).toHaveLength(asked);
  });

  it("stops waiting when the server and its actions are deleted", async () => {
    authenticator();
    let id = "";
    let deleted = false;
    api((call) => {
      if (call.method === "POST") {
        id = String(call.body!.id);
        return { status: 201, body: row(id) };
      }
      return { status: 200, body: deleted ? [] : [row(id)] };
    });
    const client = new QueryClient();
    const waiting = runAction(client, node, {
      kind: "host",
      action: "restart",
      title: "Restart Server",
    });
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    deleted = true;
    await client.invalidateQueries();
    await expect(waiting).rejects.toThrow("server-1 was deleted.");
  });

  it("keeps waiting when newer actions push the row out of the list", async () => {
    authenticator();
    let id = "";
    let stage = 0;
    api((call) => {
      if (call.method === "POST") {
        id = String(call.body!.id);
        return { status: 201, body: row(id) };
      }
      if (call.url === `/api/actions/${id}`) {
        return {
          status: 200,
          body: row(id, { status: "done", message: "Restarting now." }),
        };
      }
      const body = [
        [row(id)],
        [row("newer")],
        [row("newer"), row(id, { status: "done", message: "Restarting now." })],
      ][stage]!;
      return { status: 200, body };
    });
    const client = new QueryClient();
    const waiting = runAction(client, node, {
      kind: "host",
      action: "restart",
      title: "Restart Server",
    });
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    stage = 1;
    await client.invalidateQueries();
    stage = 2;
    await client.invalidateQueries();
    await expect(waiting).resolves.toMatchObject({ status: "done" });
  });

  it("posts the signed command with the server's name and the target version", async () => {
    authenticator();
    const calls = api((call) =>
      call.method === "POST"
        ? {
            status: 201,
            body: row(String(call.body!.id), {
              status: "failed",
              message: "x",
            }),
          }
        : { status: 200, body: [] },
    );
    await runAction(new QueryClient(), node, {
      kind: "agent",
      action: "update",
      title: "Update Agent to 0.8.1",
      args: { version: "0.8.1" },
    });
    const body = calls[0]!.body!;
    expect(calls[0]!.url).toBe("/api/actions");
    expect(body).toMatchObject({
      nodeId: "node-1",
      kind: "agent",
      name: "server-1",
      action: "update",
      title: "Update Agent to 0.8.1",
    });
    const signed = JSON.parse(String(body.signed)) as { command: string };
    const command = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(
          atob(signed.command.replaceAll("-", "+").replaceAll("_", "/")),
          (char) => char.charCodeAt(0),
        ),
      ),
    ) as Record<string, unknown>;
    expect(command).toMatchObject({
      v: 1,
      id: body.id,
      nodeId: "node-1",
      kind: "agent",
      name: "server-1",
      action: "update",
      args: { version: "0.8.1" },
    });
  });

  it("names a network command after the interface the agent checks", async () => {
    authenticator();
    const calls = api((call) =>
      call.method === "POST"
        ? {
            status: 201,
            body: row(String(call.body!.id), {
              status: "failed",
              message: "x",
            }),
          }
        : { status: 200, body: [] },
    );
    await runAction(new QueryClient(), node, {
      kind: "network",
      action: "test",
      title: "Test Link to server-2",
      args: { peer: "node-2", address: "10.88.37.2", mtu: "1420" },
    });
    const body = calls[0]!.body!;
    expect(body).toMatchObject({ kind: "network", name: "kry0" });
    const signed = JSON.parse(String(body.signed)) as { command: string };
    const command = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(
          atob(signed.command.replaceAll("-", "+").replaceAll("_", "/")),
          (char) => char.charCodeAt(0),
        ),
      ),
    ) as Record<string, unknown>;
    expect(command).toMatchObject({ kind: "network", name: "kry0" });
  });

  it("progress lines appear in order, then the row's result", async () => {
    authenticator();
    vi.stubGlobal("WebSocket", FakeSocket);
    const client = new QueryClient();
    const stop = watch(client, "wss://kry.example.test/api/live");
    const socket = FakeSocket.all[0]!;
    let id = "";
    let finished = false;
    api((call) => {
      if (call.method === "POST") {
        id = String(call.body!.id);
        return { status: 201, body: row(id) };
      }
      if (call.url === `/api/actions/${id}`) {
        return {
          status: 200,
          body: row(id, {
            status: "done",
            message: "Restarting now.",
            output: "rebooted\n",
          }),
        };
      }
      return {
        status: 200,
        body: [
          finished
            ? row(id, { status: "done", message: "Restarting now." })
            : row(id),
        ],
      };
    });
    const lines: string[] = [];
    const done = runAction(
      client,
      node,
      {
        kind: "stack",
        action: "logs",
        name: "web",
        title: "Logs",
        args: { lines: "200" },
      },
      (line) => lines.push(line),
    );
    while (!id) await settle();
    const say = (message: object) =>
      socket.onmessage?.({ data: JSON.stringify(message) });
    say({ type: "progress", id, line: "Stopping services" });
    say({ type: "progress", id: "another", line: "Not this one" });
    say({ type: "progress", id, line: "Rebooting" });
    finished = true;
    say({ type: "changed", topics: ["fleet"] });
    const result = await done;
    stop();
    expect(lines).toEqual(["Stopping services", "Rebooting"]);
    expect(result).toMatchObject({
      status: "done",
      message: "Restarting now.",
      output: "rebooted\n",
    });
  });

  it("a finished action stays finished when its output cannot be read", async () => {
    authenticator();
    let id = "";
    let finished = false;
    const calls = api((call) => {
      if (call.method === "POST") {
        id = String(call.body!.id);
        return { status: 201, body: row(id) };
      }
      if (call.url === `/api/actions/${id}`) {
        return { status: 500, body: { message: "broken" } };
      }
      return {
        status: 200,
        body: [
          finished ? row(id, { status: "done", message: "Read." }) : row(id),
        ],
      };
    });
    const client = new QueryClient();
    const waiting = runAction(client, node, {
      kind: "stack",
      action: "read",
      name: "web",
      title: "Read Compose",
    });
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    finished = true;
    await client.invalidateQueries();
    await expect(waiting).resolves.toMatchObject({
      status: "done",
      message: "Read.",
    });
    expect(calls.some((call) => call.url === `/api/actions/${id}`)).toBe(true);
  });

  it("reads the full row only for actions that carry output", async () => {
    authenticator();
    let id = "";
    let finished = false;
    const calls = api((call) => {
      if (call.method === "POST") {
        id = String(call.body!.id);
        return { status: 201, body: row(id) };
      }
      return {
        status: 200,
        body: [finished ? row(id, { status: "done" }) : row(id)],
      };
    });
    const client = new QueryClient();
    const waiting = runAction(client, node, {
      kind: "stack",
      action: "restart",
      name: "web",
      title: "Restart Stack",
    });
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    finished = true;
    await client.invalidateQueries();
    await expect(waiting).resolves.toMatchObject({ status: "done" });
    expect(calls.some((call) => call.url === `/api/actions/${id}`)).toBe(false);
    expect(calls[0]!.body).toMatchObject({ kind: "stack", name: "web" });
  });
});
