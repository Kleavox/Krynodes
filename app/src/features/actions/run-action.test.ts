import { STACK_ACTIONS, stackArgsValid } from "@krynodes/protocol";
import { QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { watch } from "@/lib/live";
import { fromB64url } from "@/lib/passkeys";
import { memoryStore } from "@/lib/pins";
import { S1 } from "@/lib/rules-test-utils";
import { oneTimeKey, seal } from "@/lib/seal";
import { pinnedNode, recipient, sealFromNode } from "@/lib/seal-test-utils";
import { endSession } from "@/lib/sign";
import type { ActionRow, FleetNode } from "@/types";

import { runAction, type ActionRequest } from "./run-action";

const PASSKEY = "AAECAwQFBgcICQoLDA0ODw";

const node: FleetNode = {
  id: S1,
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

type Answer = { status: number; body: unknown };

function commandOf(call: Call) {
  const signed = JSON.parse(String(call.body!.signed)) as { command: string };
  return JSON.parse(new TextDecoder().decode(fromB64url(signed.command))) as {
    args?: Record<string, string>;
  };
}

function api(answer: (call: Call) => Answer | Promise<Answer>) {
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
      const { status, body } = await answer(call);
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
      nodeId: S1,
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
      nodeId: S1,
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
    const pinned = await pinnedNode();
    vi.stubGlobal("WebSocket", FakeSocket);
    const client = new QueryClient();
    const stop = watch(client, "wss://kry.example.test/api/live");
    const socket = FakeSocket.all[0]!;
    let id = "";
    let to = "";
    let sealed = "";
    let finished = false;
    api(async (call) => {
      if (call.method === "POST") {
        id = String(call.body!.id);
        to = commandOf(call).args!.to!;
        return { status: 201, body: row(id) };
      }
      if (call.url === `/api/actions/${id}`) {
        sealed = await sealFromNode(pinned.key, to, "rebooted\n");
        return {
          status: 200,
          body: row(id, {
            status: "done",
            message: "Restarting now.",
            output: sealed,
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
      undefined,
      pinned.deps,
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
    expect(client.getQueryData(["actions", node.id])).toBeDefined();
    const cached = JSON.stringify(
      client
        .getQueryCache()
        .getAll()
        .map((query) => query.state.data),
    );
    expect(sealed).not.toBe("");
    expect(cached).not.toContain(to);
    expect(cached).not.toContain(sealed);
    expect(cached).not.toContain("rebooted");
  });

  it("a done read whose output cannot be fetched is an error, not a quiet success", async () => {
    authenticator();
    const pinned = await pinnedNode();
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
    const waiting = runAction(
      client,
      node,
      {
        kind: "stack",
        action: "read",
        name: "web",
        title: "Read Compose",
      },
      undefined,
      undefined,
      pinned.deps,
    );
    const refused = expect(waiting).rejects.toThrow(
      "The server's answer did not arrive.",
    );
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    finished = true;
    await client.invalidateQueries();
    await refused;
    expect(calls.some((call) => call.url === `/api/actions/${id}`)).toBe(true);
  });

  it("reads the full row only for actions that carry output or fail", async () => {
    authenticator();
    const { deps } = await pinnedNode();
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
    const waiting = runAction(
      client,
      node,
      {
        kind: "stack",
        action: "restart",
        name: "web",
        title: "Restart Stack",
      },
      undefined,
      undefined,
      deps,
    );
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    finished = true;
    await client.invalidateQueries();
    await expect(waiting).resolves.toMatchObject({ status: "done" });
    expect(calls.some((call) => call.url === `/api/actions/${id}`)).toBe(false);
    expect(calls[0]!.body).toMatchObject({ kind: "stack", name: "web" });
  });

  it("reads the full row of a failed action, because the list leaves its details out", async () => {
    authenticator();
    const pinned = await pinnedNode();
    let id = "";
    let to = "";
    let finished = false;
    const calls = api(async (call) => {
      if (call.method === "POST") {
        id = String(call.body!.id);
        to = commandOf(call).args!.to!;
        return { status: 201, body: row(id) };
      }
      const failed = {
        status: "failed" as const,
        message: "Deploy of web failed.",
      };
      if (call.url === `/api/actions/${id}`) {
        return {
          status: 200,
          body: row(id, {
            ...failed,
            output: await sealFromNode(pinned.key, to, "pull failed: denied"),
          }),
        };
      }
      return { status: 200, body: [finished ? row(id, failed) : row(id)] };
    });
    const client = new QueryClient();
    const waiting = runAction(
      client,
      node,
      { kind: "stack", action: "deploy", name: "web", title: "Deploy web" },
      undefined,
      undefined,
      pinned.deps,
    );
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    finished = true;
    await client.invalidateQueries();
    await expect(waiting).resolves.toMatchObject({
      status: "failed",
      message: "Deploy of web failed.",
      output: "pull failed: denied",
    });
    expect(calls.some((call) => call.url === `/api/actions/${id}`)).toBe(true);
  });

  it("a failed action whose full row cannot be fetched says its details could not be opened", async () => {
    authenticator();
    const pinned = await pinnedNode();
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
      const failed = {
        status: "failed" as const,
        message: "Deploy of web failed.",
      };
      return { status: 200, body: [finished ? row(id, failed) : row(id)] };
    });
    const client = new QueryClient();
    const waiting = runAction(
      client,
      node,
      { kind: "stack", action: "deploy", name: "web", title: "Deploy web" },
      undefined,
      undefined,
      pinned.deps,
    );
    while (!id || !client.getQueryData(["actions", node.id])) await settle();
    finished = true;
    await client.invalidateQueries();
    await expect(waiting).resolves.toMatchObject({
      status: "failed",
      message: "Deploy of web failed. The details could not be opened.",
      output: null,
    });
    expect(calls.some((call) => call.url === `/api/actions/${id}`)).toBe(true);
  });
});

const sealedAnswer = (
  make: (to: string) => Promise<string | null>,
  status: ActionRow["status"] = "done",
  patch: Partial<ActionRow> = {},
) =>
  api(async (call) =>
    call.method === "POST"
      ? {
          status: 201,
          body: row(String(call.body!.id), {
            kind: "stack",
            action: "logs",
            status,
            message: "Done.",
            output: await make(commandOf(call).args?.to ?? ""),
            ...patch,
          }),
        }
      : { status: 200, body: [] },
  );

describe("opening sealed output", () => {
  const logs = {
    kind: "stack" as const,
    action: "logs",
    name: "web",
    title: "Logs of web",
    args: { lines: "200" },
  };
  const containerLogs = {
    kind: "container" as const,
    action: "logs",
    name: "web-1",
    title: "Logs of web-1",
    args: { lines: "200" },
  };
  const read = {
    kind: "stack" as const,
    action: "read",
    name: "web",
    title: "Read Compose of web",
  };
  let pinned: Awaited<ReturnType<typeof pinnedNode>>;

  beforeEach(async () => {
    pinned = await pinnedNode();
  });

  const run = (request: ActionRequest = logs, client = new QueryClient()) =>
    runAction(client, node, request, undefined, undefined, pinned.deps);

  it("logs sign a fresh key each time and show the opened text", async () => {
    authenticator();
    const calls = sealedAnswer((to) =>
      sealFromNode(pinned.key, to, "web-1  ready\nweb-1  idle\n"),
    );
    const client = new QueryClient();
    const first = await run(logs, client);
    const second = await run(containerLogs, client);
    expect(first.output).toBe("web-1  ready\nweb-1  idle\n");
    expect(second.output).toBe("web-1  ready\nweb-1  idle\n");
    const [one, two] = calls.map((call) => commandOf(call).args!);
    expect(one!.to).toMatch(/^[A-Za-z0-9_-]{87}$/u);
    expect(two!.to).not.toBe(one!.to);
    expect(one).toEqual({ lines: "200", to: one!.to });
    expect(stackArgsValid("stack", "logs", one!)).toBe(true);
    expect(stackArgsValid("container", "logs", two!)).toBe(true);
  });

  it("a read signs its own key and gets the opened compose file", async () => {
    authenticator();
    const calls = api(async (call) =>
      call.method === "POST"
        ? {
            status: 201,
            body: row(String(call.body!.id), {
              kind: "stack",
              action: "read",
              status: "done",
              output: await sealFromNode(
                pinned.key,
                commandOf(call).args!.to!,
                '{"compose":"x"}',
              ),
            }),
          }
        : { status: 200, body: [] },
    );
    const result = await run(read);
    expect(result.output).toBe('{"compose":"x"}');
    const args = commandOf(calls[0]!).args!;
    expect(Object.keys(args)).toEqual(["to"]);
    expect(stackArgsValid("stack", "read", args)).toBe(true);
  });

  it("a sealed output that does not open shows an error, not empty text", async () => {
    authenticator();
    const stranger = await oneTimeKey();
    const forger = await recipient();
    for (const make of [
      () => sealFromNode(pinned.key, stranger.to, "TOKEN=secret"),
      (to: string) => sealFromNode(forger, to, "TOKEN=secret"),
      () => Promise.resolve("TOKEN=secret"),
      () => Promise.resolve("e30"),
    ]) {
      sealedAnswer(make);
      await expect(run()).rejects.toThrow(
        "The server's answer could not be opened.",
      );
    }
  });

  it("an output sealed to to without the node's key is refused", async () => {
    authenticator();
    sealedAnswer((to) => seal(to, "services:\n  evil:\n    image: x\n"));
    await expect(run(logs)).rejects.toThrow(
      "The server's answer could not be opened.",
    );
    sealedAnswer((to) => seal(to, '{"compose":"services: {}"}'));
    await expect(run(read)).rejects.toThrow(
      "The server's answer could not be opened.",
    );
  });

  it("an output sealed by another node's key is refused", async () => {
    authenticator();
    const other = await pinnedNode();
    sealedAnswer((to) => sealFromNode(other.key, to, "TOKEN=forged"));
    await expect(run(logs)).rejects.toThrow(
      "The server's answer could not be opened.",
    );
  });

  const deploy = {
    kind: "stack" as const,
    action: "deploy",
    name: "web",
    title: "Deploy web",
  };
  const failedDeploy = {
    action: "deploy",
    message: "Deploy of web failed.",
  };

  it("a failed deploy shows the opened detail", async () => {
    authenticator();
    const calls = sealedAnswer(
      (to) =>
        sealFromNode(
          pinned.key,
          to,
          "pull failed: service app: SECRET: s3cr3t-marker",
        ),
      "failed",
      failedDeploy,
    );
    expect(await run(deploy)).toMatchObject({
      status: "failed",
      message: "Deploy of web failed.",
      output: "pull failed: service app: SECRET: s3cr3t-marker",
    });
    const args = commandOf(calls[0]!).args!;
    expect(Object.keys(args)).toEqual(["to"]);
    expect(stackArgsValid("stack", "deploy", args)).toBe(true);
  });

  it("a detail that does not open shows the fixed message and says so", async () => {
    authenticator();
    const stranger = await oneTimeKey();
    const forger = await recipient();
    for (const make of [
      () => sealFromNode(pinned.key, stranger.to, "TOKEN=secret"),
      (to: string) => sealFromNode(forger, to, "TOKEN=secret"),
      (to: string) => seal(to, "TOKEN=secret"),
      () => Promise.resolve("TOKEN=secret"),
      () => Promise.resolve("e30"),
    ]) {
      sealedAnswer(make, "failed", failedDeploy);
      expect(await run(deploy)).toMatchObject({
        status: "failed",
        message: "Deploy of web failed. The details could not be opened.",
        output: null,
      });
    }
  });

  it("a failure with no details shows its message alone", async () => {
    authenticator();
    sealedAnswer(() => Promise.resolve(null), "failed", {
      action: "deploy",
      message: "stack deploy came with arguments this server does not take",
    });
    expect(await run(deploy)).toMatchObject({
      status: "failed",
      message: "stack deploy came with arguments this server does not take",
      output: null,
    });
  });

  it("a done action that carries no output shows none, whatever the Worker adds", async () => {
    authenticator();
    sealedAnswer((to) => sealFromNode(pinned.key, to, "TOKEN=secret"), "done", {
      action: "deploy",
      message: "server-1 runs web.",
    });
    expect(await run(deploy)).toMatchObject({ status: "done", output: null });
  });

  it("every stack and container verb signs its own fresh key", async () => {
    authenticator();
    const seen = new Set<string>();
    for (const kind of ["stack", "container"] as const) {
      for (const action of STACK_ACTIONS[kind]) {
        if (["create", "edit", "logs", "read"].includes(action)) continue;
        const calls = sealedAnswer(() => Promise.resolve(null), "failed", {
          kind,
          action,
        });
        await run({
          kind,
          action,
          name: "web",
          title: action,
          ...(action === "adopt" ? { args: { access: "full" } } : {}),
        });
        const args = commandOf(calls[0]!).args!;
        expect(stackArgsValid(kind, action, args), `${kind}/${action}`).toBe(
          true,
        );
        expect(seen.has(args.to!)).toBe(false);
        seen.add(args.to!);
      }
    }
    expect(seen.size).toBe(12);
  });

  it("every stack verb refuses before signing on a node outside the private network", async () => {
    const get = authenticator();
    const calls = api(() => ({ status: 500, body: {} }));
    const outside = { current: async () => null, store: memoryStore() };
    const ask = (request: ActionRequest) =>
      runAction(
        new QueryClient(),
        node,
        request,
        undefined,
        undefined,
        outside,
      );
    const wording = (kind: string, action: string) =>
      action === "logs"
        ? "its logs cannot be checked"
        : kind === "stack" && action === "read"
          ? "its compose file cannot be checked"
          : "its stacks cannot be changed";
    let refused = 0;
    for (const kind of ["stack", "container"] as const) {
      for (const action of STACK_ACTIONS[kind]) {
        await expect(
          ask({ kind, action, name: "web", title: action }),
          `${kind}/${action}`,
        ).rejects.toThrow(
          `server-1 is not in the private network, so ${wording(kind, action)}.`,
        );
        refused += 1;
      }
    }
    expect(refused).toBe(17);
    expect(get).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it("a done logs or read answer without output is an error, not a quiet success", async () => {
    authenticator();
    sealedAnswer(() => Promise.resolve(null));
    await expect(run(logs)).rejects.toThrow(
      "The server's answer did not arrive.",
    );
    await expect(run(containerLogs)).rejects.toThrow(
      "The server's answer did not arrive.",
    );
    await expect(run(read)).rejects.toThrow(
      "The server's answer did not arrive.",
    );
  });

  it("says why an answer did not open without showing it", async () => {
    authenticator();
    sealedAnswer(() => Promise.resolve("TOKEN=secret"));
    let error: unknown;
    try {
      await run();
    } catch (thrown) {
      error = thrown;
    }
    expect((error as Error).message).toBe(
      "The server's answer could not be opened.",
    );
    expect((error as Error).cause).toBeInstanceOf(Error);
  });

  it("logs on a node outside the private network refuse before signing", async () => {
    const get = authenticator();
    const calls = api(() => ({ status: 500, body: {} }));
    const outside = { current: async () => null, store: memoryStore() };
    const ask = (request: ActionRequest) =>
      runAction(
        new QueryClient(),
        node,
        request,
        undefined,
        undefined,
        outside,
      );
    await expect(ask(logs)).rejects.toThrow(
      "server-1 is not in the private network, so its logs cannot be checked.",
    );
    await expect(ask(containerLogs)).rejects.toThrow(
      "server-1 is not in the private network, so its logs cannot be checked.",
    );
    await expect(ask(read)).rejects.toThrow(
      "server-1 is not in the private network, so its compose file cannot be checked.",
    );
    expect(get).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it("an unconfirmed fingerprint refuses before signing", async () => {
    const get = authenticator();
    const calls = api(() => ({ status: 500, body: {} }));
    const check = vi.fn(async () => false);
    await expect(
      runAction(new QueryClient(), node, logs, undefined, undefined, {
        current: pinned.deps.current,
        store: memoryStore(),
        check,
      }),
    ).rejects.toThrow(
      "The fingerprint was not confirmed. Nothing was sealed or signed.",
    );
    expect(check).toHaveBeenCalledOnce();
    expect(get).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it("a unit, Docker or host action signs no key and asks for no node key", async () => {
    authenticator();
    const calls = api((call) => ({
      status: 201,
      body: row(String(call.body!.id), { status: "done" }),
    }));
    const current = vi.fn(async () => null);
    for (const request of [
      { kind: "unit", action: "restart", name: "nginx.service" },
      { kind: "docker", action: "install", name: "docker" },
      { kind: "host", action: "restart" },
    ] as const) {
      await runAction(
        new QueryClient(),
        node,
        { ...request, title: request.action },
        undefined,
        undefined,
        { current },
      );
    }
    expect(calls.map((call) => commandOf(call).args)).toEqual([
      undefined,
      undefined,
      undefined,
    ]);
    expect(current).not.toHaveBeenCalled();
  });
});
