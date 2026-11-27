import { QueryClient } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fromB64url } from "@/lib/passkeys";
import { S1 } from "@/lib/rules-test-utils";
import { open, pinnedNode, sealFromNode } from "@/lib/seal-test-utils";
import { endSession } from "@/lib/sign";
import type { FleetNode } from "@/types";

import {
  AccessChoice,
  readForEdit,
  readKey,
  saveStack,
  shouldPrefill,
  shouldStartRead,
  type ReadState,
} from "./new-stack-dialog";

const PASSKEY = "AAECAwQFBgcICQoLDA0ODw";
const COMPOSE = "services:\n  app:\n    image: nginx:1.27\n";

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
  update: null,
  kind: "server",
  address: "10.88.37.11",
  via: null,
  ms: null,
  request: null,
};

let pinned: Awaited<ReturnType<typeof pinnedNode>>;

beforeEach(async () => {
  pinned = await pinnedNode();
});

function server(
  output: string | null,
  sealIt = true,
  outcome: { status: string; message: string } = {
    status: "done",
    message: "Done.",
  },
) {
  vi.stubGlobal("location", { hostname: "kry.example.test" });
  vi.stubGlobal("navigator", {
    credentials: {
      get: vi.fn(async () => {
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
      }),
    },
  });
  const commands: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init: RequestInit = {}) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      const signed = JSON.parse(String(body.signed)) as { command: string };
      const command = JSON.parse(
        new TextDecoder().decode(fromB64url(signed.command)),
      ) as { args?: { to?: string } } & Record<string, unknown>;
      commands.push(command);
      const sealedOutput =
        sealIt && output !== null && command.args?.to
          ? await sealFromNode(pinned.key, command.args.to, output)
          : output;
      return new Response(
        JSON.stringify({
          id: body.id,
          nodeId: S1,
          kind: body.kind,
          name: body.name,
          action: body.action,
          title: body.title,
          ...outcome,
          output: sealedOutput,
          createdAt: "2026-11-22T10:00:00.000Z",
          finishedAt: "2026-11-22T10:00:01.000Z",
        }),
        { status: 201 },
      );
    }),
  );
  return commands;
}

afterEach(() => {
  vi.unstubAllGlobals();
  endSession();
});

describe("Edit Compose", () => {
  it("edit compose prefills from the opened read and a blank .env sends no env", async () => {
    const commands = server(
      JSON.stringify({
        compose: COMPOSE,
        access: "full",
        title: "Web",
        names: {},
        network: [8080],
        env: ["TOKEN"],
      }),
    );
    const client = new QueryClient();
    const read = await readForEdit(client, node, "web", undefined, pinned.deps);
    expect(commands[0]).toMatchObject({
      kind: "stack",
      name: "web",
      action: "read",
      args: { to: expect.stringMatching(/^[A-Za-z0-9_-]{87}$/u) },
    });
    expect(read).toEqual({
      compose: COMPOSE,
      access: "full",
      title: "Web",
      network: [8080],
      env: ["TOKEN"],
    });
    await saveStack(client, node, {
      name: "web",
      editing: true,
      form: { ...read, env: "" },
      deps: pinned.deps,
    });
    const edit = commands[1] as {
      action: string;
      args: Record<string, string>;
    };
    expect(edit.action).toBe("edit");
    expect(edit.args).toEqual({
      compose: expect.stringMatching(/^[A-Za-z0-9_-]+$/u),
      access: "full",
      network: "8080",
      title: "Web",
      to: expect.stringMatching(/^[A-Za-z0-9_-]{87}$/u),
    });
    expect((await open(pinned.key, edit.args.compose!)).text).toBe(COMPOSE);
    expect("env" in edit.args).toBe(false);
  });

  it("a failed save shows its opened detail, and signs the key it opens with", async () => {
    const commands = server(
      "service app mounts /srv/example-data from the server",
      true,
      { status: "failed", message: "Edit of web failed." },
    );
    const row = await saveStack(new QueryClient(), node, {
      name: "web",
      editing: true,
      form: {
        compose: COMPOSE,
        access: "contained",
        network: [],
        title: "",
        env: "",
      },
      deps: pinned.deps,
    });
    expect(row).toMatchObject({
      status: "failed",
      message: "Edit of web failed.",
      output: "service app mounts /srv/example-data from the server",
    });
    expect(commands).toHaveLength(1);
  });

  it("a failed read says what failed and why", async () => {
    server("the compose file of web does not fit in one answer", true, {
      status: "failed",
      message: "Read of web failed.",
    });
    await expect(
      readForEdit(new QueryClient(), node, "web", undefined, pinned.deps),
    ).rejects.toThrow(
      "Read of web failed. the compose file of web does not fit in one answer",
    );
  });

  it("a failed read whose detail does not open still says what failed", async () => {
    server("the compose file of web does not fit in one answer", false, {
      status: "failed",
      message: "Read of web failed.",
    });
    await expect(
      readForEdit(new QueryClient(), node, "web", undefined, pinned.deps),
    ).rejects.toThrow("Read of web failed. The details could not be opened.");
  });

  it("a read that does not open is a failure, not an empty form", async () => {
    server(JSON.stringify({ compose: COMPOSE }), false);
    await expect(
      readForEdit(new QueryClient(), node, "web", undefined, pinned.deps),
    ).rejects.toThrow("The server's answer could not be opened.");
  });

  it("a stack/read without the compose shows a plain failure", async () => {
    server(JSON.stringify({ access: "full" }));
    await expect(
      readForEdit(new QueryClient(), node, "web", undefined, pinned.deps),
    ).rejects.toThrow("The server's answer did not hold the compose file.");
  });

  it("a stack/read with no output at all is a failure, not an empty form", async () => {
    server(null);
    await expect(
      readForEdit(new QueryClient(), node, "web", undefined, pinned.deps),
    ).rejects.toThrow("The server's answer did not arrive.");
  });

  it("a re-render with an equal-valued new editing object starts no second read and keeps edits", () => {
    const state: ReadState = { started: null, done: false, edited: false };
    const first = { project: "web" };
    const key = readKey(first.project, S1);
    expect(shouldStartRead(key, state)).toBe(true);
    state.started = key;
    const again = { project: "web" };
    expect(again).not.toBe(first);
    expect(shouldStartRead(readKey(again.project, S1), state)).toBe(false);
    state.done = true;
    state.edited = true;
    expect(
      shouldStartRead(readKey({ project: "web" }.project, S1), state),
    ).toBe(false);
    expect(shouldPrefill(state)).toBe(false);
  });

  it("a read cut short before it finished starts again, and none starts without the server", () => {
    const state: ReadState = { started: null, done: false, edited: false };
    const key = readKey("web", S1);
    state.started = key;
    state.started = null;
    expect(shouldStartRead(key, state)).toBe(true);
    expect(shouldStartRead(readKey("web", undefined), state)).toBe(false);
    expect(shouldPrefill({ started: key, done: true, edited: false })).toBe(
      true,
    );
  });
});

describe("Access", () => {
  it("the Contained line says internet only", () => {
    const html = renderToStaticMarkup(
      <AccessChoice value="contained" onChange={() => undefined} />,
    );
    expect(html).toContain("Reaches the internet only; no host paths.");
    expect(html).not.toContain("Contained: ");
    expect(html).not.toContain("own folder and network");
  });
});
