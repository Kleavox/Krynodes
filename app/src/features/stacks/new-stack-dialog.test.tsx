import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import { S1 } from "@/lib/rules-test-utils";
import { endSession } from "@/lib/sign";
import type { FleetNode } from "@/types";

import {
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

function server(output: string | null) {
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
      commands.push(
        JSON.parse(
          new TextDecoder().decode(
            Uint8Array.from(
              atob(signed.command.replaceAll("-", "+").replaceAll("_", "/")),
              (char) => char.charCodeAt(0),
            ),
          ),
        ) as Record<string, unknown>,
      );
      return new Response(
        JSON.stringify({
          id: body.id,
          nodeId: S1,
          kind: body.kind,
          name: body.name,
          action: body.action,
          title: body.title,
          status: "done",
          message: "Done.",
          output,
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
  it("prefills from stack/read and a blank .env sends no env", async () => {
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
    const read = await readForEdit(client, node, "web");
    expect(commands[0]).toMatchObject({
      kind: "stack",
      name: "web",
      action: "read",
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
      deps: {
        current: () => Promise.reject(new Error("no seal key was asked for")),
      },
    });
    const edit = commands[1] as {
      action: string;
      args: Record<string, string>;
    };
    expect(edit.action).toBe("edit");
    expect(edit.args).toEqual({
      compose: COMPOSE,
      access: "full",
      network: "8080",
      title: "Web",
    });
    expect("env" in edit.args).toBe(false);
  });

  it("a stack/read without the compose shows a plain failure", async () => {
    server(null);
    await expect(readForEdit(new QueryClient(), node, "web")).rejects.toThrow(
      "The server's answer did not hold the compose file.",
    );
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
