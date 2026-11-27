import { joinFingerprint, type NetworkDocument } from "@krynodes/protocol";
import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import { runAction } from "@/features/actions/run-action";
import { endSession } from "@/lib/sign";
import type { FleetNode } from "@/types";

import { memoryStore, remember } from "./pins";
import { network, S1, S2 } from "./rules-test-utils";
import { open, recipient } from "./seal-test-utils";
import {
  buildStackArgs,
  checkLabel,
  portAllowed,
  publishedPorts,
  readStack,
  stackLine,
  type SealDeps,
  type StackForm,
} from "./stacks";

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
  update: null,
  kind: "server",
  address: "10.88.37.11",
  via: null,
  ms: null,
  request: null,
};

const COMPOSE = "services:\n  app:\n    image: nginx:1.27\n";

const form = (patch: Partial<StackForm> = {}): StackForm => ({
  compose: COMPOSE,
  access: "contained",
  network: [],
  title: "",
  env: "",
  ...patch,
});

async function sealedTo() {
  const to = await recipient();
  const document: NetworkDocument = network([]);
  document.members[0]!.sealKey = to.public;
  const member = document.members[0]!;
  const fingerprint = await joinFingerprint(
    member.key,
    member.signer,
    member.sealKey,
  );
  return {
    to,
    fingerprint,
    current: async () => ({ document, hash: "q".repeat(43) }),
  };
}

function authenticator() {
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
}

const decode = (text: string) =>
  JSON.parse(
    new TextDecoder().decode(
      Uint8Array.from(
        atob(text.replaceAll("-", "+").replaceAll("_", "/")),
        (char) => char.charCodeAt(0),
      ),
    ),
  ) as Record<string, unknown>;

interface Signed {
  kind: string;
  name: string;
  action: string;
  args: Record<string, string>;
}

async function signed(
  args: Record<string, string>,
  deps: SealDeps,
  action = "create",
) {
  authenticator();
  vi.stubGlobal("location", { hostname: "kry.example.test" });
  const posted: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init: RequestInit = {}) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      posted.push(body);
      return new Response(
        JSON.stringify({
          id: body.id,
          nodeId: S1,
          kind: "stack",
          name: "web",
          action,
          title: "New Stack",
          status: "done",
          message: "web runs.",
          createdAt: "2026-11-22T10:00:00.000Z",
          finishedAt: "2026-11-22T10:00:01.000Z",
        }),
        { status: 201 },
      );
    }),
  );
  await runAction(
    new QueryClient(),
    node,
    {
      kind: "stack",
      action,
      name: "web",
      title: "New Stack",
      args,
    },
    undefined,
    undefined,
    deps,
  );
  const body = String(posted[0]!.signed);
  const command = decode(
    (JSON.parse(body) as { command: string }).command,
  ) as unknown as Signed;
  return { posted: posted[0]!, body, command };
}

afterEach(() => {
  vi.unstubAllGlobals();
  endSession();
});

describe("a stack's signed settings", () => {
  it("new stack signs the sealed compose and the sealed env inside the command", async () => {
    const { to, fingerprint, current } = await sealedTo();
    const store = memoryStore();
    remember(store, [{ node: S1, fingerprint }]);
    const args = await buildStackArgs(
      form({ env: "TOKEN=abc\n", network: [8080], title: "Web" }),
      node,
      { current, store },
    );
    const { posted, command } = await signed(args, { current, store });
    expect(posted).toMatchObject({ kind: "stack", name: "web" });
    expect(command).toMatchObject({
      kind: "stack",
      name: "web",
      action: "create",
    });
    expect(command.args.access).toBe("contained");
    expect(command.args.network).toBe("8080");
    expect(command.args.title).toBe("Web");
    expect(command.args.to).toMatch(/^[A-Za-z0-9_-]{87}$/u);
    expect(command.args.compose).not.toContain("nginx");
    expect(command.args.env).not.toContain("TOKEN");
    expect((await open(to, command.args.compose!)).text).toBe(COMPOSE);
    expect((await open(to, command.args.env!)).text).toBe("TOKEN=abc\n");
  });

  it("the signed save carries no compose text", async () => {
    const { to, fingerprint, current } = await sealedTo();
    const store = memoryStore();
    remember(store, [{ node: S1, fingerprint }]);
    const secret = "    image: registry.example.test/private-app:9.9.9";
    const compose = `services:\n  app:\n${secret}\n`;
    const args = await buildStackArgs(form({ compose }), node, {
      current,
      store,
    });
    const { body, command } = await signed(args, { current, store }, "edit");
    for (const text of [body, JSON.stringify(command)]) {
      expect(text).not.toContain("private-app");
      expect(text).not.toContain("registry.example.test");
    }
    expect(command.action).toBe("edit");
    expect((await open(to, command.args.compose!)).text).toBe(compose);
  });

  it("an unanchored server shows the fingerprint check before sealing", async () => {
    const { to, fingerprint, current } = await sealedTo();
    const store = memoryStore();
    const refused = vi.fn(async () => false);
    await expect(
      buildStackArgs(form({ env: "A=1" }), node, {
        current,
        store,
        check: refused,
      }),
    ).rejects.toThrow(
      "The fingerprint was not confirmed. Nothing was sealed or signed.",
    );
    expect(refused).toHaveBeenCalledWith([
      {
        node: S1,
        name: "server-1",
        fingerprint,
        line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
      },
    ]);
    const confirmed = vi.fn(async () => true);
    const args = await buildStackArgs(form({ env: "A=1" }), node, {
      current,
      store,
      check: confirmed,
    });
    expect((await open(to, args.env!)).text).toBe("A=1");
    const again = vi.fn(async () => false);
    await buildStackArgs(form({ env: "A=2" }), node, {
      current,
      store,
      check: again,
    });
    expect(again).not.toHaveBeenCalled();
  });

  it("a stack without an .env still seals its compose and sends no env", async () => {
    const { to, fingerprint, current } = await sealedTo();
    const store = memoryStore();
    remember(store, [{ node: S1, fingerprint }]);
    const check = vi.fn(async () => false);
    const args = await buildStackArgs(form({ access: "full" }), node, {
      current,
      store,
      check,
    });
    expect(Object.keys(args).sort()).toEqual(["access", "compose", "network"]);
    expect((await open(to, args.compose!)).text).toBe(COMPOSE);
    expect(check).not.toHaveBeenCalled();
  });

  it("an unanchored server asks for the fingerprint once for a compose and an .env", async () => {
    const { to, current } = await sealedTo();
    const check = vi.fn(async () => true);
    const args = await buildStackArgs(form({ env: "A=1" }), node, {
      current,
      store: memoryStore(),
      check,
    });
    expect(check).toHaveBeenCalledTimes(1);
    expect((await open(to, args.compose!)).text).toBe(COMPOSE);
    expect((await open(to, args.env!)).text).toBe("A=1");
  });

  it("refuses a save for a server outside the private network", async () => {
    for (const env of ["", "A=1"]) {
      await expect(
        buildStackArgs(form({ env }), node, {
          current: async () => null,
          store: memoryStore(),
        }),
      ).rejects.toThrow(
        "server-1 is not in the private network, so its compose file cannot be sealed.",
      );
    }
  });

  it("seals a compose of 32768 bytes into what the server accepts, and a longer one never", async () => {
    const { to, fingerprint, current } = await sealedTo();
    const store = memoryStore();
    remember(store, [{ node: S1, fingerprint }]);
    const text = "a".repeat(32768);
    const args = await buildStackArgs(form({ compose: text }), node, {
      current,
      store,
    });
    expect(args.compose).toHaveLength(58463);
    expect((await open(to, args.compose!)).text).toBe(text);
    await expect(
      buildStackArgs(form({ compose: "€".repeat(10923) }), node, {
        current,
        store,
      }),
    ).rejects.toThrow("The compose file must be at most 32 KB.");
  });

  it("seals a 16384-byte .env into what the server accepts, and a longer one never", async () => {
    const { to, fingerprint, current } = await sealedTo();
    const store = memoryStore();
    remember(store, [{ node: S1, fingerprint }]);
    const env = "K=" + "é".repeat(8191);
    expect(new TextEncoder().encode(env)).toHaveLength(16384);
    const args = await buildStackArgs(
      form({ compose: "a".repeat(32768), env }),
      node,
      { current, store },
    );
    expect(args.compose).toHaveLength(58463);
    expect(args.env).toHaveLength(29336);
    expect((await open(to, args.env!)).text).toBe(env);
    await expect(
      buildStackArgs(form({ env: env + "a" }), node, { current, store }),
    ).rejects.toThrow("The .env must be at most 16 KB.");
  });

  it("refuses an empty or oversized compose before anything is signed", async () => {
    await expect(buildStackArgs(form({ compose: " " }), node)).rejects.toThrow(
      "Paste a compose file.",
    );
    await expect(
      buildStackArgs(form({ compose: "a".repeat(32769) }), node),
    ).rejects.toThrow("The compose file must be at most 32 KB.");
  });
});

describe("what the pages say", () => {
  it("a stopped-by-owner check reads Paused", () => {
    expect(checkLabel({ state: "down", cause: "owner" })).toBe("Paused");
    expect(checkLabel({ state: "down", cause: null })).toBe("Down");
    expect(checkLabel({ state: "up", cause: null })).toBe("Up");
  });

  it("a check of a removed container or an offline server reads --", () => {
    expect(checkLabel({ state: "gone", cause: null })).toBe("--");
    expect(checkLabel({ state: "unknown", cause: null })).toBe("--");
    expect(checkLabel({ state: "gone", cause: "owner" })).toBe("--");
  });

  it("counts running containers", () => {
    expect(stackLine({ running: 2, total: 3 })).toBe("2 of 3 running");
  });

  it("finds the host ports a compose file publishes", () => {
    expect(
      publishedPorts(
        [
          "x-ports: &ports",
          '  - "9000:9000"',
          "services:",
          "  web:",
          "    image: nginx",
          "    ports:",
          '      - "8080:80"',
          '      - "127.0.0.1:8443:443/tcp"',
          '      - "[::]:8053:53/udp"',
          '      - "3000"',
          '      - "${PORT}:80"',
          '      - "7000-7002:7000-7002"',
          "  api:",
          "    image: api",
          "    ports: *ports",
          "  db:",
          "    image: db",
          "    ports:",
          "      - target: 5432",
          "        published: 5432",
        ].join("\n"),
      ),
    ).toEqual([5432, 7000, 7001, 7002, 8053, 8080, 8443, 9000]);
    expect(publishedPorts("services: [")).toEqual([]);
    expect(publishedPorts("")).toEqual([]);
  });

  it("knows which ports a Connections rule lets through to a server", () => {
    const document = network([
      {
        from: { group: "laptops" },
        to: { node: S1 },
        ports: ["8000-8100/tcp"],
      },
    ]);
    expect(portAllowed(document, S1, 8080)).toBe(true);
    expect(portAllowed(document, S1, 9000)).toBe(false);
    expect(portAllowed(document, S2, 8080)).toBe(false);
    expect(
      portAllowed(
        network([
          {
            from: { group: "laptops" },
            to: { group: "servers" },
            ports: "all",
          },
        ]),
        S2,
        9000,
      ),
    ).toBe(true);
    expect(portAllowed(undefined, S1, 8080)).toBe(false);
  });

  it("reads a stack's stored settings and never an .env value", () => {
    expect(
      readStack(
        JSON.stringify({
          compose: COMPOSE,
          access: "full",
          title: "Web",
          names: {},
          network: [8080],
          env: ["TOKEN"],
        }),
      ),
    ).toEqual({
      compose: COMPOSE,
      access: "full",
      title: "Web",
      network: [8080],
      env: ["TOKEN"],
    });
    expect(() => readStack(null)).toThrow(
      "The server's answer did not hold the compose file.",
    );
  });
});
