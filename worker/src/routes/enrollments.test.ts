import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { LAPTOP, PHONE } from "../test/keys";
import { createTestDb } from "../test/sqlite-d1";

const INSTALLER = readFileSync(
  new URL("../../../app/public/install.sh", import.meta.url),
  "utf8",
);

function fleet(extra: Partial<Env> = {}) {
  const { db, sqlite } = createTestDb();
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.test",
    ASSETS: {
      fetch: async (request: Request) =>
        new URL(request.url).pathname === "/install.sh"
          ? new Response(INSTALLER)
          : new Response("not found", { status: 404 }),
    },
    ...extra,
  } as unknown as Env;
  const request = (
    method: string,
    path: string,
    body?: unknown,
    token?: string,
  ) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const create = async (setup: unknown = {}) => {
    const response = await request("POST", "/api/enrollments", setup);
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      id: string;
      command: string;
      enrollmentToken: string;
    };
    return { id: body.id, command: body.command, token: body.enrollmentToken };
  };
  const script = async (token: string) => {
    const response = await request("GET", `/i/${token}`);
    return { status: response.status, text: await response.text() };
  };
  const enroll = (token: string, hostname: string) =>
    request(
      "POST",
      "/api/agent/enroll",
      {
        hostname,
        operatingSystem: "linux",
        architecture: "amd64",
        agentVersion: "0.6.0",
      },
      token,
    );
  const status = async (id: string) =>
    (await request("GET", `/api/enrollments/${id}`)).json();
  const nodes = () =>
    sqlite
      .prepare(
        "SELECT id, name, interval_seconds, owner_user_id, enrolled_at FROM nodes",
      )
      .all() as {
      id: string;
      name: string;
      interval_seconds: number;
      owner_user_id: string;
      enrolled_at: string | null;
    }[];
  return { sqlite, request, create, script, enroll, status, nodes };
}

const tail = (text: string) => text.split("\n").slice(-5).join("\n");

describe("enrollment tokens", () => {
  it("creates no node until an agent enrolls, only a short install command", async () => {
    const { create, nodes, status } = fleet();
    const { id, command, token } = await create();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(command).toBe(
      `curl -fsSL https://kry.example.test/i/${token} | sudo sh`,
    );
    expect(nodes()).toEqual([]);
    expect(await status(id)).toEqual({ status: "pending" });
  });

  it("points the command and the installer at AGENT_ORIGIN when it is set", async () => {
    const { create, script } = fleet({
      AGENT_ORIGIN: "https://kry.example.workers.dev",
    });
    const { command, token } = await create();
    expect(command).toBe(
      `curl -fsSL https://kry.example.workers.dev/i/${token} | sudo sh`,
    );
    const served = await script(token);
    expect(served.status).toBe(200);
    expect(served.text.startsWith("#!/bin/sh\n")).toBe(true);
    expect(tail(served.text)).toBe(
      `{\n  kry_args='https://kry.example.workers.dev ${token}'\n  main $kry_args\n}\n`,
    );
    expect(served.text).not.toContain('main "$@"');
  });

  it("serves the chosen setup and lets it change until the server enrolls", async () => {
    const { create, script, request, enroll } = fleet();
    const { id, token } = await create({
      recommended: true,
      docker: true,
      rebootHour: 20,
    });
    expect(tail((await script(token)).text)).toBe(
      `{\n  kry_args='https://kry.example.test ${token} --setup recommended,docker --reboot-hour 20'\n  main $kry_args\n}\n`,
    );
    const changed = await request("PATCH", `/api/enrollments/${id}`, {
      recommended: false,
      docker: true,
      rebootHour: null,
    });
    expect(changed.status).toBe(200);
    expect(tail((await script(token)).text)).toBe(
      `{\n  kry_args='https://kry.example.test ${token} --setup docker'\n  main $kry_args\n}\n`,
    );
    expect(
      (
        await request("PATCH", `/api/enrollments/${id}`, {
          recommended: true,
          docker: true,
          rebootHour: 24,
        })
      ).status,
    ).toBe(400);
    await enroll(token, "web-01");
    expect(
      (
        await request("PATCH", `/api/enrollments/${id}`, {
          recommended: true,
          docker: true,
          rebootHour: 3,
        })
      ).status,
    ).toBe(409);
  });

  it("snapshots the admin user when the command is made and never lets a change replace it", async () => {
    const { create, script, request } = fleet();
    const blob = (line: string) => line.split(" ")[1];
    expect(
      (
        await request("PUT", "/api/settings/enroll-defaults", {
          recommended: true,
          docker: true,
          hour: 3,
          keys: [LAPTOP, PHONE],
        })
      ).status,
    ).toBe(200);
    const { id, token } = await create({
      docker: true,
      adminUser: true,
      adminName: "musyaf",
    });
    const flags = `--admin musyaf --admin-key ${blob(LAPTOP)}:j5mus-laptop --admin-key ${blob(PHONE)}:phone`;
    expect(tail((await script(token)).text)).toBe(
      `{\n  kry_args='https://kry.example.test ${token} --setup docker ${flags}'\n  main $kry_args\n}\n`,
    );
    await request("PUT", "/api/settings/enroll-defaults", {
      recommended: true,
      docker: true,
      hour: 3,
      keys: [PHONE],
    });
    expect(
      (
        await request("PATCH", `/api/enrollments/${id}`, {
          docker: true,
          adminUser: true,
          adminName: "intruder",
          admin: { name: "intruder", keys: [PHONE] },
        })
      ).status,
    ).toBe(200);
    expect(tail((await script(token)).text)).toContain(flags);
    await request("PATCH", `/api/enrollments/${id}`, { docker: true });
    expect(tail((await script(token)).text)).not.toContain("--admin");
    await request("PATCH", `/api/enrollments/${id}`, {
      docker: true,
      adminUser: true,
    });
    expect(tail((await script(token)).text)).toContain(flags);
  });

  it("adds no admin user when Enroll Defaults has no keys", async () => {
    const { create, script } = fleet();
    const { token } = await create({ adminUser: true, adminName: "musyaf" });
    expect(tail((await script(token)).text)).not.toContain("--admin");
    const unnamed = await create({ adminUser: true });
    expect(tail((await script(unnamed.token)).text)).not.toContain("--admin");
  });

  it("refuses an admin user without a usable name while keys are set", async () => {
    const { request } = fleet();
    await request("PUT", "/api/settings/enroll-defaults", {
      recommended: true,
      docker: true,
      hour: 3,
      keys: [LAPTOP],
    });
    for (const adminName of [undefined, "", "root", "Musyaf", "bad name"]) {
      expect(
        (
          await request("POST", "/api/enrollments", {
            adminUser: true,
            adminName,
          })
        ).status,
        String(adminName),
      ).toBe(400);
    }
  });

  it("gets the server ready for the private network only while one exists", async () => {
    const { create, script, sqlite } = fleet();
    const { token } = await create({ docker: true, network: true });
    expect(tail((await script(token)).text)).toBe(
      `{\n  kry_args='https://kry.example.test ${token} --setup docker'\n  main $kry_args\n}\n`,
    );
    sqlite.exec(
      `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
       VALUES ('standalone', '10.88.4.0/24', 51820, 1420, 1, '{}', 'x', 'now', 'owner')`,
    );
    expect(tail((await script(token)).text)).toBe(
      `{\n  kry_args='https://kry.example.test ${token} --setup docker --network 10.88.4.0/24'\n  main $kry_args\n}\n`,
    );
    sqlite.exec("UPDATE network SET deleted = 1");
    expect(tail((await script(token)).text)).not.toContain("--network");
  });

  it("answers a used or unknown command with a script that says why and stops", async () => {
    const { create, script, enroll } = fleet();
    const { token } = await create();
    await enroll(token, "web-01");
    for (const code of [token, "x".repeat(43)]) {
      const served = await script(code);
      expect(served.status).toBe(200);
      expect(served.text).toBe(
        '#!/bin/sh\necho "This install command was already used or has expired. Create a new one in Krynodes." >&2\nexit 1\n',
      );
    }
  });

  it("creates the node from the hostname when the agent enrolls", async () => {
    const { create, enroll, nodes, status } = fleet();
    const { id, token } = await create();

    const response = await enroll(token, "web-01");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { nodeId: string; token: string };

    const [node] = nodes();
    expect(node).toMatchObject({
      id: body.nodeId,
      name: "web-01",
      interval_seconds: 60,
      owner_user_id: "standalone",
    });
    expect(node!.enrolled_at).not.toBeNull();
    expect(await status(id)).toEqual({
      status: "used",
      node: { id: body.nodeId, name: "web-01" },
    });
  });

  it("lets a token enroll exactly one server", async () => {
    const { create, enroll, nodes } = fleet();
    const { token } = await create();
    expect((await enroll(token, "web-01")).status).toBe(200);
    expect((await enroll(token, "intruder")).status).toBe(401);
    expect(nodes().map((node) => node.name)).toEqual(["web-01"]);
  });

  it("cuts a long hostname to the 100-character name limit", async () => {
    const { create, enroll, nodes } = fleet();
    const { token } = await create();
    await enroll(token, "h".repeat(180));
    expect(nodes()[0]!.name).toBe("h".repeat(100));
  });

  it("refuses an expired token and reports it as expired", async () => {
    const { sqlite, create, enroll, nodes, status } = fleet();
    const { id, token } = await create();
    sqlite
      .prepare("UPDATE enrollment_tokens SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 60_000).toISOString(), id);
    expect((await enroll(token, "web-01")).status).toBe(401);
    expect(nodes()).toEqual([]);
    expect(await status(id)).toEqual({ status: "expired" });
  });

  it("does not show another owner's enrollment", async () => {
    const { sqlite, request } = fleet();
    sqlite
      .prepare(
        `INSERT INTO enrollment_tokens (id, owner_user_id, token_hash, expires_at)
         VALUES ('other', 'someone-else', 'hash', ?)`,
      )
      .run(new Date(Date.now() + 60_000).toISOString());
    expect((await request("GET", "/api/enrollments/other")).status).toBe(404);
  });

  it("no longer creates nodes directly", async () => {
    const { request } = fleet();
    expect((await request("POST", "/api/nodes", {})).status).toBe(404);
  });
});
