import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { LAPTOP, LAPTOP_PRINT, PHONE } from "../test/keys";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const NODE = "11111111-1111-4111-8111-111111111111";

function setup() {
  const { db, sqlite } = createTestDb();
  seedNode(sqlite, { id: NODE });
  const env = { DB: db } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      env,
    );
  return { call, sqlite };
}

const security = {
  checkedAt: "2026-10-10T09:00:00.000Z",
  findings: [
    {
      id: "public-ports",
      severity: "warning",
      detail:
        "Listening on public addresses outside Krynodes: 57969/tcp (tailscaled), 41641/udp (tailscaled)",
    },
  ],
  recipes: [],
  lockdown: false,
  rebootHour: null,
  listeners: [
    {
      address: "100.79.66.29",
      port: 57969,
      protocol: "tcp",
      process: "tailscaled",
    },
    { address: "0.0.0.0", port: 41641, protocol: "udp", process: "tailscaled" },
  ],
};

describe("server addresses", () => {
  it("no longer serves the address display", async () => {
    const { call } = setup();
    expect((await call("GET", "/api/settings/address-display")).status).toBe(
      404,
    );
  });
});

describe("enroll defaults", () => {
  it("start with protections, Docker and 03:00, and keep what is saved", async () => {
    const { call } = setup();
    expect(
      await (await call("GET", "/api/settings/enroll-defaults")).json(),
    ).toEqual({
      recommended: true,
      docker: true,
      hour: 3,
      network: false,
      admin: null,
    });
    const saved = await call("PUT", "/api/settings/enroll-defaults", {
      recommended: true,
      docker: false,
      hour: 22,
    });
    expect(saved.status).toBe(200);
    expect(
      await (await call("GET", "/api/settings/enroll-defaults")).json(),
    ).toEqual({
      recommended: true,
      docker: false,
      hour: 22,
      network: false,
      admin: null,
    });
  });

  it("refuses an hour outside the day", async () => {
    const { call } = setup();
    for (const hour of [-1, 24, 3.5]) {
      expect(
        (
          await call("PUT", "/api/settings/enroll-defaults", {
            recommended: true,
            docker: true,
            hour,
          })
        ).status,
      ).toBe(400);
    }
  });
});

describe("the admin user in enroll defaults", () => {
  const defaults = { recommended: true, docker: true, hour: 3, network: false };

  it("keeps a name and its keys and shows each key's fingerprint", async () => {
    const { call } = setup();
    const saved = await call("PUT", "/api/settings/enroll-defaults", {
      ...defaults,
      admin: { name: "musyaf", keys: [LAPTOP, PHONE] },
    });
    expect(saved.status).toBe(200);
    const read = (await (
      await call("GET", "/api/settings/enroll-defaults")
    ).json()) as { admin: { name: string; keys: unknown[] } };
    expect(read.admin).toEqual({
      name: "musyaf",
      keys: [
        {
          line: LAPTOP,
          type: "ssh-ed25519",
          fingerprint: LAPTOP_PRINT,
          label: "j5mus-laptop",
        },
        {
          line: PHONE,
          type: "ssh-ed25519",
          fingerprint: "SHA256:8N+1D7dUMegVjJ9iFeI8fD+W16LUuALxq/zyJv66bQk",
          label: "phone",
        },
      ],
    });
  });

  it("refuses root, a bad name, a key it cannot read and more than four keys", async () => {
    const { call } = setup();
    for (const admin of [
      { name: "root", keys: [LAPTOP] },
      { name: "Musyaf", keys: [LAPTOP] },
      { name: "musyaf", keys: [] },
      { name: "musyaf", keys: ["ssh-ed25519 AAAA laptop"] },
      { name: "musyaf", keys: Array(5).fill(LAPTOP) },
    ]) {
      expect(
        (
          await call("PUT", "/api/settings/enroll-defaults", {
            ...defaults,
            admin,
          })
        ).status,
        JSON.stringify(admin.name),
      ).toBe(400);
    }
  });
});

describe("addresses that are not public", () => {
  it("starts empty and stores normalized ranges once each", async () => {
    const { call } = setup();
    expect(
      await (await call("GET", "/api/settings/private-ranges")).json(),
    ).toEqual({ ranges: [], network: null });
    const saved = await call("PUT", "/api/settings/private-ranges", {
      ranges: ["100.64.0.0/10", " fd7a:115c:a1e0::/48 ", "100.64.0.1/10"],
    });
    expect(saved.status).toBe(200);
    expect(await saved.json()).toEqual({
      ranges: ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
    });
    expect(
      await (await call("GET", "/api/settings/private-ranges")).json(),
    ).toEqual({
      ranges: ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
      network: null,
    });
  });

  it("names the entry it cannot read", async () => {
    const { call } = setup();
    const response = await call("PUT", "/api/settings/private-ranges", {
      ranges: ["10.0.0.0/8", "10.0.0/8"],
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      code: "INVALID_RANGE",
      message: "10.0.0/8 is not an address range, such as 10.8.0.0/24.",
    });
    expect(
      (
        await call("PUT", "/api/settings/private-ranges", {
          ranges: Array.from(
            { length: 33 },
            (_, index) => `10.${index}.0.0/16`,
          ),
        })
      ).status,
    ).toBe(400);
  });

  it("applies the ranges to every server's security report", async () => {
    const { call, sqlite } = setup();
    sqlite
      .prepare("UPDATE nodes SET security = ? WHERE id = ?")
      .run(JSON.stringify(security), NODE);
    const detail = async () =>
      (
        (await (await call("GET", "/api/services")).json()) as {
          nodes: { security: { findings: { detail: string }[] } }[];
        }
      ).nodes[0]!.security.findings[0]?.detail;
    expect(await detail()).toContain("57969/tcp");
    await call("PUT", "/api/settings/private-ranges", {
      ranges: ["100.64.0.0/10"],
    });
    expect(await detail()).toBe(
      "Listening on public addresses outside Krynodes: 41641/udp (tailscaled)",
    );
  });

  it("counts the private network's range as private while it exists", async () => {
    const { call, sqlite } = setup();
    sqlite.prepare("UPDATE nodes SET security = ? WHERE id = ?").run(
      JSON.stringify({
        ...security,
        findings: [
          {
            ...security.findings[0],
            detail:
              "Listening on public addresses outside Krynodes: 5432/tcp (postgres), 41641/udp (tailscaled)",
          },
        ],
        listeners: [
          {
            address: "10.88.4.1",
            port: 5432,
            protocol: "tcp",
            process: "postgres",
          },
          security.listeners[1],
        ],
      }),
      NODE,
    );
    sqlite.exec(
      `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
       VALUES ('standalone', '10.88.4.0/24', 51820, 1420, 1, '{}', 'x', 'now', 'owner')`,
    );
    const detail = async () =>
      (
        (await (await call("GET", "/api/services")).json()) as {
          nodes: { security: { findings: { detail: string }[] } }[];
        }
      ).nodes[0]!.security.findings[0]?.detail;
    expect(await detail()).toBe(
      "Listening on public addresses outside Krynodes: 41641/udp (tailscaled)",
    );
    sqlite.exec("UPDATE network SET deleted = 1");
    expect(await detail()).toContain("5432/tcp");
  });

  it("puts what only the network reaches on its own line, and sends each stack's network", async () => {
    const { call, sqlite } = setup();
    sqlite.prepare("UPDATE nodes SET security = ? WHERE id = ?").run(
      JSON.stringify({
        ...security,
        listeners: [
          ...security.listeners,
          {
            address: "10.88.4.2",
            port: 5432,
            protocol: "tcp",
            process: "db-db-1",
          },
        ],
      }),
      NODE,
    );
    sqlite.exec(
      `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
       VALUES ('standalone', '10.88.4.0/24', 51820, 1420, 1, '{}', 'x', 'now', 'owner')`,
    );
    const network = {
      serves: [{ port: "5432/tcp", all: true }],
      reaches: [],
      private: ["5432/tcp"],
    };
    sqlite
      .prepare(
        `INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at, access, network)
         VALUES (?, 'db', '/srv/db', 1, 1, 1, 0, 'now', 'contained', ?)`,
      )
      .run(NODE, JSON.stringify(network));
    const node = (
      (await (await call("GET", "/api/services")).json()) as {
        nodes: {
          security: { findings: { id: string; detail: string }[] };
          stacks: { project: string; network: unknown }[];
        }[];
      }
    ).nodes[0]!;
    expect(
      node.security.findings.find((finding) => finding.id === "private-ports")
        ?.detail,
    ).toBe("On the private network only: 5432/tcp (db-db-1)");
    expect(node.stacks).toMatchObject([{ project: "db", network }]);
  });

  it("never sends the addresses a server's listeners are bound to", async () => {
    const { call, sqlite } = setup();
    const services = async () =>
      (await (await call("GET", "/api/services")).json()) as {
        nodes: { security: Record<string, unknown> }[];
      };
    for (const report of [security, { ...security, findings: "old" }]) {
      sqlite
        .prepare("UPDATE nodes SET security = ? WHERE id = ?")
        .run(JSON.stringify(report), NODE);
      for (const ranges of [[], ["100.64.0.0/10"]]) {
        await call("PUT", "/api/settings/private-ranges", { ranges });
        const body = await services();
        expect(body.nodes[0]!.security).not.toHaveProperty("listeners");
        expect(JSON.stringify(body)).not.toContain("100.79.66.29");
      }
    }
  });
});
