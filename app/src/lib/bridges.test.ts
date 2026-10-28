import type { BridgesReport } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import type { StackEntry } from "../types";
import {
  composeLines,
  composeNote,
  deleteText,
  moveLines,
  nameLine,
  networkBoxes,
  pickSubnet,
  stackNetworkArgs,
  subnetLine,
} from "./bridges";

const report: BridgesReport = {
  networks: [
    {
      name: "apps-inner",
      kind: "contained",
      subnet: "172.24.0.0/24",
      members: [
        {
          project: "kuma",
          service: "web",
          address: "172.24.0.3",
          offers: ["3001/tcp"],
          guest: false,
        },
        {
          project: "db",
          service: "postgres",
          address: "172.24.0.4",
          offers: ["5432/tcp"],
          guest: true,
        },
        {
          project: "adns",
          service: "adguard",
          address: "172.24.0.2",
          offers: ["53/udp"],
          guest: false,
        },
      ],
    },
    {
      name: "default-env_public",
      kind: "full",
      subnet: "172.23.0.0/16",
      members: [
        {
          project: "grafana",
          service: "grafana",
          address: null,
          offers: [],
          guest: false,
        },
        {
          project: "umami",
          service: "umami",
          address: null,
          offers: [],
          guest: false,
        },
      ],
    },
    { name: "proxy", kind: "outside", subnet: "172.30.0.0/16", members: [] },
  ],
  taken: [
    { range: "172.18.0.0/16", by: "kuma_default" },
    { range: "172.24.0.0/24", by: "apps-inner" },
    { range: "172.23.0.0/16", by: "default-env_public" },
    { range: "192.168.1.0/24", by: "eth0", own: true },
  ],
  claimed: ["kuma_default"],
};

const stack = (
  project: string,
  network: Partial<NonNullable<StackEntry["network"]>> = {},
): StackEntry => ({
  project,
  directory: `/opt/${project}`,
  running: 1,
  total: 1,
  compose: true,
  rollback: false,
  access: "contained",
  network: {
    serves: [],
    reaches: [],
    private: [],
    offers: [],
    peers: [],
    ...network,
  },
});

const kuma = stack("kuma", {
  offers: ["apps-inner/web=3001/tcp"],
  peers: ["apps-inner/postgres.db:5432/tcp", "apps-inner/old.gone:80/tcp"],
});
const adns = stack("adns", { peers: ["apps-inner/web.kuma:3001/tcp"] });
const db = {
  ...stack("db", { offers: ["apps-inner/postgres=5432/tcp"] }),
  access: "full" as const,
};
const io = { name: "io", bridges: report, stacks: [kuma, adns, db] };

const joining = (network: string, service = "web", extra = "") => `services:
  ${service}:
    image: example/app:1
    networks:
      - shared
${extra}
networks:
  shared:
    name: ${network}
    external: true
`;

describe("picking a free subnet", () => {
  it("takes the first /24 of 172.24.0.0/13 nothing uses", () => {
    expect(pickSubnet([], null)).toBe("172.24.0.0/24");
    expect(pickSubnet(report.taken, null)).toBe("172.24.1.0/24");
    expect(pickSubnet([], "172.24.0.0/23")).toBe("172.24.2.0/24");
    expect(
      pickSubnet([{ range: "172.24.0.0/13", by: "big" }], null),
    ).toBeNull();
  });
});

describe("the subnet line", () => {
  const line = (input: string, privateRange: string | null = "10.88.0.0/24") =>
    subnetLine(input, { name: "io", bridges: report }, privateRange);

  it("says what Krynodes picks or that a typed one is free", () => {
    expect(line("")).toEqual({
      ok: true,
      text: "Krynodes picks 172.24.1.0/24, free on io.",
    });
    expect(line("172.25.0.0/24")).toEqual({ ok: true, text: "✓ Free on io" });
  });

  it("refuses in the agent's order", () => {
    for (const [input, text] of [
      ["172.25.0.0", "Write it as 172.24.0.0/24."],
      ["300.1.0.0/24", "Write it as 172.24.0.0/24."],
      ["172.25.0.5/24", "Write it as 172.25.0.0/24."],
      ["172.18.5.0/24", "Overlaps kuma_default (172.18.0.0/16) on io."],
      ["10.88.0.0/16", "Overlaps your private network (10.88.0.0/24)."],
      ["100.64.1.0/24", "Overlaps Tailscale's addresses (100.64.0.0/10)."],
      ["192.168.1.0/25", "Overlaps io's own network (192.168.1.0/24 on eth0)."],
      [
        "8.8.8.0/24",
        "Use a private range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16.",
      ],
      ["10.0.0.0/15", "Use a prefix from /16 to /28."],
      ["172.25.0.0/29", "Use a prefix from /16 to /28."],
    ] as const) {
      expect(line(input)).toEqual({ ok: false, text });
    }
  });

  it("shows -- and stays off before the server reports its networks", () => {
    expect(subnetLine("", { name: "io", bridges: null }, null)).toEqual({
      ok: false,
      text: "--",
    });
  });
});

describe("the name line", () => {
  it("takes a Docker network name nobody has", () => {
    expect(nameLine("apps-inner", io)).toEqual({
      ok: false,
      text: "io already has a network named apps-inner.",
    });
    expect(nameLine("-x", io).ok).toBe(false);
    expect(nameLine("", io)).toEqual({
      ok: false,
      text: "Letters, digits, dots, dashes and underscores.",
    });
    expect(nameLine("shared.cache", io)).toEqual({
      ok: true,
      text: "Letters, digits, dots, dashes and underscores.",
    });
  });

  it("names the stack that makes a network with that name itself", () => {
    const server = {
      name: "io",
      bridges: { ...report, claimed: ["default-env_public", "orphan_net"] },
      stacks: [stack("default"), stack("default-env")],
    };
    expect(
      nameLine("default-env_public", {
        ...server,
        bridges: { ...server.bridges, networks: [] },
      }),
    ).toEqual({
      ok: false,
      text: "The default-env stack makes its own public network with this name. Write external: true there, or pick another name.",
    });
    expect(nameLine("orphan_net", server).text).toBe(
      "A stack on io makes its own network with this name. Write external: true there, or pick another name.",
    );
  });
});

describe("compose lines, notes and deleting", () => {
  it("writes the lines a stack adds to join", () => {
    expect(composeLines(report.networks[1]!, "grafana")).toBe(`services:
  grafana:
    networks:
      - public

networks:
  public:
    name: default-env_public
    external: true
`);
    expect(composeLines(report.networks[0]!, "app")).toContain(
      "  apps-inner:\n    name: apps-inner\n",
    );
    expect(composeNote("full", "io")).toBe(
      "Only Full Access stacks on io can use it.",
    );
    expect(composeNote("contained", "io")).toBe(
      "Contained stacks on io join it; a Full Access stack joins as a guest.",
    );
    expect(composeNote("outside", "io")).toBe(
      "Only Full Access stacks on io can use it.",
    );
  });

  it("deletes only what nothing uses", () => {
    expect(deleteText(report.networks[1]!)).toEqual({
      title: "Delete default-env_public?",
      body: "grafana and umami still use it. Take it out of their compose files first.",
      ok: false,
    });
    expect(deleteText({ ...report.networks[0]!, members: [] })).toEqual({
      title: "Delete apps-inner?",
      body: "Nothing uses it now. Its addresses are freed.",
      ok: true,
    });
  });
});

describe("network boxes in the stack dialog", () => {
  it("gives a Contained stack its offers and what it may reach", () => {
    expect(
      networkBoxes(joining("apps-inner"), io, "kuma", "contained"),
    ).toEqual([
      {
        name: "apps-inner",
        kind: "contained",
        guest: false,
        address: "kuma's web is 172.24.0.3 here.",
        offers: [{ service: "web", value: "3001/tcp" }],
        reach: [
          {
            entry: "postgres.db:5432/tcp",
            guest: true,
            ticked: true,
            gone: false,
          },
          {
            entry: "adguard.adns:53/udp",
            guest: false,
            ticked: false,
            gone: false,
          },
          { entry: "old.gone:80/tcp", guest: false, ticked: true, gone: true },
        ],
        refusal: null,
      },
    ]);
  });

  it("gives a Full Access stack a guest box with offers only", () => {
    expect(
      networkBoxes(joining("apps-inner", "postgres"), io, "db", "full"),
    ).toEqual([
      {
        name: "apps-inner",
        kind: "contained",
        guest: true,
        address:
          "db joins as a guest: it answers on the ports it offers and never starts a connection here. postgres is 172.24.0.4.",
        offers: [{ service: "postgres", value: "5432/tcp" }],
        reach: [],
        refusal: null,
      },
    ]);
  });

  it("refuses a service whose name another stack already has on the network", () => {
    expect(
      networkBoxes(
        joining("apps-inner", "adguard"),
        io,
        "pihole",
        "contained",
      )[0]!.refusal,
    ).toBe(
      "apps-inner already has a service named adguard, from adns. Rename this one in the compose file.",
    );
  });

  it("tells a new service where its address comes from", () => {
    expect(
      networkBoxes(joining("apps-inner", "app"), io, "status", "contained")[0]!
        .address,
    ).toBe("app gets an address from 172.24.0.0/24 when it starts.");
  });

  it("refuses what a stack cannot join", () => {
    const refusal = (
      text: string,
      project = "status",
      access: "contained" | "full" = "contained",
    ) => networkBoxes(text, io, project, access).map((box) => box.refusal);
    expect(refusal(joining("default-env_public"))).toEqual([
      "A Contained stack cannot join default-env_public, a Full Access network.",
    ]);
    expect(refusal(joining("proxy"))).toEqual([
      "proxy on io was not made by Krynodes as a Contained network. Create one under Docker Networks.",
    ]);
    expect(refusal(joining("shared-cache"))).toEqual([
      "shared-cache is not on io. Create it under Docker Networks first.",
    ]);
    expect(
      refusal(
        joining("apps-inner", "postgres", "    privileged: true"),
        "db",
        "full",
      ),
    ).toEqual([
      "postgres is privileged, so it cannot join apps-inner, a Contained network.",
    ]);
    expect(
      refusal(
        joining("apps-inner", "postgres", "    cap_add: [NET_ADMIN]"),
        "db",
        "full",
      ),
    ).toEqual([
      "postgres adds NET_ADMIN, so it cannot join apps-inner, a Contained network.",
    ]);
    expect(
      refusal(joining("apps-inner", "app", "    deploy:\n      replicas: 2")),
    ).toEqual([
      "app runs 2 copies; a service on a Contained network runs one, so its address stays fixed.",
    ]);
    expect(
      networkBoxes(joining("default-env_public"), io, "grafana", "full"),
    ).toEqual([]);
    expect(
      networkBoxes(
        "services:\n  web:\n    image: x\n",
        io,
        "kuma",
        "contained",
      ),
    ).toEqual([]);
  });
});

describe("what the stack dialog sends for its networks", () => {
  const kumaBoxes = networkBoxes(
    joining("apps-inner"),
    io,
    "kuma",
    "contained",
  );

  it("sends the offers and the ticked ports of other stacks", () => {
    expect(
      stackNetworkArgs(kumaBoxes, {}, { "apps-inner/old.gone:80/tcp": false }),
    ).toEqual({
      args: {
        offers: "apps-inner/web=3001/tcp",
        peers: "apps-inner/postgres.db:5432/tcp",
      },
      problem: null,
    });
    expect(
      stackNetworkArgs(
        kumaBoxes,
        { "apps-inner/web": "3001/tcp, 9000/udp" },
        {
          "apps-inner/postgres.db:5432/tcp": false,
          "apps-inner/adguard.adns:53/udp": true,
        },
      ).args,
    ).toEqual({
      offers: "apps-inner/web=3001/tcp,apps-inner/web=9000/udp",
      peers: "apps-inner/adguard.adns:53/udp,apps-inner/old.gone:80/tcp",
    });
  });

  it("sends neither for a stack with no shared network", () => {
    expect(stackNetworkArgs([], {}, {})).toEqual({ args: {}, problem: null });
  });

  it("sends only offers for a guest", () => {
    const boxes = networkBoxes(
      joining("apps-inner", "postgres"),
      io,
      "db",
      "full",
    );
    expect(
      stackNetworkArgs(boxes, { "apps-inner/postgres": "" }, {}).args,
    ).toEqual({
      offers: "",
    });
  });

  it("stops at a refusal or a port that is not one", () => {
    expect(
      stackNetworkArgs(
        networkBoxes(joining("proxy"), io, "status", "contained"),
        {},
        {},
      ).problem,
    ).toBe(
      "proxy on io was not made by Krynodes as a Contained network. Create one under Docker Networks.",
    );
    expect(
      stackNetworkArgs(kumaBoxes, { "apps-inner/web": "3001" }, {}).problem,
    ).toBe("web offers 3001; write a port such as 3001/tcp.");
    expect(
      stackNetworkArgs(kumaBoxes, { "apps-inner/web": "70000/tcp" }, {})
        .problem,
    ).toBe("web offers 70000/tcp; write a port such as 3001/tcp.");
  });
});

describe("moving a stack that uses Krynodes networks", () => {
  const empty: BridgesReport = { networks: [], taken: [], claimed: [] };
  const kumaMoving = {
    ...kuma,
    network: { ...kuma.network!, peers: ["apps-inner/postgres.db:5432/tcp"] },
  };
  const from = { ...io, stacks: [kumaMoving, adns, db] };

  it("creates the network first and says who loses what", () => {
    expect(
      moveLines(kumaMoving, from, { name: "vps-2", bridges: empty }),
    ).toEqual({
      lines: [
        "+ Creates apps-inner on vps-2 first · Contained · 172.24.0.0/24",
        "kuma reaches postgres.db on apps-inner. db stays on io, so kuma loses that after the move.",
        "adns reaches web.kuma on apps-inner. It loses that once kuma leaves io.",
      ],
      refusal: null,
      creates: [
        { name: "apps-inner", kind: "contained", subnet: "172.24.0.0/24" },
      ],
    });
  });

  it("refuses a target whose network already has a service of that name", () => {
    expect(
      moveLines(kumaMoving, from, {
        name: "vps-2",
        bridges: {
          ...empty,
          networks: [
            {
              ...report.networks[0]!,
              members: [
                { ...report.networks[0]!.members[0]!, project: "status" },
              ],
            },
          ],
        },
      }).refusal,
    ).toBe(
      "apps-inner on vps-2 already has a service named web, from status. Move is off.",
    );
  });

  it("refuses a target whose subnet or name is taken", () => {
    expect(
      moveLines(kumaMoving, from, {
        name: "vps-2",
        bridges: {
          ...empty,
          taken: [{ range: "172.24.0.0/16", by: "umami_default" }],
        },
      }).refusal,
    ).toBe(
      "apps-inner's subnet 172.24.0.0/24 overlaps umami_default (172.24.0.0/16) on vps-2. Move is off.",
    );
    expect(
      moveLines(kumaMoving, from, {
        name: "vps-2",
        bridges: {
          ...empty,
          networks: [
            {
              name: "apps-inner",
              kind: "outside",
              subnet: "172.24.0.0/24",
              members: [],
            },
          ],
        },
      }).refusal,
    ).toBe(
      "vps-2 already has a network named apps-inner that Krynodes did not make. Move is off.",
    );
    expect(
      moveLines(kumaMoving, from, {
        name: "vps-2",
        bridges: {
          ...empty,
          networks: [
            {
              name: "apps-inner",
              kind: "contained",
              subnet: "172.24.0.0/24",
              members: [],
            },
          ],
        },
      }).creates,
    ).toEqual([]);
    expect(
      moveLines(stack("plain"), from, { name: "vps-2", bridges: null }),
    ).toEqual({ lines: [], refusal: null, creates: [] });
  });
});
