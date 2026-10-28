import type { BridgesReport } from "@krynodes/protocol";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { CreateNetworkForm } from "./create-network-dialog";
import { DeleteNetworkActions } from "./delete-network-dialog";
import { NetworkRows } from "./docker-networks";

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
    { name: "proxy", kind: "outside", subnet: "172.19.0.0/16", members: [] },
  ],
  taken: [
    { range: "172.18.0.0/16", by: "kuma_default" },
    { range: "172.24.0.0/24", by: "apps-inner" },
    { range: "172.23.0.0/16", by: "default-env_public" },
    { range: "172.19.0.0/16", by: "proxy" },
  ],
  claimed: ["kuma_default"],
};

const io = { name: "io", bridges: report, stacks: [] };
const none = () => {};

const text = (html: string) =>
  html
    .replace(/<[^>]+>/gu, " ")
    .replace(/\s+/gu, " ")
    .replace(/ ,/gu, ",")
    .trim();

const button = (html: string, label: string) =>
  html
    .split("<button")
    .slice(1)
    .map((part) => part.slice(0, part.indexOf("</button>")))
    .find((part) => text(`<x${part}`).endsWith(label));

const form = (value: {
  name: string;
  kind: "contained" | "full";
  subnet: string;
}) =>
  renderToStaticMarkup(
    <CreateNetworkForm
      server={io}
      privateRange="10.88.0.0/24"
      value={value}
      onChange={none}
      pending={false}
      onCreate={none}
      onCancel={none}
    />,
  );

describe("Docker Networks on the server page", () => {
  it("shows a row per shared network with its kind, subnet and users", () => {
    const rows = renderToStaticMarkup(
      <NetworkRows server={io} onCopy={none} onDelete={none} />,
    )
      .split("<li")
      .slice(1)
      .map((row) => text(`<x${row}`));
    expect(rows).toHaveLength(3);
    expect(rows[0]).toContain("apps-inner Contained");
    expect(rows[0]).toContain("172.24.0.0/24");
    expect(rows[0]).toContain("adns, kuma, db guest");
    expect(rows[1]).toContain("default-env_public Full Access");
    expect(rows[1]).toContain("grafana, umami");
    expect(rows[2]).toContain("proxy Outside Krynodes");
    expect(rows[2]).toContain("Not used");
  });

  it("says when the server has not reported its networks", () => {
    const html = renderToStaticMarkup(
      <NetworkRows
        server={{ ...io, bridges: null }}
        onCopy={none}
        onDelete={none}
      />,
    );
    expect(text(html)).toBe("io has not reported its networks yet.");
  });
});

describe("Create Network", () => {
  it("keeps Create off while the subnet overlaps another network", () => {
    const html = form({
      name: "shared",
      kind: "full",
      subnet: "172.18.0.0/16",
    });
    expect(text(html)).toContain(
      "Overlaps kuma_default (172.18.0.0/16) on io.",
    );
    expect(button(html, "Create")).toContain('disabled=""');
  });

  it("turns Create on for a free name and subnet", () => {
    const html = form({
      name: "default-env_public2",
      kind: "full",
      subnet: "172.25.0.0/16",
    });
    expect(text(html)).toContain("✓ Free on io");
    expect(button(html, "Create")).not.toContain('disabled=""');
    expect(button(html, "Create")).toContain("<svg");
  });

  it("keeps Create off for a name the server already has", () => {
    const html = form({ name: "proxy", kind: "full", subnet: "" });
    expect(text(html)).toContain("io already has a network named proxy.");
    expect(button(html, "Create")).toContain('disabled=""');
  });

  it("explains a Contained network only when Contained is picked", () => {
    const contained = form({ name: "inner", kind: "contained", subnet: "" });
    expect(text(contained)).toContain("On a Contained Network");
    expect(text(contained)).toContain(
      "Krynodes picks 172.24.1.0/24, free on io.",
    );
    expect(
      text(form({ name: "inner", kind: "full", subnet: "" })),
    ).not.toContain("On a Contained Network");
  });
});

describe("Delete Network", () => {
  const actions = (index: number) =>
    renderToStaticMarkup(
      <DeleteNetworkActions
        network={{
          ...report.networks[index]!,
          ...(index === 0 ? { members: [] } : {}),
        }}
        pending={false}
        onDelete={none}
        onCancel={none}
      />,
    );

  it("keeps Delete off while a stack still uses the network", () => {
    expect(button(actions(1), "Delete")).toContain('disabled=""');
  });

  it("deletes an empty network with the Fingerprint", () => {
    const html = button(actions(0), "Delete");
    expect(html).not.toContain('disabled=""');
    expect(html).toContain("<svg");
  });
});
