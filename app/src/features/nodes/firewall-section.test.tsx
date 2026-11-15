import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { recipeChoices } from "@/lib/security";
import type {
  FirewallOpening,
  NodeRecord,
  SecurityReport,
  StackEntry,
} from "@/types";

import { FROM, FirewallSection } from "./firewall-section";

const node = { id: "n1", name: "server-1" } as NodeRecord;

const report = (open: FirewallOpening[]): SecurityReport => ({
  checkedAt: "2026-11-14T10:00:00.000Z",
  findings: [],
  recipes: ["firewall"],
  lockdown: false,
  rebootHour: null,
  firewall: { closed: true, open, other: [] },
});

const stacks: Pick<StackEntry, "project" | "access" | "public">[] = [];

const section = (open: FirewallOpening[]) => {
  const security = report(open);
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <FirewallSection
        node={node}
        report={security}
        stacks={stacks}
        choice={recipeChoices(security).find(
          (choice) => choice.id === "firewall",
        )!}
        onTurnOn={() => {}}
      />
    </QueryClientProvider>,
  );
};

const text = (html: string) =>
  html
    .replace(/<[^>]+>/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();

const openPort = (html: string) =>
  html
    .split("<button")
    .find((part) => part.includes("Open Port"))!
    .split(">")[0]!;

describe("the firewall of a server still on agent 0.7.22 or older", () => {
  const html = section([
    { port: 22, protocol: "tcp", from: "tailscale" },
    { port: 443, protocol: "tcp", from: "everyone" },
  ]);

  it("shows an opening from Tailscale as set up outside Krynodes, with no menu", () => {
    expect(text(html)).toContain(
      "22/tcp · From Tailscale · Set up outside Krynodes",
    );
    expect(html).not.toContain('aria-label="22/tcp actions"');
  });

  it("sends nothing: Open Port is off and no row edits its opening", () => {
    expect(openPort(html)).toContain('disabled=""');
    expect(html).not.toContain('aria-label="443/tcp actions"');
    expect(text(html)).toContain("Update this server to agent 0.7.23 first");
  });
});

describe("the firewall of a server with no opening from Tailscale", () => {
  const html = section([{ port: 443, protocol: "tcp", from: "everyone" }]);

  it("keeps Open Port and each row's menu", () => {
    expect(openPort(html)).not.toContain('disabled=""');
    expect(html).toContain('aria-label="443/tcp actions"');
    expect(text(html)).not.toContain("Update this server");
  });
});

describe("Open Port", () => {
  it("offers Everyone and Addresses only", () => {
    expect(FROM).toEqual([
      { value: "everyone", label: "Everyone" },
      { value: "addresses", label: "Addresses" },
    ]);
  });
});
