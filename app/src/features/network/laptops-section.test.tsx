import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { NetworkLaptop, NetworkView } from "@/types";

import { CodeSheet } from "./add-laptop-dialog";
import { LaptopsSection } from "./laptops-section";

const NOW = Date.parse("2026-11-16T10:00:00Z");

const laptop = (
  nodeId: string,
  name: string,
  extra: Partial<NetworkLaptop> = {},
): NetworkLaptop => ({
  nodeId,
  name,
  address: null,
  state: "waiting",
  version: "0.7.24",
  lastSeen: "2026-11-16T09:59:40Z",
  sealKey: null,
  trust: null,
  applied: 2,
  ...extra,
});

const view = (laptops: NetworkLaptop[]) =>
  ({ laptops, version: 2 }) as NetworkView;

const section = (laptops: NetworkLaptop[], blocker: string | null = null) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <LaptopsSection
        view={view(laptops)}
        now={NOW}
        blocker={blocker}
        onApprove={() => undefined}
        onDismiss={() => undefined}
        onRename={() => undefined}
        onRemove={() => undefined}
      />
    </QueryClientProvider>,
  );

const text = (html: string) => html.replace(/<[^>]+>/gu, " ");

const approve = (html: string) =>
  /<button[^>]*>Approve<\/button>/u.exec(html)?.[0] ?? "";

const members = [
  laptop("n1", "laptop-1", { state: "in", address: "10.88.0.9" }),
  laptop("n2", "laptop-2"),
];

describe("the Laptops section of the Network page", () => {
  it("shows nothing without a laptop", () => {
    expect(section([])).toBe("");
    expect(section([laptop("n3", "laptop-3", { state: "leaving" })])).toBe("");
  });

  it("lists a laptop in the network with its address and a menu, and a waiting one with Approve and a menu", () => {
    const html = section(members);
    expect(text(html)).toContain("Laptops");
    expect(text(html)).toContain("laptop-1");
    expect(text(html)).toContain("10.88.0.9");
    expect(text(html)).toContain("Online");
    expect(html).toContain('aria-label="More for laptop-1"');
    expect(text(html)).toContain("laptop-2 wants to join");
    expect(approve(html)).not.toBe("");
    expect(approve(html)).not.toContain('disabled=""');
    expect(html).toContain('aria-label="More for laptop-2"');
  });

  it("disables Approve and names the server to update first", () => {
    const html = section(members, "Update server-1 to agent 0.7.24 first.");
    expect(approve(html)).toContain('disabled=""');
    expect(text(html)).toContain("Update server-1 to agent 0.7.24 first.");
  });

  it("says a laptop that missed a change is behind, and an unknown version as --", () => {
    expect(text(section(members))).not.toContain("Behind");
    expect(text(section(members))).not.toContain("Version");
    const behind = section([
      laptop("n1", "laptop-1", { state: "in", applied: 1 }),
    ]);
    expect(text(behind)).toContain("Behind · Version 1");
    const unknown = text(
      section([laptop("n1", "laptop-1", { state: "in", applied: null })]),
    );
    expect(unknown).toContain("Version --");
    expect(unknown).not.toContain("Version 0");
  });

  it("says a laptop that has not reported is not seen yet, never a time of zero", () => {
    const html = section([laptop("n2", "laptop-2", { lastSeen: null })]);
    expect(text(html)).toContain("Not seen yet");
    expect(text(html)).not.toContain("Offline 0");
  });
});

const DASHBOARD = "https://kry.example.test";

const sheet = (expiresAt: string, endpoint = DASHBOARD) =>
  renderToStaticMarkup(
    <CodeSheet
      code="code-1234"
      expiresAt={expiresAt}
      origin={DASHBOARD}
      endpoint={endpoint}
      now={NOW}
    />,
  );

const plain = (html: string) =>
  text(html).replaceAll("&quot;", '"').replaceAll("&amp;", "&");

describe("Add Laptop", () => {
  it("shows the full install command, when it expires and where to get the agent", () => {
    const html = sheet("2026-11-16T10:10:00Z");
    expect(plain(html)).toContain(
      "On the laptop, download Krynodes for Windows to Downloads. Then run this in PowerShell as Administrator.",
    );
    expect(plain(html)).toContain(
      '& "$HOME\\Downloads\\krynodes-windows-amd64.exe" install --code code-1234 --origin https://kry.example.test | Out-Host',
    );
    expect(html).toContain(
      'href="https://github.com/Kleavox/Krynodes/releases/latest/download/krynodes-windows-amd64.exe"',
    );
    expect(text(html)).toContain("Delete any older copy in Downloads first.");
    expect(text(html)).toContain("Expires in 10:00");
    expect(text(html)).toContain("Copy Command");
  });

  it("names the agent origin when it is not the dashboard's", () => {
    expect(
      plain(sheet("2026-11-16T10:10:00Z", "https://agent.example.test")),
    ).toContain(
      "install --code code-1234 --origin https://kry.example.test --endpoint https://agent.example.test | Out-Host",
    );
  });

  it("says a code that ran out is gone", () => {
    const html = sheet("2026-11-16T09:59:00Z");
    expect(text(html)).toContain("Expired.");
    expect(text(html)).not.toContain("Expires in");
  });
});
