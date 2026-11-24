import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { queryKeys } from "@/lib/query-client";
import type { FleetNode } from "@/types";

import { FleetPage } from "./fleet";

const server = (name: string, online: boolean): FleetNode => ({
  id: `id-${name}`,
  name,
  hostname: `${name}.example.test`,
  os: "Debian 13",
  arch: "arm64",
  version: "0.8.0",
  online,
  lastSeenAt: null,
  trust: null,
  update: null,
  kind: "server",
  address: null,
  via: null,
  ms: null,
  request: null,
});

const page = (nodes?: FleetNode[]) => {
  const client = new QueryClient();
  if (nodes) client.setQueryData(queryKeys.fleet, nodes);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <FleetPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe("the fleet page", () => {
  it("lists every server the Worker knows, with a way to enroll another", () => {
    const html = page([server("server-1", true), server("server-2", false)]);
    expect(html).toContain('id="server-id-server-1"');
    expect(html).toContain('id="server-id-server-2"');
    expect(html).toContain("Enroll Server");
  });

  it("says so when there are no servers", () => {
    expect(page([])).toContain("No servers yet");
  });

  it("shows it is loading before the first answer", () => {
    expect(page()).toContain('aria-label="Loading servers"');
  });
});
