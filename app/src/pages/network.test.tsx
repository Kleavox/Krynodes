import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { queryKeys } from "@/lib/query-client";
import { OPEN_CONNECTIONS_LINE } from "@/lib/rules";
import { document as rules } from "@/lib/rules-test-utils";
import type { JoinRequest, NetworkView } from "@/types";

import { NetworkPage } from "./network";

const S1 = "11111111-1111-4111-8111-111111111111";
const AT = "2026-11-22T00:00:00.000Z";

const request: JoinRequest = {
  node: S1,
  name: "server-1",
  kind: "server",
  hostname: null,
  os: null,
  key: null,
  signer: null,
  sealKey: null,
  ready: true,
  reason: null,
  since: AT,
};

const empty: NetworkView = {
  network: null,
  members: [],
  requests: [],
  rejected: [],
  allow: [],
  links: [],
};

const live: NetworkView = {
  ...empty,
  network: {
    range: "10.88.37.0/24",
    port: 51820,
    mtu: 1420,
    version: 3,
    dns: null,
    deleted: false,
  },
  members: [
    {
      node: S1,
      name: "server-1",
      kind: "server",
      state: "in",
      address: "10.88.37.14",
      key: null,
      signer: null,
      port: 51820,
      mtu: null,
      endpoint: null,
      nat: true,
      applied: 2,
      failure: null,
      announced: null,
      since: AT,
      joinedAt: AT,
    },
  ],
};

const page = (view: NetworkView, current?: Error, trusted = false) => {
  const client = new QueryClient();
  client.setQueryData(queryKeys.network, view);
  client.setQueryData(queryKeys.fleet, []);
  if (trusted) {
    client.setQueryData([...queryKeys.network, "current"], {
      document: rules(),
      hash: "q".repeat(43),
    });
  }
  if (current) {
    client.setQueryDefaults([...queryKeys.network, "current"], {
      retryOnMount: false,
    });
    client
      .getQueryCache()
      .build(client, { queryKey: [...queryKeys.network, "current"] })
      .setState({ status: "error", error: current });
  }
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <NetworkPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe("the network page", () => {
  it("offers Create Network when none exists and a server asked to join", () => {
    const html = page({ ...empty, requests: [request] });
    expect(html).toContain("Join Requests");
    expect(html).toContain("No private network yet");
    expect(html).toMatch(/<button(?![^>]*disabled="")[^>]*>Create Network/u);
    expect(html).not.toContain("Delete Network");
    expect(page(empty)).toMatch(/<button[^>]*disabled=""[^>]*>Create Network/u);
  });

  it("shows the members, laptops, the connections line and Delete Network", () => {
    const html = page(live, undefined, true);
    expect(html).not.toContain("Join Requests");
    expect(html).toContain("10.88.37.0/24 · Version 3");
    expect(html).toContain("Members");
    expect(html).toContain("Applying…");
    expect(html).toContain("Add Laptop");
    expect(html).toContain("Laptop DNS");
    expect(html).toContain("Connections");
    expect(html).toContain(OPEN_CONNECTIONS_LINE);
    expect(html).toContain("Delete Network");
  });

  it("lists the rules of the network under Connections, once the document has loaded", () => {
    const html = page(live, undefined, true);
    expect(html).toContain(
      "All Laptops can connect to All Servers on all ports.",
    );
    expect(html).toContain("Add Rule");
    const loading = page(live);
    expect(loading).not.toContain("Add Rule");
    expect(loading).not.toContain("Connections");
  });

  it("a network document that cannot be trusted is said on the page", () => {
    const html = page(
      live,
      new Error(
        "The network document does not match its hash. Nothing was changed.",
      ),
    );
    expect(html).toMatch(
      /role="alert"[^>]*>The network document does not match its hash\. Nothing was changed\./u,
    );
    expect(page(live)).not.toContain("does not match its hash");
  });
});
