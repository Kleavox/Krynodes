import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { queryKeys } from "@/lib/query-client";
import type { Device, FleetNode } from "@/types";

import { PasskeysPage, trustedBy } from "./passkeys";

const device = (id: string, name: string, synced: boolean): Device => ({
  id,
  name,
  alg: -7,
  publicKey: `key-${id}`,
  synced,
  createdAt: "2026-11-22T10:00:00.000Z",
  trusted: false,
});

const server = (name: string, core: string[] | null) =>
  ({
    id: `id-${name}`,
    name,
    trust: core && { version: 1, core, access: core },
  }) as FleetNode;

const page = (devices?: Device[], nodes?: FleetNode[]) => {
  const client = new QueryClient();
  if (devices) client.setQueryData(queryKeys.devices, devices);
  if (nodes) client.setQueryData(queryKeys.fleet, nodes);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <PasskeysPage />
      </MemoryRouter>
    </QueryClientProvider>,
  ).replace(/<[^>]+>/gu, " ");
};

describe("the passkeys page", () => {
  it("lists each passkey with where it lives and the servers that trust it", () => {
    const shown = page(
      [device("laptop", "Laptop", false), device("phone", "Phone", true)],
      [server("server-1", ["laptop", "phone"]), server("server-2", ["laptop"])],
    );
    expect(shown).toMatch(/Laptop.*This Device Only.*server-1, server-2/su);
    expect(shown).toMatch(/Phone.*Synced.*server-1/su);
    expect(shown).toContain("Add Passkey");
  });

  it("says no server trusts a passkey, or -- before the fleet loads", () => {
    const laptop = device("laptop", "Laptop", false);
    expect(trustedBy(laptop, [server("server-1", null)])).toBe("No Servers");
    expect(trustedBy(laptop, undefined)).toBe("--");
  });

  it("asks for a first passkey when there is none", () => {
    expect(page([], [])).toContain("No passkeys yet");
  });
});
