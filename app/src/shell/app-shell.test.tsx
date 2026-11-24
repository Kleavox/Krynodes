import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { queryKeys } from "@/lib/query-client";
import type { FleetNode } from "@/types";

import { AppShell } from "./app-shell";

const shell = (requests: FleetNode["request"][]) => {
  const client = new QueryClient();
  client.setQueryData(
    queryKeys.fleet,
    requests.map((request, index) => ({ id: `n${index}`, request })),
  );
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AppShell
          identity={{ id: "u1", email: "owner@example.test", username: null }}
          via="standalone"
        />
      </MemoryRouter>
    </QueryClientProvider>,
  ).replace(/<[^>]+>/gu, " ");
};

describe("the menu's Network item", () => {
  it("counts the machines in Fleet that asked to join", () => {
    expect(shell(["requested", "rejected", null, "requested"])).toContain(
      "Network 2",
    );
    expect(shell(["rejected", null])).not.toMatch(/Network \d/u);
  });
});
