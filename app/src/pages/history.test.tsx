import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { queryKeys } from "@/lib/query-client";
import type { ActionRow, FleetNode } from "@/types";

import { HistoryPage } from "./history";

const action = (id: string, patch: Partial<ActionRow> = {}): ActionRow => ({
  id,
  nodeId: "node-1",
  kind: "host",
  name: "server-1",
  action: "restart",
  title: "Restart Server",
  status: "done",
  message: "Restarting now.",
  output: null,
  createdAt: "2026-11-22T03:00:00.000Z",
  finishedAt: null,
  ...patch,
});

const nodes = [{ id: "node-1", name: "server-1" }] as FleetNode[];

const page = (rows?: ActionRow[]) => {
  const client = new QueryClient();
  client.setQueryData(queryKeys.fleet, nodes);
  if (rows) client.setQueryData(queryKeys.actions, rows);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    </QueryClientProvider>,
  ).replace(/<[^>]+>/gu, " ");
};

describe("the history page", () => {
  it("history shows No answer for an old sent action", () => {
    const shown = page([
      action("a1", {
        status: "failed",
        message: "No answer from server-1.",
      }),
    ]);
    expect(shown).toContain("server-1");
    expect(shown).toContain("Restart Server");
    expect(shown).toContain("Failed");
    expect(shown).toContain("No answer from server-1.");
  });

  it("lists actions in the order the Worker gives, newest first, with their time", () => {
    const shown = page([
      action("a2", {
        title: "Update Agent to 0.8.1",
        createdAt: "2026-11-22T04:00:00.000Z",
      }),
      action("a1", { status: "sent", message: null }),
    ]);
    expect(shown).toMatch(/Update Agent to 0\.8\.1.*Restart Server/su);
    expect(shown).toContain("11:00");
    expect(shown).toContain("Sent");
    expect(shown).toContain("--");
  });

  it("names a server it no longer knows --", () => {
    expect(page([action("a1", { nodeId: "gone" })])).toMatch(
      /--\s+Restart Server/u,
    );
  });

  it("says when only the newest 50 are shown", () => {
    const fifty = Array.from({ length: 50 }, (_, index) => action(`a${index}`));
    expect(page(fifty)).toContain("Showing the newest 50 actions.");
    expect(page([action("a1")])).not.toContain("newest 50");
  });

  it("says so when nothing was done yet", () => {
    expect(page([])).toContain("No actions yet");
  });
});
