import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { queryKeys } from "@/lib/query-client";
import type { ActionRow, FleetNode, NetworkChange } from "@/types";

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

const page = (rows?: ActionRow[], changes: NetworkChange[] | Error = []) => {
  const client = new QueryClient();
  client.setQueryData(queryKeys.fleet, nodes);
  const key = [...queryKeys.network, "changes"];
  if (changes instanceof Error) {
    client.setQueryDefaults(key, { retryOnMount: false });
    client
      .getQueryCache()
      .build(client, { queryKey: key })
      .setState({ status: "error", error: changes });
  } else {
    client.setQueryData(key, changes);
  }
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
    expect(page(fifty)).toContain(
      "Showing the newest 50 actions and the newest 50 network changes.",
    );
    const changes = Array.from({ length: 50 }, (_, index) => ({
      id: `c${index}`,
      at: "2026-11-22T01:00:00.000Z",
      change: "Add server-2 to the private network",
      detail: null,
      nodes: [],
    }));
    expect(page([action("a1")], changes)).toContain(
      "Showing the newest 50 actions and the newest 50 network changes.",
    );
    expect(page([action("a1")])).not.toContain("newest 50");
  });

  it("says so when nothing was done yet", () => {
    expect(page([])).toContain("No actions yet");
  });

  it("merges network changes with the actions by time", () => {
    const shown = page(
      [action("a1", { createdAt: "2026-11-22T03:00:00.000Z" })],
      [
        {
          id: "c2",
          at: "2026-11-22T05:00:00.000Z",
          change: "Add server-2 to the private network",
          detail: null,
          nodes: ["node-2"],
        },
        {
          id: "c1",
          at: "2026-11-22T02:00:00.000Z",
          change: "Create the private network with server-1",
          detail: null,
          nodes: ["node-1"],
        },
      ],
    );
    expect(shown).toMatch(
      /Add server-2 to the private network.*Restart Server.*Create the private network with server-1/su,
    );
    expect(shown).toContain("Network");
    expect(page([], [])).toContain("No actions yet");
  });

  it("says so when the network changes cannot load", () => {
    const shown = page([action("a1")], new Error("The hub did not answer."));
    expect(shown.replaceAll("&#x27;", "'")).toContain(
      "Network changes can't load: The hub did not answer.",
    );
    expect(shown).toContain("Restart Server");
  });
});
