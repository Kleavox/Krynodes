import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { queryKeys } from "@/lib/query-client";
import type { CheckView } from "@/types";

import { ChecksPage } from "./checks";

const check = (patch: Partial<CheckView>): CheckView => ({
  id: "check-1",
  nodeId: "node-1",
  nodeName: "server-1",
  online: true,
  container: "web-app-1",
  name: "Web",
  public: false,
  note: null,
  state: "up",
  lastState: "up",
  cause: null,
  since: null,
  createdAt: "2026-11-22T10:00:00.000Z",
  ...patch,
});

const page = (checks?: CheckView[], statusPage: string | null = null) => {
  const client = new QueryClient();
  if (checks) client.setQueryData(queryKeys.checks, { checks, statusPage });
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <ChecksPage />
    </QueryClientProvider>,
  ).replace(/<[^>]+>/gu, " ");
};

describe("the checks page", () => {
  it("a stopped-by-owner check reads Paused", () => {
    const shown = page([check({ state: "down", cause: "owner" })]);
    expect(shown).toContain("Paused");
    expect(shown).not.toContain("Down");
  });

  it("a check of a removed container reads --", () => {
    const shown = page([check({ state: "gone", lastState: "gone" })]);
    expect(shown).toContain("--");
    expect(shown).not.toContain(" Up ");
  });

  it("an offline server's check is never shown as up", () => {
    const shown = page([
      check({ online: false, state: "unknown", lastState: "up" }),
    ]);
    expect(shown).toContain("--");
    expect(shown).toContain("server-1 is offline");
    expect(shown).not.toContain(" Up ");
  });

  it("lists name, server, container and links the status page", () => {
    const shown = page(
      [check({ public: true, note: "Main site" })],
      "https://stats.example.test",
    );
    for (const line of [
      "Web",
      "server-1",
      "web-app-1",
      "Up",
      "Public",
      "Main site",
      "Status Page",
    ]) {
      expect(shown).toContain(line);
    }
  });

  it("links the status page only when the Worker names one", () => {
    const client = new QueryClient();
    client.setQueryData(queryKeys.checks, {
      checks: [check({})],
      statusPage: "https://stats.example.test",
    });
    expect(
      renderToStaticMarkup(
        <QueryClientProvider client={client}>
          <ChecksPage />
        </QueryClientProvider>,
      ),
    ).toContain('href="https://stats.example.test"');
    expect(page([check({})], null)).not.toContain("Status Page");
  });

  it("says so when there are no checks", () => {
    expect(page([])).toContain("No checks yet");
  });
});
