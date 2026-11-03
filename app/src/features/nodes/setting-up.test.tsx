import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { NodeRecord } from "@/types";

import { SettingUpCard } from "./setting-up";

const node = {
  id: "node-1",
  name: "server-1",
  last_seen_at: null,
  enrolled_at: "2026-11-03 02:00:00",
  disabled_at: null,
} as NodeRecord;

describe("a server that is setting up", () => {
  it("shows the shape of a server card loading, with no data, nothing to open and a menu to delete it", () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <SettingUpCard node={node} />
      </QueryClientProvider>,
    );
    expect(html).toContain("server-1");
    expect(html).toContain("Setting Up");
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain('role="status"');
    expect(html).toContain("Opens when setup is done");
    expect(
      html.match(/data-slot="skeleton"/g)?.length ?? 0,
    ).toBeGreaterThanOrEqual(5);
    expect(html.match(/<button/g)?.length).toBe(1);
    expect(html).toContain('aria-label="Actions for server-1"');
    expect(html).not.toContain("<a ");
    expect(html).not.toMatch(/\d%/);
  });
});
