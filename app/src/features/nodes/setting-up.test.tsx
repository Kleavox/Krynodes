import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { SetupView } from "@/lib/setup";
import type { NodeRecord } from "@/types";

import { SettingUpCard } from "./setting-up";

const node = {
  id: "node-1",
  name: "server-1",
  last_seen_at: null,
  enrolled_at: "2026-11-03 02:00:00",
  disabled_at: null,
} as NodeRecord;

const card = (view: SetupView) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <SettingUpCard node={node} view={view} />
    </QueryClientProvider>,
  );

const running = (step: string | null): SetupView => ({
  label: "Setting Up",
  stopped: false,
  failed: false,
  step,
});

const failed = (step: string | null): SetupView => ({
  label: "Setup Failed",
  stopped: false,
  failed: true,
  step,
});

describe("a server that is setting up", () => {
  it("shows the shape of a server card loading, with no data, nothing to open and a menu to delete it", () => {
    const html = card(running(null));
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

  it("names the step it is in, with no step count", () => {
    const html = card(running("Installing Docker"));
    expect(html).toContain("Installing Docker");
    expect(html).not.toMatch(/\d of \d/i);
  });
});

describe("a server whose setup failed", () => {
  const text = (html: string) =>
    html
      .replace(/<[^>]+>/gu, " ")
      .replace(/\s+/gu, " ")
      .trim();

  it("says so, says where it went silent, stops loading and keeps the menu to delete it", () => {
    const html = card(failed("Installing Docker"));
    expect(text(html)).toContain("Setup Failed");
    expect(text(html)).toContain("Went silent at Installing Docker");
    expect(text(html)).toContain("Delete it and enroll the server again");
    expect(html).not.toContain("aria-busy");
    expect(html).not.toContain('role="status"');
    expect(html).not.toContain("animate-pulse");
    expect(html).toContain('aria-label="Actions for server-1"');
  });

  it("says a server that restarted at the end did not come back", () => {
    expect(text(card(failed("Restarting")))).toContain(
      "Did not come back after its restart",
    );
  });

  it("says a server that never said a step never connected", () => {
    expect(text(card(failed(null)))).toContain("Never connected");
  });
});
