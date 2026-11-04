import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Dialog } from "@/components/ui/dialog";
import type { NetworkView, NodeRecord } from "@/types";

import { Picker } from "./create-dialog";

const NOW = Date.parse("2026-11-04T10:00:00Z");

const node = (id: string, name: string) =>
  ({
    id,
    name,
    agent_version: "0.7.15",
    enrolled_at: "2026-11-01T00:00:00Z",
    disabled_at: null,
    last_seen_at: "2026-11-04T09:59:50Z",
  }) as NodeRecord;

const view = {
  network: {
    range: "10.88.1.0/24",
    port: 51820,
    mtu: 1420,
    version: 1,
    createdAt: "2026-11-01T00:00:00Z",
    createdBy: "a",
  },
  version: 1,
  document: null,
  body: null,
  quarantined: [],
  wrongPorts: [],
  members: [],
  waiting: [],
  links: [],
  live: {},
  held: [],
  changes: [],
} as NetworkView;

const picker = (preset?: string) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <Dialog open>
        <Picker
          kind="add"
          nodes={[node("n1", "server-1"), node("n2", "server-2")]}
          services={undefined}
          view={view}
          ranges={[]}
          release="0.7.15"
          preset={preset}
          now={NOW}
        />
      </Dialog>
    </QueryClientProvider>,
  );

const text = (html: string) => html.replace(/<[^>]+>/gu, " ");

describe("joining the private network", () => {
  it("lists only the server whose Join was pressed, without a checkbox", () => {
    const html = picker("n1");
    expect(text(html)).toContain("server-1");
    expect(text(html)).not.toContain("server-2");
    expect(html).not.toContain('type="checkbox"');
    expect(text(html)).toContain(
      "server-1 joins. The others learn its key in the same step.",
    );
  });

  it("lets Add Server pick among every server that is not in yet", () => {
    const html = picker();
    expect(text(html)).toContain("server-1");
    expect(text(html)).toContain("server-2");
    expect(html.match(/type="checkbox"/gu)).toHaveLength(2);
  });
});
