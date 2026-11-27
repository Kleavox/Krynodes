import type { StackEntry } from "@krynodes/protocol";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { linesValid } from "@/features/stacks/logs-dialog";
import { PortChoices } from "@/features/stacks/new-stack-dialog";
import {
  installDocker,
  removedItems,
  serviceItems,
  stackItems,
} from "@/features/stacks/stack-menu";
import { queryKeys } from "@/lib/query-client";
import { network, S1 } from "@/lib/rules-test-utils";
import type { StackNode } from "@/types";

import { StacksPage } from "./stacks";

const stack = (patch: Partial<StackEntry> = {}): StackEntry => ({
  project: "web",
  title: "Web",
  directory: "/var/lib/krynodes/compose/web",
  own: true,
  access: "contained",
  running: 2,
  total: 3,
  rollback: false,
  network: [],
  services: [{ service: "app", container: "web-app-1" }],
  ...patch,
});

const entry = (patch: Partial<StackNode> = {}): StackNode => ({
  nodeId: S1,
  name: "server-1",
  online: true,
  docker: "ready",
  compose: "2.29.1",
  stacks: [stack()],
  containers: [
    {
      name: "web-app-1",
      project: "web",
      service: "app",
      image: "nginx:1.27",
      state: "running",
      health: null,
      ports: [],
    },
    {
      name: "proxy-1",
      project: null,
      service: null,
      image: "caddy:2",
      state: "stopped",
      health: null,
      ports: [],
    },
  ],
  units: [{ name: "cron.service", state: "running", protected: false }],
  removed: [{ project: "old", removedAt: "2026-11-20T03:00:00.000Z" }],
  updatedAt: "2026-11-22T10:00:00.000Z",
  ...patch,
});

const wrap = (children: ReactNode, nodes?: StackNode[]) => {
  const client = new QueryClient();
  if (nodes) client.setQueryData(queryKeys.stacks, { nodes });
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>,
  );
};

const text = (html: string) => html.replace(/<[^>]+>/gu, " ");

const labels = (items: { label: string }[]) => items.map((one) => one.label);

describe("the stacks page", () => {
  it("shows each server's stacks, removed stacks and services", () => {
    const shown = text(wrap(<StacksPage />, [entry()]));
    for (const line of [
      "server-1",
      "Web",
      "2 of 3 running",
      "Removed",
      "old",
      "Services",
      "proxy-1",
      "cron.service",
      "New Stack",
    ]) {
      expect(shown).toContain(line);
    }
  });

  it("offers Install Docker where Docker is missing", () => {
    const shown = text(
      wrap(<StacksPage />, [
        entry({ docker: "missing", stacks: [], containers: [], removed: [] }),
      ]),
    );
    expect(shown).toContain("Docker is not installed.");
    expect(shown).toContain("Install Docker");
  });

  it("names the Install Docker dialog once", () => {
    const ask = installDocker(entry({ docker: "missing" })).ask!;
    expect(ask.heading).toBe("Install Docker");
    expect(ask.title).toBe("Install Docker");
    expect(ask.body).toBe(
      "server-1 installs Docker and Docker Compose from Docker's own packages.",
    );
  });

  it("greys an offline server", () => {
    const html = wrap(<StacksPage />, [entry({ online: false })]);
    expect(html).toMatch(
      /<section aria-label="server-1" class="[^"]*opacity-60/u,
    );
    expect(text(html)).toContain("Offline");
  });

  it("an offline server's stacks and services read -- instead of their last counts", () => {
    const shown = text(wrap(<StacksPage />, [entry({ online: false })]));
    expect(shown).not.toContain("2 of 3 running");
    expect(shown).not.toContain("Running");
    expect(shown).not.toContain("Stopped");
    expect(shown).toContain("Container · --");
    expect(shown).toContain("Unit · --");
  });

  it("Show Logs waits for a line count from 1 to 500", () => {
    expect(["1", "200", "500"].map(linesValid)).toEqual([true, true, true]);
    expect(
      ["", "0", "501", "05", "5.5", "abc"].some((one) => linesValid(one)),
    ).toBe(false);
  });

  it("rollback is offered only when the stack has one", () => {
    expect(labels(stackItems(entry(), stack()))).toEqual([
      "Deploy",
      "Edit Compose",
      "Start",
      "Stop",
      "Restart",
      "Logs",
      "Add Check",
      "Remove",
    ]);
    const items = stackItems(entry(), stack({ rollback: true }));
    expect(labels(items)).toContain("Rollback");
    expect(items.find((one) => one.label === "Rollback")!.ask).toMatchObject({
      kind: "stack",
      action: "rollback",
      name: "web",
      destructive: true,
    });
  });

  it("every destructive verb asks in an alert dialog first", () => {
    const destructive = [
      ...stackItems(entry(), stack({ rollback: true })),
      ...removedItems(entry(), "old"),
      ...serviceItems(entry(), {
        kind: "container",
        item: entry().containers[1]!,
      }),
    ].filter((one) => one.destructive);
    expect(labels(destructive)).toEqual([
      "Rollback",
      "Stop",
      "Remove",
      "Delete Permanently",
      "Stop",
    ]);
    for (const one of destructive) {
      expect(one.ask?.destructive).toBe(true);
      expect(one.ask?.heading).toMatch(/\?$/u);
    }
  });

  it("Delete Permanently says it deletes the folder, the volumes and the checks", () => {
    const purge = removedItems(entry(), "old").find(
      (one) => one.label === "Delete Permanently",
    );
    expect(purge?.ask).toMatchObject({
      action: "purge",
      body: "old, its folder, its volumes and its checks are deleted from server-1. This cannot be undone.",
    });
  });

  it("Remove says what Delete Permanently will later delete", () => {
    const remove = stackItems(entry(), stack()).find(
      (one) => one.label === "Remove",
    );
    expect(remove?.ask?.body).toBe(
      "web stops and waits in Removed for 7 days. Restore brings it back; Delete Permanently deletes it, its folder, its volumes and its checks.",
    );
  });

  it("an offline server's menu refuses at once", () => {
    const away = entry({ online: false });
    const refusal = [{ label: "server-1 is offline." }];
    expect(stackItems(away, stack())).toEqual(refusal);
    expect(removedItems(away, "old")).toEqual(refusal);
    expect(serviceItems(away, { kind: "unit", item: away.units[0]! })).toEqual(
      refusal,
    );
  });

  it("a stack Krynodes does not manage offers Adopt", () => {
    expect(labels(stackItems(entry(), stack({ own: false })))).toEqual([
      "Adopt",
      "Add Check",
    ]);
  });

  it("a protected unit offers nothing to run", () => {
    expect(
      serviceItems(entry(), {
        kind: "unit",
        item: { name: "ssh.service", state: "running", protected: true },
      }),
    ).toEqual([{ label: "ssh.service is protected." }]);
  });

  it("a private network port without a rule shows the Connections line", () => {
    const choices = (allow: Parameters<typeof network>[0]) =>
      text(
        wrap(
          <PortChoices
            ports={[8080, 9000]}
            network={[8080]}
            nodeId={S1}
            document={network(allow)}
            onChange={() => {}}
          />,
        ),
      );
    const line =
      "Nothing reaches this port until a rule in Connections allows it.";
    expect(choices([])).toContain(line);
    expect(choices([])).toContain("Open Connections");
    expect(
      choices([
        { from: { group: "laptops" }, to: { node: S1 }, ports: ["8080/tcp"] },
      ]),
    ).not.toContain(line);
  });
});
