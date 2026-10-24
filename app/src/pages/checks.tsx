import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckDialog } from "@/features/checks/check-dialog";
import { CheckRow, useCheckView } from "@/features/checks/check-row";
import { DownBox, type DownItem } from "@/features/checks/down-box";
import { useHistoryAttention, useIncidentBoard, useOverview } from "@/lib/api";
import {
  autoRestartLine,
  checksByServer,
  serverChecksText,
} from "@/lib/checks";
import type { CheckRecord } from "@/types";

type Filter = "all" | "down" | "up";

function readFilter(value: string | null): Filter {
  return value === "down" || value === "up" ? value : "all";
}

export function ChecksPage() {
  const overview = useOverview();
  const attention = useHistoryAttention();
  const board = useIncidentBoard();
  const view = useCheckView();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const filter = readFilter(params.get("status"));

  const setParam = (key: string, value: string | null) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (value === null) next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: true },
    );

  const nodes = overview.data?.nodes ?? [];
  const dialog = (
    <CheckDialog
      open={params.get("add") === "1"}
      onOpenChange={(open) => setParam("add", open ? "1" : null)}
      nodes={nodes}
    />
  );

  if (!overview.data) {
    return (
      <>
        <PageHeader title="Checks" />
        <Skeleton className="h-64" />
        {dialog}
      </>
    );
  }

  const { checks } = overview.data;
  const { display } = view;
  const groups = checksByServer(checks, nodes, overview.dataUpdatedAt);
  const down = checks.filter(
    (check) => check.enabled && display(check) === "DOWN",
  );
  const up = checks.filter((check) => display(check) === "UP");
  const downItems: DownItem[] = groups.flatMap((group) =>
    group.checks
      .filter(
        (check) =>
          check.enabled && display(check) === "DOWN" && !view.planned(check),
      )
      .map((check) => {
        const incident = view.openIncident(check);
        return {
          check,
          node: group.node,
          figure: view.figure(check),
          incident,
          updates: incident
            ? (board.data?.latest[incident.id]?.updates ?? 0)
            : 0,
          autoLine: autoRestartLine(
            check,
            attention.data?.items ?? [],
            view.now,
          ),
          strip: view.strip(check),
          restart: view.restartFor(check),
          logs: view.logsFor(check),
        };
      }),
  );
  const needle = query.trim().toLowerCase();
  const shown = (check: CheckRecord, serverName: string) =>
    (filter === "all" ||
      (filter === "down"
        ? check.enabled && display(check) === "DOWN"
        : display(check) === "UP")) &&
    (!needle ||
      [check.name, check.target, serverName].some((text) =>
        text.toLowerCase().includes(needle),
      ));
  const visible = groups
    .map((group) => ({
      ...group,
      total: group.checks.length,
      checks: group.checks.filter((check) => shown(check, group.node.name)),
    }))
    .filter((group) => group.checks.length > 0);

  return (
    <>
      <PageHeader
        title="Checks"
        actions={
          <Button
            onClick={() => setParam("add", "1")}
            disabled={nodes.length === 0}
          >
            Add check
          </Button>
        }
      />

      {nodes.length === 0 ? (
        <EmptyState
          title="No servers yet"
          body="Enroll a server before adding checks. Checks run on the server's agent."
          action={
            <Button asChild>
              <Link to="/?enroll=1">Enroll server</Link>
            </Button>
          }
        />
      ) : checks.length === 0 ? (
        <EmptyState
          title="No checks configured"
          body="Add an HTTP, TCP, container or systemd check to one of your servers."
        />
      ) : (
        <div className="space-y-4">
          <DownBox items={downItems} nodes={nodes} />
          <div className="flex flex-wrap items-center gap-2">
            <Input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search checks"
              aria-label="Search checks"
              className="h-9 w-full sm:w-56 md:h-8"
            />
            <FilterChips
              label="Filter checks"
              value={filter}
              onChange={(value) =>
                setParam("status", value === "all" ? null : value)
              }
              options={[
                { value: "all", label: `All ${checks.length}` },
                { value: "down", label: `Down ${down.length}` },
                { value: "up", label: `Up ${up.length}` },
              ]}
            />
          </div>
          {visible.length === 0 ? (
            <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
              Nothing matches. Change the search or the filter to see the rest.
            </p>
          ) : (
            visible.map((group) => (
              <section
                key={group.node.id}
                aria-label={group.node.name}
                className="divide-y rounded-lg border bg-card"
              >
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2">
                  <h2 className="text-sm font-medium">{group.node.name}</h2>
                  <span className="font-mono text-xs text-muted-foreground">
                    {serverChecksText(group.total, group.down)}
                  </span>
                  <Link
                    to={`/nodes/${group.node.id}`}
                    className="ml-auto font-mono text-xs text-primary underline-offset-4 hover:underline"
                  >
                    Open server →
                  </Link>
                </div>
                <ul className="divide-y">
                  {group.checks.map((check) => (
                    <CheckRow key={check.id} check={check} view={view} />
                  ))}
                </ul>
              </section>
            ))
          )}
        </div>
      )}

      {view.results.isError && (
        <p role="status" className="mt-3 text-sm text-destructive">
          Check history could not be loaded. Status and latency are still
          current.
        </p>
      )}

      {dialog}
    </>
  );
}
