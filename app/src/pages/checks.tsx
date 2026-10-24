import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { PageHeader } from "@/components/page-header";
import { StatusDot } from "@/components/status";
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

type Filter = "all" | "down" | "offline" | "up";

function readFilter(value: string | null): Filter {
  return value === "down" || value === "offline" || value === "up"
    ? value
    : "all";
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
  const isDown = (check: CheckRecord) =>
    display(check) === "DOWN" && view.live(check).tone !== "work";
  const isOffline = (check: CheckRecord) =>
    display(check) === "OFFLINE" && view.live(check).tone === "off";
  const isUp = (check: CheckRecord) => display(check) === "UP";
  const down = checks.filter(isDown);
  const offline = checks.filter(isOffline);
  const up = checks.filter(isUp);
  const downItems: DownItem[] = groups.flatMap((group) =>
    group.checks.filter(isDown).map((check) => {
      const incident = view.openIncident(check);
      return {
        check,
        node: group.node,
        figure: view.live(check).label,
        incident,
        updates: incident ? (board.data?.latest[incident.id]?.updates ?? 0) : 0,
        autoLine: autoRestartLine(check, attention.data?.items ?? [], view.now),
        strip: view.strip(check),
        restart: view.restartFor(check),
        logs: view.logsFor(check),
      };
    }),
  );
  const needle = query.trim().toLowerCase();
  const matches: Record<Filter, (check: CheckRecord) => boolean> = {
    all: () => true,
    down: isDown,
    offline: isOffline,
    up: isUp,
  };
  const shown = (check: CheckRecord, serverName: string) =>
    matches[filter](check) &&
    (!needle ||
      [check.name, check.target, serverName].some((text) =>
        text.toLowerCase().includes(needle),
      ));
  const visible = groups
    .map((group) => ({
      ...group,
      total: group.checks.length,
      down: group.checks.filter(isDown).length,
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
            Add Check
          </Button>
        }
      />

      {nodes.length === 0 ? (
        <EmptyState
          title="No Servers Yet"
          body="Enroll a server before adding checks. Checks run on the server's agent."
          action={
            <Button asChild>
              <Link to="/?enroll=1">Enroll Server</Link>
            </Button>
          }
        />
      ) : checks.length === 0 ? (
        <EmptyState
          title="No Checks Configured"
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
              label="Filter Checks"
              value={filter}
              onChange={(value) =>
                setParam("status", value === "all" ? null : value)
              }
              options={[
                { value: "all", label: `All ${checks.length}` },
                { value: "down", label: `Down ${down.length}` },
                ...(offline.length > 0 || filter === "offline"
                  ? [
                      {
                        value: "offline" as const,
                        label: `Offline ${offline.length}`,
                      },
                    ]
                  : []),
                { value: "up", label: `Up ${up.length}` },
              ]}
            />
          </div>
          {visible.length === 0 ? (
            <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
              Nothing matches. Change the search or the filter to see the rest.
            </p>
          ) : (
            visible.map((group) => {
              const quiet = group.checks.find(
                (check) => display(check) === "OFFLINE",
              );
              const state = quiet && view.live(quiet);
              return (
                <section
                  key={group.node.id}
                  aria-label={group.node.name}
                  className="divide-y rounded-lg border bg-card"
                >
                  <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2">
                    <h2 className="text-sm font-medium">{group.node.name}</h2>
                    {state && (
                      <span className="inline-flex items-center gap-1.5 self-center font-mono text-xs text-muted-foreground">
                        <StatusDot tone={state.tone} />
                        {state.label}
                      </span>
                    )}
                    <span className="font-mono text-xs text-muted-foreground">
                      {serverChecksText(group.total, group.down)}
                    </span>
                    <Link
                      to={`/nodes/${group.node.id}`}
                      className="ml-auto font-mono text-xs text-primary underline-offset-4 hover:underline"
                    >
                      Open Server →
                    </Link>
                  </div>
                  <ul className="divide-y">
                    {group.checks.map((check) => (
                      <CheckRow key={check.id} check={check} view={view} />
                    ))}
                  </ul>
                </section>
              );
            })
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
