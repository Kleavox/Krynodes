import { useState } from "react";
import { Link, Navigate, useLocation, useSearchParams } from "react-router";

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
import {
  useCheckDismissals,
  useDismissCheck,
  useHistoryAttention,
  useIncidentBoard,
  useNetwork,
  useOverview,
  useServices,
} from "@/lib/api";
import {
  autoRestartLine,
  checksByServer,
  serverChecksText,
} from "@/lib/checks";
import {
  downLatest,
  incidentRowLine,
  incidentsRedirect,
  last30Parts,
  lastIncidentLine,
  recentIncidents,
} from "@/lib/incidents";
import {
  checkSuggestions,
  hostingOf,
  type CheckSuggestion,
} from "@/lib/network";
import { cn } from "@/lib/utils";
import type { CheckRecord } from "@/types";

type Filter = "all" | "down" | "offline" | "up";

function readFilter(value: string | null): Filter {
  return value === "down" || value === "offline" || value === "up"
    ? value
    : "all";
}

export function IncidentsRedirect() {
  const { search } = useLocation();
  return <Navigate to={incidentsRedirect(search)} replace />;
}

export function ChecksPage() {
  const overview = useOverview();
  const attention = useHistoryAttention();
  const board = useIncidentBoard();
  const view = useCheckView();
  const services = useServices();
  const network = useNetwork().data;
  const dismissals = useCheckDismissals().data?.dismissals;
  const dismiss = useDismissCheck();
  const [prefill, setPrefill] = useState<CheckSuggestion["check"] | null>(null);
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
    <>
      <CheckDialog
        open={params.get("add") === "1"}
        onOpenChange={(open) => setParam("add", open ? "1" : null)}
        nodes={nodes}
      />
      <CheckDialog
        open={prefill !== null}
        onOpenChange={(open) => !open && setPrefill(null)}
        nodes={nodes}
        prefill={prefill ?? undefined}
      />
    </>
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

  const { checks, incidents } = overview.data;
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
        latest: downLatest(
          incident ? board.data?.latest[incident.id] : undefined,
          autoRestartLine(check, attention.data?.items ?? [], view.now),
        ),
        strip: view.strip(check, "max-md:hidden"),
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
  const suggestions =
    network && dismissals && filter === "all" && !needle
      ? checkSuggestions(
          hostingOf(services.data?.nodes ?? [], nodes),
          network,
          checks,
          dismissals,
        )
      : [];
  const suggestionsFor = (nodeId: string) =>
    suggestions.filter((suggestion) => suggestion.nodeId === nodeId);
  const alone = nodes.filter(
    (node) =>
      suggestionsFor(node.id).length > 0 &&
      !visible.some((group) => group.node.id === node.id),
  );
  const suggested = (nodeId: string) =>
    suggestionsFor(nodeId).map((suggestion) => (
      <li
        key={`${suggestion.project}:${suggestion.check.target}`}
        className="flex flex-wrap items-center gap-2 px-3 py-2.5 text-sm"
      >
        <span className="min-w-0 flex-1 break-words text-muted-foreground">
          {suggestion.text}
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="h-9 md:h-8"
          disabled={dismiss.isPending}
          onClick={() =>
            dismiss.mutate({
              nodeId: suggestion.nodeId,
              project: suggestion.project,
              reaches: suggestion.reaches,
            })
          }
        >
          Not Now
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-9 md:h-8"
          onClick={() => setPrefill(suggestion.check)}
        >
          Add Check
        </Button>
      </li>
    ));
  const lately = recentIncidents(incidents, view.now);
  const summary = board.data && last30Parts(board.data.last30);
  const more = (board.data?.last30.count ?? 0) > lately.length;
  const recent = lately.filter(
    (incident) =>
      !needle ||
      [incident.check_name, incident.node_name, incident.summary ?? ""].some(
        (text) => text.toLowerCase().includes(needle),
      ),
  );

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
        <div className="space-y-4 md:space-y-6">
          <DownBox items={downItems} nodes={nodes} />
          <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_340px] lg:gap-6">
            <div className="min-w-0 space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search checks and incidents"
                  aria-label="Search checks and incidents"
                  className="h-9 w-full sm:w-60 md:h-8"
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
                  Nothing matches. Change the search or the filter to see the
                  rest.
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
                        <h2 className="text-sm font-medium">
                          {group.node.name}
                        </h2>
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
                        {group.checks.map((check) => {
                          const last = lastIncidentLine(check.id, incidents);
                          return (
                            <CheckRow
                              key={check.id}
                              check={check}
                              view={view}
                              note={
                                last && (
                                  <p className="truncate font-mono text-xs text-muted-foreground">
                                    {last}
                                  </p>
                                )
                              }
                            />
                          );
                        })}
                        {suggested(group.node.id)}
                      </ul>
                    </section>
                  );
                })
              )}
              {alone.map((node) => (
                <section
                  key={node.id}
                  aria-label={node.name}
                  className="divide-y rounded-lg border bg-card"
                >
                  <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2">
                    <h2 className="text-sm font-medium">{node.name}</h2>
                    <Link
                      to={`/nodes/${node.id}`}
                      className="ml-auto font-mono text-xs text-primary underline-offset-4 hover:underline"
                    >
                      Open Server →
                    </Link>
                  </div>
                  <ul className="divide-y">{suggested(node.id)}</ul>
                </section>
              ))}
            </div>
            <aside aria-labelledby="recent-incidents">
              <h2
                id="recent-incidents"
                className="mb-2 text-xs text-muted-foreground"
              >
                Incidents · last 30 days
              </h2>
              <div className="rounded-lg border bg-card">
                <div className="flex items-baseline gap-3 px-3 py-3">
                  {summary ? (
                    <p className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-3 gap-y-1">
                      <span>
                        <span className="font-mono text-base lg:text-lg">
                          {summary.count}
                        </span>{" "}
                        <span className="text-xs text-muted-foreground">
                          {summary.noun}
                        </span>
                      </span>
                      <span className="lg:ml-auto">
                        <span className="font-mono text-base lg:text-lg">
                          {summary.down}
                        </span>{" "}
                        <span className="text-xs text-muted-foreground">
                          down
                        </span>
                      </span>
                    </p>
                  ) : (
                    <p className="flex-1 font-mono text-sm text-muted-foreground">
                      {board.data ? "No Incidents" : "--"}
                    </p>
                  )}
                  <Link
                    to="/history?show=incidents"
                    className={cn(
                      "shrink-0 font-mono text-xs text-primary underline-offset-4 hover:underline",
                      !more && "lg:hidden",
                    )}
                  >
                    All →
                  </Link>
                </div>
                {recent.length > 0 && (
                  <ul className="hidden divide-y border-t lg:block">
                    {recent.map((incident) => (
                      <li key={incident.id}>
                        <Link
                          to={`/incidents/${incident.id}`}
                          className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2.5 px-3 py-2 transition-colors hover:bg-card-hover"
                        >
                          <StatusDot
                            tone={incident.resolved_at ? "ok" : "bad"}
                            className="mt-1.5"
                          />
                          <span className="min-w-0">
                            <span className="flex items-baseline gap-1.5 text-sm">
                              <span className="truncate font-medium">
                                {incident.check_name}
                              </span>
                              <span className="shrink-0 text-xs text-muted-foreground">
                                {incident.node_name}
                              </span>
                            </span>
                            <span className="block truncate font-mono text-xs text-muted-foreground">
                              {incidentRowLine(incident, view.now)}
                            </span>
                          </span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </aside>
          </div>
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
