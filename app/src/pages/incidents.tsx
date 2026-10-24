import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { PageHeader } from "@/components/page-header";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useIncidentBoard, useOverview } from "@/lib/api";
import {
  clockTime,
  formatDuration,
  parseTimestamp,
  shortDate,
} from "@/lib/format";
import { UPDATE_LABEL, last30Text, latestLine } from "@/lib/incidents";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import type { Incident, IncidentBoard } from "@/types";

type Filter = "all" | "open" | "resolved";

function readFilter(value: string | null): Filter {
  return value === "open" || value === "resolved" ? value : "all";
}

export function IncidentsPage() {
  const overview = useOverview();
  const board = useIncidentBoard();
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const filter = readFilter(params.get("status"));

  if (!overview.data) {
    return (
      <>
        <PageHeader title="Incidents" />
        <Skeleton className="h-64" />
      </>
    );
  }

  const { incidents, checks } = overview.data;
  const open = incidents.filter((incident) => incident.status === "OPEN");
  const resolved = incidents.filter(
    (incident) => incident.status === "RESOLVED",
  );
  const hasChecks = checks.some((check) => Boolean(check.enabled));

  return (
    <>
      <PageHeader
        title="Incidents"
        actions={
          incidents.length > 0 && (
            <FilterChips
              label="Filter Incidents"
              value={filter}
              onChange={(value) =>
                setParams(value === "all" ? {} : { status: value }, {
                  replace: true,
                })
              }
              options={[
                { value: "all", label: "All" },
                { value: "open", label: `Open ${open.length}` },
                { value: "resolved", label: `Resolved ${resolved.length}` },
              ]}
            />
          )
        }
      />

      {incidents.length === 0 ? (
        hasChecks ? (
          <EmptyState
            title="No Incidents Recorded"
            body="An incident opens after consecutive check failures and closes when the check recovers."
          />
        ) : (
          <EmptyState
            title="No Checks Configured"
            body="Add a check to start recording incidents."
            action={
              <Button asChild>
                <Link to="/checks?add=1">Add Check</Link>
              </Button>
            }
          />
        )
      ) : (
        <div className="space-y-6">
          {filter !== "resolved" &&
            (open.length > 0 ? (
              <section aria-label="Open Incidents" className="space-y-3">
                {open.map((incident) => (
                  <OpenIncident
                    key={incident.id}
                    incident={incident}
                    latest={board.data?.latest[incident.id]}
                    now={now}
                  />
                ))}
              </section>
            ) : (
              filter === "open" && (
                <EmptyState
                  title="Nothing Is Open"
                  body="Every recorded incident has resolved."
                />
              )
            ))}
          {filter !== "open" &&
            (resolved.length > 0 ? (
              <section aria-labelledby="resolved-incidents">
                <div className="mb-2 flex min-h-8 flex-wrap items-baseline gap-x-3">
                  <h2
                    id="resolved-incidents"
                    className="text-xs font-medium text-muted-foreground"
                  >
                    Resolved
                  </h2>
                  {board.data && (
                    <span className="font-mono text-xs text-muted-foreground">
                      {last30Text(board.data.last30)}
                    </span>
                  )}
                </div>
                <ul className="divide-y rounded-lg border bg-card">
                  {resolved.map((incident) => (
                    <ResolvedRow key={incident.id} incident={incident} />
                  ))}
                </ul>
              </section>
            ) : (
              filter === "resolved" && (
                <EmptyState
                  title="No Resolved Incidents Yet"
                  body="Resolved incidents appear here, newest first."
                />
              )
            ))}
          {incidents.length >= 50 && (
            <p className="text-xs text-muted-foreground">
              Showing the latest 50 incidents.
            </p>
          )}
        </div>
      )}
    </>
  );
}

function OpenIncident({
  incident,
  latest,
  now,
}: {
  incident: Incident;
  latest: IncidentBoard["latest"][string] | undefined;
  now: number;
}) {
  const start = parseTimestamp(incident.started_at);
  const line = latest ? latestLine(latest) : null;
  const failed =
    !latest?.update &&
    (latest?.action?.status === "failed" ||
      latest?.action?.status === "expired");
  return (
    <article className="rounded-lg border border-l-[3px] border-destructive/45 border-l-destructive bg-destructive/5 p-3.5">
      <div className="flex flex-wrap items-center gap-2 font-medium">
        <StatusDot tone="bad" />
        <span className="sr-only">Open:</span>
        <Link
          to={`/incidents/${incident.id}`}
          className="min-w-0 break-words hover:underline"
        >
          {incident.check_name}
        </Link>
        {incident.update_status && (
          <span className="rounded border border-warning/40 px-1.5 font-mono text-[11px] font-normal text-warning">
            {UPDATE_LABEL[incident.update_status]}
          </span>
        )}
        <span className="text-xs font-normal text-muted-foreground">
          On{" "}
          <Link
            to={`/nodes/${incident.node_id}`}
            className="text-foreground hover:underline"
          >
            {incident.node_name}
          </Link>
        </span>
        <span className="ml-auto font-mono text-xs text-destructive">
          Down {formatDuration(now - start)}
        </span>
      </div>
      <p className="mt-1.5 font-mono text-xs break-words">
        {incident.summary && (
          <span className="text-destructive">{incident.summary} · </span>
        )}
        <span className="text-muted-foreground">
          Since{" "}
          {now - start < 86_400_000
            ? clockTime(start)
            : `${shortDate(start)} ${clockTime(start)}`}
        </span>
      </p>
      {latest && line && (
        <p className="mt-1.5 flex gap-2 border-t border-destructive/20 pt-1.5 font-mono text-xs">
          <span className="shrink-0 text-muted-foreground">
            {clockTime(latest.at)}
          </span>
          <span className={cn("min-w-0 break-words", failed && "text-warning")}>
            {line}
          </span>
        </p>
      )}
    </article>
  );
}

function ResolvedRow({ incident }: { incident: Incident }) {
  const start = parseTimestamp(incident.started_at);
  const end = incident.resolved_at
    ? parseTimestamp(incident.resolved_at)
    : null;
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-2.5 transition-colors hover:bg-card-hover md:grid-cols-[110px_minmax(0,1fr)_minmax(0,0.6fr)_minmax(0,1.2fr)_60px]">
      <span className="font-mono text-xs text-muted-foreground">
        {shortDate(start)} {clockTime(start)}
      </span>
      <span className="min-w-0 truncate">
        <span className="sr-only">Resolved: </span>
        <Link to={`/incidents/${incident.id}`} className="hover:underline">
          {incident.check_name}
        </Link>
      </span>
      <Link
        to={`/nodes/${incident.node_id}`}
        className="hidden truncate font-mono text-xs text-muted-foreground hover:underline md:block"
      >
        {incident.node_name}
      </Link>
      <span
        className="hidden truncate font-mono text-xs text-muted-foreground md:block"
        title={incident.summary ?? undefined}
      >
        {incident.summary ?? ""}
      </span>
      <span className="text-right font-mono text-xs">
        {end === null ? "--" : formatDuration(end - start)}
      </span>
    </li>
  );
}
