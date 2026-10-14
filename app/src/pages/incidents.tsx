import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { PageHeader } from "@/components/page-header";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { UPDATE_LABEL } from "@/features/incidents/incident-updates";
import { useOverview } from "@/lib/api";
import {
  clockTime,
  formatDuration,
  parseTimestamp,
  shortDate,
} from "@/lib/format";
import { groupByDay } from "@/lib/series";
import { useNow } from "@/lib/use-now";
import type { Incident } from "@/types";

type Filter = "all" | "open" | "resolved";

function readFilter(value: string | null): Filter {
  return value === "open" || value === "resolved" ? value : "all";
}

export function IncidentsPage() {
  const overview = useOverview();
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
              label="Filter incidents"
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
            title="No incidents recorded"
            body="An incident opens after consecutive check failures and closes when the check recovers."
          />
        ) : (
          <EmptyState
            title="No checks configured"
            body="Add a check to start recording incidents."
            action={
              <Button asChild>
                <Link to="/checks?add=1">Add check</Link>
              </Button>
            }
          />
        )
      ) : (
        <div className="space-y-6">
          {filter !== "resolved" &&
            (open.length > 0 ? (
              <section aria-label="Open incidents" className="space-y-3">
                {open.map((incident) => (
                  <OpenIncident
                    key={incident.id}
                    incident={incident}
                    now={now}
                  />
                ))}
              </section>
            ) : (
              filter === "open" && (
                <EmptyState
                  title="Nothing is open"
                  body="Every recorded incident has resolved."
                />
              )
            ))}
          {filter !== "open" &&
            (resolved.length > 0
              ? groupByDay(
                  resolved,
                  (incident) => incident.started_at,
                  now,
                ).map((group) => (
                  <section
                    key={group.label}
                    aria-label={`Resolved ${group.label}`}
                  >
                    <h2 className="mb-2 text-[11px] tracking-wider text-muted-foreground uppercase">
                      {group.label}
                    </h2>
                    <ul className="divide-y rounded-lg border bg-card">
                      {group.items.map((incident) => (
                        <ResolvedRow key={incident.id} incident={incident} />
                      ))}
                    </ul>
                  </section>
                ))
              : filter === "resolved" && (
                  <EmptyState
                    title="No resolved incidents yet"
                    body="Resolved incidents appear here, grouped by day."
                  />
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

function OpenIncident({ incident, now }: { incident: Incident; now: number }) {
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
        <span className="ml-auto font-mono text-xs text-destructive">
          Ongoing {formatDuration(now - parseTimestamp(incident.started_at))}
        </span>
      </div>
      <p className="mt-1.5 text-xs text-muted-foreground">
        Node{" "}
        <Link
          to={`/nodes/${incident.node_id}`}
          className="text-foreground hover:underline"
        >
          {incident.node_name}
        </Link>{" "}
        · started {shortDate(incident.started_at)}{" "}
        {clockTime(incident.started_at)}
      </p>
      {incident.summary && (
        <p className="mt-1 font-mono text-xs break-words">{incident.summary}</p>
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
    <li className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-2.5 transition-colors hover:bg-card-hover md:grid-cols-[auto_minmax(0,1.2fr)_minmax(0,1fr)_150px_70px]">
      <StatusDot tone="idle" />
      <span
        className="min-w-0 truncate"
        title={incident.summary ?? incident.check_name}
      >
        <span className="sr-only">Resolved: </span>
        <Link to={`/incidents/${incident.id}`} className="hover:underline">
          {incident.check_name}
        </Link>
      </span>
      <Link
        to={`/nodes/${incident.node_id}`}
        className="hidden truncate text-sm text-muted-foreground hover:underline md:block"
      >
        {incident.node_name}
      </Link>
      <span className="hidden font-mono text-xs text-muted-foreground md:block">
        {clockTime(start)} → {end === null ? "--" : clockTime(end)}
      </span>
      <span className="text-right font-mono text-xs">
        {end === null ? "--" : formatDuration(end - start)}
      </span>
    </li>
  );
}
