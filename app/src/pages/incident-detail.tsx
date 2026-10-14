import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { StatusChip, StatusDot } from "@/components/status";
import { Skeleton } from "@/components/ui/skeleton";
import {
  IncidentTimeline,
  UpdateForm,
} from "@/features/incidents/incident-updates";
import { useIncident } from "@/lib/api";
import {
  clockTime,
  formatDuration,
  parseTimestamp,
  shortDate,
} from "@/lib/format";
import { errorMessage } from "@/lib/http";
import { useNow } from "@/lib/use-now";

const SECTION_TITLE =
  "mb-2 flex min-h-8 items-center text-[11px] tracking-wider text-muted-foreground uppercase";

const when = (value: string) =>
  `${shortDate(parseTimestamp(value))} ${clockTime(parseTimestamp(value))}`;

export function IncidentDetailPage() {
  const { id = "" } = useParams();
  const detail = useIncident(id);
  const now = useNow();

  if (detail.isError) {
    return (
      <>
        <PageHeader title="Incident" />
        <EmptyState
          title="Incident not found"
          body={errorMessage(detail.error)}
        />
      </>
    );
  }
  if (!detail.data) {
    return (
      <>
        <PageHeader title="Incident" />
        <Skeleton className="h-64" />
      </>
    );
  }

  const { incident, results } = detail.data;
  const open = incident.status === "OPEN";
  const start = parseTimestamp(incident.started_at);
  const end = incident.resolved_at ? parseTimestamp(incident.resolved_at) : now;
  const duration = formatDuration(end - start);

  return (
    <>
      <PageHeader
        crumb={
          <>
            <Link to="/incidents" className="hover:underline">
              Incidents
            </Link>{" "}
            / {incident.check_name}
          </>
        }
        title={incident.check_name}
        meta={
          <StatusChip
            tone={open ? "bad" : "idle"}
            label={open ? "Open" : "Resolved"}
            detail={open ? `ongoing ${duration}` : `lasted ${duration}`}
          />
        }
      />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)] lg:items-start">
        <div className="order-2 space-y-6 lg:order-none">
          <section aria-labelledby="incident-updates">
            <h2 id="incident-updates" className={SECTION_TITLE}>
              Updates
            </h2>
            <div className="space-y-3">
              {open && <UpdateForm detail={detail.data} />}
              <IncidentTimeline detail={detail.data} />
            </div>
          </section>
          <section aria-labelledby="incident-results">
            <h2 id="incident-results" className={SECTION_TITLE}>
              Results · {results.length}
            </h2>
            {results.length === 0 ? (
              <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
                No results kept for this incident. Results are kept for 8 days.
              </p>
            ) : (
              <ul className="divide-y rounded-lg border bg-card">
                {results.map((result) => (
                  <li
                    key={result.t}
                    className="grid grid-cols-[auto_auto_minmax(0,1fr)_auto] items-start gap-x-3 px-3 py-2.5 text-sm"
                  >
                    <span className="font-mono text-xs leading-5 text-muted-foreground">
                      {clockTime(result.t)}
                    </span>
                    <span className="flex items-center gap-1.5 font-mono text-[11px] leading-5">
                      <StatusDot tone={result.status === "UP" ? "ok" : "bad"} />
                      {result.status}
                    </span>
                    <span className="min-w-0 font-mono text-xs leading-5 break-words text-muted-foreground">
                      {result.message ?? ""}
                    </span>
                    <span className="text-right font-mono text-xs leading-5">
                      {result.latencyMs === null
                        ? "--"
                        : `${result.latencyMs}ms`}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <section
          aria-labelledby="incident-details"
          className="order-1 rounded-lg border bg-card p-4 lg:order-none"
        >
          <h2
            id="incident-details"
            className="text-[11px] tracking-wider text-muted-foreground uppercase"
          >
            Details
          </h2>
          <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Node</dt>
            <dd className="min-w-0 truncate text-right">
              <Link
                to={`/nodes/${incident.node_id}`}
                className="hover:underline"
              >
                {incident.node_name}
              </Link>
            </dd>
            <dt className="text-muted-foreground">Check</dt>
            <dd className="text-right font-mono text-xs leading-5">
              {incident.check_kind}
            </dd>
            <dt className="text-muted-foreground">Target</dt>
            <dd className="min-w-0 text-right font-mono text-xs leading-5 break-all">
              {incident.check_target}
            </dd>
            <dt className="text-muted-foreground">Started</dt>
            <dd className="text-right font-mono text-xs leading-5">
              {when(incident.started_at)}
            </dd>
            <dt className="text-muted-foreground">Resolved</dt>
            <dd className="text-right font-mono text-xs leading-5">
              {incident.resolved_at ? when(incident.resolved_at) : "--"}
            </dd>
          </dl>
        </section>
      </div>
    </>
  );
}
