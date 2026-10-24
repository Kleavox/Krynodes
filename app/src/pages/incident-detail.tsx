import { ownerOf } from "@krynodes/protocol/owner";
import { Link, useParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { SmallLabel, StatusDot } from "@/components/status";
import { HeartbeatStrip } from "@/components/strips";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  IncidentTimeline,
  UpdateForm,
} from "@/features/incidents/incident-updates";
import { useIncident, useOverview, useServices } from "@/lib/api";
import { graceSeconds, stampTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import { incidentState, incidentStrip, ownerLink } from "@/lib/incidents";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";

export function IncidentDetailPage() {
  const { id = "" } = useParams();
  const detail = useIncident(id);
  const overview = useOverview();
  const services = useServices();
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

  const { incident } = detail.data;
  const open = incident.status === "OPEN";
  const interval =
    overview.data?.nodes.find((node) => node.id === incident.node_id)
      ?.interval_seconds ?? 0;
  const server = services.data?.nodes.find(
    (node) => node.id === incident.node_id,
  );
  const owner = server
    ? ownerOf(
        { kind: incident.check_kind, target: incident.check_target },
        server,
      )
    : null;
  const watched = owner && ownerLink(owner);
  const windowSeconds = Math.max(300, interval);
  const strip = incidentStrip(
    incident,
    detail.data.results,
    windowSeconds,
    now,
  );

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
          <span
            className={cn(
              "inline-flex items-center gap-1.5 font-mono text-xs",
              open ? "text-destructive" : "text-muted-foreground",
            )}
          >
            <StatusDot tone={open ? "bad" : "idle"} />
            {incidentState(incident, now)}
          </span>
        }
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link to={`/checks?q=${encodeURIComponent(incident.check_name)}`}>
                Open check
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to={`/nodes/${incident.node_id}`}>
                Open {incident.node_name} →
              </Link>
            </Button>
          </>
        }
      />
      <div className="space-y-4">
        <p className="-mt-3 flex flex-wrap items-center gap-x-1.5 gap-y-1 font-mono text-xs text-muted-foreground">
          <SmallLabel>{incident.check_kind}</SmallLabel>
          <span className="min-w-0 break-all">{incident.check_target}</span>
          <span>· on</span>
          <Link
            to={`/nodes/${incident.node_id}`}
            className="text-foreground hover:underline"
          >
            {incident.node_name}
          </Link>
          {watched && (
            <>
              <span>·</span>
              <Link to={watched.to} className="text-foreground hover:underline">
                {watched.label}
              </Link>
            </>
          )}
        </p>
        <div className="space-y-1">
          <HeartbeatStrip
            results={strip.results}
            incidents={[incident]}
            since={strip.measuredFrom}
            windowSeconds={strip.slotSeconds}
            graceSeconds={open ? graceSeconds(interval) : 0}
            settleSeconds={open ? windowSeconds : 0}
            now={strip.until}
            asOf={open ? detail.dataUpdatedAt : strip.until}
            count={strip.count}
          />
          <p className="flex justify-between gap-2 font-mono text-[11px] text-muted-foreground">
            <span>{stampTime(strip.since, now)}</span>
            <span>{stampTime(incident.started_at, strip.since)} opened</span>
            <span>
              {incident.resolved_at
                ? `${stampTime(incident.resolved_at, strip.since)} resolved`
                : "now"}
            </span>
          </p>
        </div>
        {open && <UpdateForm detail={detail.data} />}
        <IncidentTimeline detail={detail.data} />
      </div>
    </>
  );
}
