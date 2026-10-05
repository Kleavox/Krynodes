import { maintenanceSpans, plannedNow } from "@/lib/operations";
import type { Span } from "@/lib/series";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { PageHeader } from "@/components/page-header";
import { StatusDot, checkTone } from "@/components/status";
import { HeartbeatStrip, newestLatency } from "@/components/strips";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckDialog } from "@/features/checks/check-dialog";
import { CheckMenu } from "@/features/checks/check-menu";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useCheckResults, useOverview, useServices } from "@/lib/api";
import { isPending, serviceForCheck } from "@/lib/services";
import {
  checkDisplayStatus,
  clockTime,
  graceSeconds,
  nodeState,
  parseTimestamp,
  publicLabel,
} from "@/lib/format";
import { uptimeTip } from "@/lib/series";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import type { CheckHistory, CheckRecord, Incident, NodeRecord } from "@/types";

const COLUMNS =
  "md:grid-cols-[76px_minmax(120px,1.2fr)_76px_minmax(120px,1.4fr)_minmax(80px,0.8fr)_minmax(140px,2fr)_64px_64px_32px]";

type Filter = "all" | "down" | "up";

function readFilter(value: string | null): Filter {
  return value === "down" || value === "up" ? value : "all";
}

export function ChecksPage() {
  const overview = useOverview();
  const results = useCheckResults();
  const services = useServices();
  const runAction = useSignedAction();
  const now = useNow(60_000);
  const [params, setParams] = useSearchParams();
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
  const seen = overview.dataUpdatedAt;
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const display = (check: CheckRecord) => {
    const node = nodeById.get(check.node_id);
    return checkDisplayStatus(
      check.status,
      node ? nodeState(node, seen) : "offline",
      check.enabled,
    );
  };
  const down = checks.filter(
    (check) => check.enabled && display(check) === "DOWN",
  );
  const up = checks.filter((check) => display(check) === "UP");
  const visible = filter === "down" ? down : filter === "up" ? up : checks;

  return (
    <>
      <PageHeader
        title="Checks"
        actions={
          <>
            {checks.length > 0 && (
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
            )}
            <Button
              onClick={() => setParam("add", "1")}
              disabled={nodes.length === 0}
            >
              Add check
            </Button>
          </>
        }
      />

      {nodes.length === 0 ? (
        <EmptyState
          title="No nodes yet"
          body="Enroll a node before adding checks. Checks run on the node's agent."
          action={
            <Button asChild>
              <Link to="/?enroll=1">Enroll node</Link>
            </Button>
          }
        />
      ) : checks.length === 0 ? (
        <EmptyState
          title="No checks configured"
          body="Add an HTTP, TCP or systemd check to one of your nodes."
        />
      ) : visible.length === 0 ? (
        <EmptyState
          title={filter === "down" ? "No checks are down" : "No checks are up"}
          body="Change the filter to see the rest."
        />
      ) : (
        <div className="rounded-lg border bg-card">
          <div
            aria-hidden="true"
            className={cn(
              "hidden gap-x-3 border-b px-3 py-2 text-[11px] tracking-wider text-muted-foreground uppercase md:grid",
              COLUMNS,
            )}
          >
            <span>Status</span>
            <span>Name</span>
            <span>Kind</span>
            <span>Target</span>
            <span>Node</span>
            <span>Last 4 hours</span>
            <span className="text-right">Up 4h</span>
            <span className="text-right">Latency</span>
            <span />
          </div>
          <ul className="divide-y">
            {visible.map((check) => (
              <CheckRow
                key={check.id}
                check={check}
                nodes={nodes}
                node={nodeById.get(check.node_id)}
                history={results.data?.checks[check.id]}
                incidents={overview.data.incidents.filter(
                  (incident) => incident.check_id === check.id,
                )}
                now={now}
                seen={seen}
                asOf={results.data ? results.dataUpdatedAt : undefined}
                maintenance={maintenanceSpans(
                  services.data?.actions ?? [],
                  check.node_id,
                )}
                restart={(() => {
                  const node = nodeById.get(check.node_id);
                  const entry = serviceForCheck(check, services.data);
                  const trusted =
                    (services.data?.nodes.find(
                      (entry) => entry.id === check.node_id,
                    )?.trust?.access.length ?? 0) > 0;
                  const busy = services.data?.actions.some(
                    (action) =>
                      isPending(action) &&
                      action.nodeId === check.node_id &&
                      action.kind === "systemd" &&
                      action.name === entry?.name,
                  );
                  return node && entry && trusted && !busy
                    ? () =>
                        runAction.mutate({
                          action: "restart",
                          targets: [
                            {
                              nodeId: node.id,
                              kind: "systemd",
                              name: entry.name,
                            },
                          ],
                        })
                    : undefined;
                })()}
              />
            ))}
          </ul>
        </div>
      )}

      {results.isError && (
        <p role="status" className="mt-3 text-sm text-destructive">
          Check history could not be loaded. Status and latency are still
          current.
        </p>
      )}

      {dialog}
    </>
  );
}

function CheckRow({
  check,
  nodes,
  node,
  history,
  incidents,
  now,
  seen,
  asOf,
  maintenance,
  restart,
}: {
  check: CheckRecord;
  nodes: NodeRecord[];
  node: NodeRecord | undefined;
  history: CheckHistory | undefined;
  incidents: Incident[];
  now: number;
  seen: number;
  restart: (() => void) | undefined;
  asOf: number | undefined;
  maintenance: Span[];
}) {
  const windowSeconds = Math.max(300, node?.interval_seconds ?? 0);
  const status = checkDisplayStatus(
    check.status,
    node ? nodeState(node, seen) : "offline",
    check.enabled,
  );
  return (
    <li
      className={cn(
        "grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2 px-3 py-2.5 transition-colors hover:bg-card-hover",
        !check.enabled && "text-muted-foreground",
        COLUMNS,
      )}
    >
      <span className="flex items-center gap-1.5 font-mono text-[11px]">
        {status === "DOWN" && plannedNow(maintenance, now) ? (
          <span
            className="flex items-center gap-1.5"
            title="Down during planned work on its server. No incident opens unless it stays down afterwards."
          >
            <StatusDot tone="warn" pulse />
            PLANNED
          </span>
        ) : (
          <>
            <StatusDot tone={checkTone(status)} />
            {status}
          </>
        )}
      </span>
      <span className="min-w-0 truncate font-medium" title={check.name}>
        {check.name}
        {publicLabel(check) && (
          <Badge variant="outline" className="ml-2 font-mono text-[10px]">
            {publicLabel(check)}
          </Badge>
        )}
        {check.auto_restart === 1 && (
          <Badge
            variant="outline"
            className="ml-2 font-mono text-[10px]"
            title="Restarts automatically when this check turns red"
          >
            AUTO
          </Badge>
        )}
        <span className="ml-2 font-mono text-[10px] text-muted-foreground md:hidden">
          {check.kind}
        </span>
      </span>
      <span className="hidden md:block">
        <Badge variant="outline" className="font-mono">
          {check.kind}
        </Badge>
      </span>
      <span
        className="hidden truncate font-mono text-xs text-muted-foreground md:block"
        title={check.target}
      >
        {check.target}
      </span>
      <Link
        to={`/nodes/${check.node_id}`}
        className="hidden truncate text-sm hover:underline md:block"
      >
        {node?.name ?? "--"}
      </Link>
      <HeartbeatStrip
        results={history?.results}
        incidents={incidents}
        since={check.enabled ? parseTimestamp(check.created_at) : null}
        windowSeconds={windowSeconds}
        graceSeconds={graceSeconds(node?.interval_seconds ?? 0)}
        settleSeconds={windowSeconds}
        now={now}
        asOf={asOf}
        count={48}
        maintenance={maintenance}
        className="col-span-3 md:col-span-1"
      />
      <span className="hidden text-right font-mono text-xs md:block">
        <span className="sr-only">Up 4h </span>
        {history?.up4h == null ? (
          "--"
        ) : (
          <span
            tabIndex={0}
            className="tip"
            data-tip={uptimeTip(history.results, clockTime)}
          >
            {history.up4h.toFixed(1)}%
            <span className="sr-only">
              {" "}
              {uptimeTip(history.results, clockTime)}
            </span>
          </span>
        )}
      </span>
      <span className="hidden text-right font-mono text-xs md:block">
        {newestLatency(history)}
      </span>
      <span className="col-start-3 row-start-1 md:col-start-auto md:row-start-auto">
        <CheckMenu check={check} nodes={nodes} restart={restart} />
      </span>
    </li>
  );
}
