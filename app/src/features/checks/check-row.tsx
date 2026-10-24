import type { ReactNode } from "react";

import { SmallLabel, StatusDot, checkTone } from "@/components/status";
import { HeartbeatStrip } from "@/components/strips";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import type { LogsTarget } from "@/features/services/logs-dialog";
import { useCheckResults, useOverview, useServices } from "@/lib/api";
import { checkFigure, shownTarget } from "@/lib/checks";
import { agentCurrent } from "@/lib/devices";
import {
  checkDisplayStatus,
  clockTime,
  graceSeconds,
  nodeState,
  parseTimestamp,
} from "@/lib/format";
import { maintenanceSpans, plannedNow } from "@/lib/operations";
import { uptimeTip } from "@/lib/series";
import { isPending, serviceForCheck } from "@/lib/services";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import type { CheckRecord } from "@/types";

import { CheckMenu } from "./check-menu";
import { CheckTags } from "./down-box";

const ROW =
  "grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-x-3 gap-y-1.5 px-3 py-2 transition-colors hover:bg-card-hover md:grid-cols-[minmax(0,1.3fr)_minmax(140px,1.2fr)_56px_96px_32px]";

export function useCheckView() {
  const overview = useOverview();
  const results = useCheckResults();
  const services = useServices();
  const runAction = useSignedAction();
  const now = useNow(60_000);
  const nodes = overview.data?.nodes ?? [];
  const incidents = overview.data?.incidents ?? [];
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
  const maintenance = (check: CheckRecord) =>
    maintenanceSpans(services.data?.actions ?? [], check.node_id);
  const planned = (check: CheckRecord) =>
    display(check) === "DOWN" && plannedNow(maintenance(check), now);
  const openIncident = (check: CheckRecord) =>
    incidents.find(
      (incident) =>
        incident.check_id === check.id && incident.status === "OPEN",
    );
  const figure = (check: CheckRecord) =>
    check.enabled
      ? checkFigure(
          check,
          display(check),
          openIncident(check),
          results.data?.checks[check.id],
          now,
        )
      : "paused";
  const entryOf = (check: CheckRecord) => {
    const entry = serviceForCheck(check, services.data);
    const trusted =
      (services.data?.nodes.find((item) => item.id === check.node_id)?.trust
        ?.access.length ?? 0) > 0;
    const busy = services.data?.actions.some(
      (action) =>
        isPending(action) &&
        action.nodeId === check.node_id &&
        action.kind === entry?.kind &&
        action.name === entry?.name,
    );
    return { entry, trusted, busy };
  };
  const restartFor = (check: CheckRecord) => {
    const { entry, trusted, busy } = entryOf(check);
    return entry && trusted && !busy
      ? () =>
          runAction.mutate({
            action: "restart",
            targets: [
              { nodeId: check.node_id, kind: entry.kind, name: entry.name },
            ],
          })
      : undefined;
  };
  const logsFor = (check: CheckRecord): LogsTarget | null => {
    const node = nodeById.get(check.node_id);
    const { entry } = entryOf(check);
    return node && entry && agentCurrent(node)
      ? {
          nodeId: node.id,
          nodeName: node.name,
          kind: entry.kind,
          name: entry.name,
        }
      : null;
  };
  const strip = (check: CheckRecord, className?: string) => {
    const node = nodeById.get(check.node_id);
    const windowSeconds = Math.max(300, node?.interval_seconds ?? 0);
    return (
      <HeartbeatStrip
        results={results.data?.checks[check.id]?.results}
        incidents={incidents.filter(
          (incident) => incident.check_id === check.id,
        )}
        since={check.enabled ? parseTimestamp(check.created_at) : null}
        windowSeconds={windowSeconds}
        graceSeconds={graceSeconds(node?.interval_seconds ?? 0)}
        settleSeconds={windowSeconds}
        now={now}
        asOf={results.data ? results.dataUpdatedAt : undefined}
        count={48}
        maintenance={maintenance(check)}
        className={className}
      />
    );
  };
  return {
    nodes,
    now,
    results,
    display,
    planned,
    openIncident,
    figure,
    restartFor,
    logsFor,
    strip,
  };
}

export type CheckView = ReturnType<typeof useCheckView>;

export function CheckRow({
  check,
  view,
  note,
}: {
  check: CheckRecord;
  view: CheckView;
  note?: ReactNode;
}) {
  const status = view.display(check);
  const target = shownTarget(check);
  const history = view.results.data?.checks[check.id];
  const isPlanned = view.planned(check);
  return (
    <li className={cn(ROW, !check.enabled && "text-muted-foreground")}>
      <div className="min-w-0">
        <p className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
          <span
            title={
              isPlanned
                ? "Down during planned work on its server. No incident opens unless it stays down afterwards."
                : status
            }
          >
            <StatusDot
              tone={isPlanned ? "warn" : checkTone(status)}
              pulse={isPlanned}
            />
          </span>
          <span className="truncate font-medium" title={check.name}>
            {check.name}
          </span>
          <SmallLabel>{check.kind}</SmallLabel>
          <CheckTags check={check} />
        </p>
        {target && (
          <p
            className="truncate font-mono text-xs text-muted-foreground"
            title={check.target}
          >
            {target}
          </p>
        )}
        {note}
      </div>
      {view.strip(check, "col-span-3 md:col-span-1")}
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
      <span
        className={cn(
          "col-start-2 row-start-1 text-right font-mono text-xs md:col-start-auto md:row-start-auto",
          status === "DOWN" && !isPlanned && "text-destructive",
        )}
      >
        {isPlanned ? "planned" : view.figure(check)}
      </span>
      <span className="col-start-3 row-start-1 md:col-start-auto md:row-start-auto">
        <CheckMenu
          check={check}
          nodes={view.nodes}
          restart={
            check.kind === "SERVICE" ? view.restartFor(check) : undefined
          }
        />
      </span>
    </li>
  );
}
