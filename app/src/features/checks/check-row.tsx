import type { ReactNode } from "react";

import { SmallLabel, StatusDot } from "@/components/status";
import { HeartbeatStrip } from "@/components/strips";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import type { LogsTarget } from "@/features/services/logs-dialog";
import { useCheckResults, useOverview, useServices } from "@/lib/api";
import { checkLive, kindLabel, shownTarget, type LiveTone } from "@/lib/checks";
import { agentCurrent } from "@/lib/devices";
import {
  checkDisplayStatus,
  clockTime,
  graceSeconds,
  nodeState,
  parseTimestamp,
} from "@/lib/format";
import { workSpans } from "@/lib/operations";
import { heartbeatSlots, uptimeOf, uptimeTip } from "@/lib/series";
import { isPending, serviceForCheck } from "@/lib/services";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import type { CheckRecord } from "@/types";

import { CheckMenu } from "./check-menu";
import { CheckTags } from "./down-box";

const ROW =
  "grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-x-3 gap-y-1.5 px-3 py-2 transition-colors hover:bg-card-hover md:grid-cols-[minmax(0,1.3fr)_minmax(140px,1.2fr)_56px_120px_32px]";

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
  const work = (check: CheckRecord) =>
    workSpans(
      services.data?.actions ?? [],
      check.node_id,
      check,
      services.data?.nodes.find((item) => item.id === check.node_id),
    );
  const quiet = (check: CheckRecord) =>
    results.data?.nodes?.[check.node_id]?.quiet ?? [];
  const openIncident = (check: CheckRecord) =>
    incidents.find(
      (incident) =>
        incident.check_id === check.id && incident.status === "OPEN",
    );
  const healing = (check: CheckRecord) => {
    const { entry } = entryOf(check);
    return (services.data?.actions ?? []).some(
      (action) =>
        isPending(action) &&
        action.action === "heal" &&
        action.nodeId === check.node_id &&
        action.kind === entry?.kind &&
        action.name === entry?.name,
    );
  };
  const live = (check: CheckRecord) =>
    checkLive({
      check,
      display: display(check),
      incident: openIncident(check),
      latest: results.data?.checks[check.id],
      lastSeen: nodeById.get(check.node_id)?.last_seen_at,
      work: work(check),
      quiet: quiet(check),
      healing: healing(check),
      now,
    });
  const windowOf = (check: CheckRecord) =>
    Math.max(300, nodeById.get(check.node_id)?.interval_seconds ?? 0);
  const slots = (check: CheckRecord) => {
    const node = nodeById.get(check.node_id);
    const windowSeconds = windowOf(check);
    return heartbeatSlots({
      slots: results.data?.checks[check.id]?.results ?? [],
      incidents: incidents.filter((incident) => incident.check_id === check.id),
      since: check.enabled ? parseTimestamp(check.created_at) : null,
      slotSeconds: windowSeconds,
      graceSeconds: graceSeconds(node?.interval_seconds ?? 0),
      settleSeconds: windowSeconds,
      now,
      asOf: results.data ? results.dataUpdatedAt : undefined,
      count: 48,
      work: work(check),
      quiet: quiet(check),
    });
  };
  const uptime = (check: CheckRecord) => uptimeOf(slots(check));
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
  const strip = (check: CheckRecord, className?: string) => (
    <HeartbeatStrip
      slots={slots(check)}
      windowSeconds={windowOf(check)}
      className={className}
    />
  );
  return {
    nodes,
    now,
    results,
    display,
    live,
    uptime,
    windowOf,
    openIncident,
    restartFor,
    logsFor,
    strip,
  };
}

const TONE_NOTE: Partial<Record<LiveTone, string>> = {
  work: "Down during work you sent. No incident opens unless it stays down afterwards. Not counted against uptime.",
  info: "The server is in its routine restart. Not counted against uptime.",
  off: "The server has sent nothing. Counted as down.",
};

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
  const target = shownTarget(check);
  const live = view.live(check);
  const uptime = view.uptime(check);
  const tip = uptimeTip(uptime, view.windowOf(check) * 1000, clockTime);
  return (
    <li className={cn(ROW, !check.enabled && "text-muted-foreground")}>
      <div className="min-w-0">
        <p className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
          <span
            title={
              view.display(check) === "UNTRUSTED"
                ? "Quarantined. Its results are not used and not counted against uptime."
                : (TONE_NOTE[live.tone] ?? live.label)
            }
          >
            <StatusDot
              tone={live.tone}
              pulse={live.tone === "work" || live.tone === "info"}
            />
          </span>
          <span className="truncate font-medium" title={check.name}>
            {check.name}
          </span>
          <SmallLabel>{kindLabel(check.kind)}</SmallLabel>
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
        <span className="sr-only">Uptime 4h </span>
        {uptime.percent === null ? (
          "--"
        ) : (
          <span tabIndex={0} className="tip" data-tip={tip}>
            {uptime.percent.toFixed(1)}%<span className="sr-only"> {tip}</span>
          </span>
        )}
      </span>
      <span
        className={cn(
          "col-start-2 row-start-1 text-right font-mono text-xs md:col-start-auto md:row-start-auto",
          (live.tone === "bad" || live.tone === "warn") && "text-destructive",
          live.tone === "work" && "text-primary",
          live.tone === "info" && "text-info",
        )}
      >
        {live.label}
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
