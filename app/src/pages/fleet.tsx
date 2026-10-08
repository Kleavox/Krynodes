import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { LayoutGrid, List, Search, TriangleAlert, X } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { Meter } from "@/components/meter";
import { DockerMark } from "@/components/docker-mark";
import { SecurityMark } from "@/components/security-mark";
import { PageHeader } from "@/components/page-header";
import { Sparkline } from "@/components/sparkline";
import { NodeStatus, OperationText } from "@/components/node-status";
import { StatusDot, nodeTone } from "@/components/status";
import { ReportStrip } from "@/components/strips";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { AgentVersion } from "@/features/agent/agent-version";
import { LatestAgent, UpdateNotice } from "@/features/agent/update-notice";
import { EnrollDialog } from "@/features/nodes/enroll-dialog";
import { NodeActions } from "@/features/nodes/node-actions";
import { UsageDialog } from "@/features/usage/usage-dialog";
import {
  useOverview,
  useRecentMetrics,
  useServices,
  useUsage,
} from "@/lib/api";
import { agentState, type AgentState } from "@/lib/agent";
import { budgetLevel, estimateDailyUse, quotaLine } from "@/lib/budget";
import {
  checkDisplayStatus,
  formatDuration,
  formatUptime,
  graceSeconds,
  metricText,
  nodeState,
  parseTimestamp,
  timeAgo,
  type NodeState,
} from "@/lib/format";
import { fleetCounts, matchesFleet, type FleetFilter } from "@/lib/fleet";
import {
  bySeverity,
  fleetSummary,
  nodeHealth,
  nodeUsage,
  type Severity,
} from "@/lib/health";
import {
  handleOf,
  maintenanceSpans,
  serverOperation,
  type ServerOperation,
} from "@/lib/operations";
import { isPending, runningText } from "@/lib/services";
import { layoutReportSlots, type Span } from "@/lib/series";
import { useMediaQuery } from "@/lib/use-media-query";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import type {
  ActionRecord,
  AgentRelease,
  CheckRecord,
  Incident,
  NodeRecord,
  RecentNode,
  RecentSlot,
} from "@/types";

function laidSlots(
  node: NodeRecord,
  recent: RecentNode | undefined,
  now: number,
  asOf: number | null,
  maintenance: Span[],
) {
  return layoutReportSlots<RecentSlot>({
    slots: recent?.slots ?? [],
    slotSeconds: recent?.slotSeconds ?? Math.max(300, node.interval_seconds),
    graceSeconds: graceSeconds(node.interval_seconds),
    settleSeconds: Math.max(300, node.interval_seconds),
    since:
      asOf !== null && node.enrolled_at
        ? parseTimestamp(node.enrolled_at)
        : null,
    now,
    asOf: asOf ?? undefined,
    maintenance,
  });
}

function spanOf(laid: { start: number }[]): string {
  const first = laid[0];
  const second = laid[1];
  if (!first || !second) return "--";
  return formatDuration((second.start - first.start) * laid.length);
}

function checksLine(checks: CheckRecord[], state: NodeState): string {
  if (checks.length === 0) return "No checks";
  if (state !== "online") return "Checks not reporting";
  const up = checks.filter((check) => check.status === "UP").length;
  return `${up}/${checks.length} checks up`;
}

function systemLine(node: NodeRecord): string {
  return [node.operating_system, node.architecture].filter(Boolean).join(" · ");
}

function readFilter(value: string | null): FleetFilter {
  return value === "issues" || value === "offline" || value === "updates"
    ? value
    : "all";
}

const SEVERITY_BORDER: Partial<Record<Severity, string>> = {
  critical: "border-destructive/50",
  warning: "border-warning/50",
};

const SEVERITY_TEXT: Partial<Record<Severity, string>> = {
  critical: "text-destructive",
  warning: "text-warning",
};

interface Row {
  node: NodeRecord;
  name: string;
  hostname: string | null;
  system: string | null;
  state: NodeState;
  severity: Severity;
  reasons: string[];
  agent: AgentState;
  operation: ServerOperation | null;
  busy: ActionRecord | null;
  maintenance: Span[];
}

export function FleetPage() {
  const overview = useOverview();
  const services = useServices();
  const recent = useRecentMetrics();
  const now = useNow(5_000);
  const desktop = useMediaQuery("(min-width: 768px)");
  const [params, setParams] = useSearchParams();

  const setParam = (key: string, value: string | null) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (value === null || value === "") next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: true },
    );

  const selectedId = params.get("node");
  const filter = readFilter(params.get("filter"));
  const query = params.get("q") ?? "";
  const view = desktop && params.get("view") === "list" ? "list" : "cards";
  const asOf = recent.data ? recent.dataUpdatedAt : null;
  const closePanel = () => setParam("node", null);

  useEffect(() => {
    if (!selectedId || !desktop) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !event.defaultPrevented) closePanel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const enrollDialog = (
    <EnrollDialog
      open={params.get("enroll") === "1"}
      onOpenChange={(open) => setParam("enroll", open ? "1" : null)}
    />
  );

  if (!overview.data) {
    return (
      <>
        <PageHeader title="Fleet" />
        <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[0, 1, 2, 3].map((key) => (
            <Skeleton key={key} className="h-24" />
          ))}
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {[0, 1, 2].map((key) => (
            <Skeleton key={key} className="h-52" />
          ))}
        </div>
        {enrollDialog}
      </>
    );
  }

  const { nodes, checks, incidents, agentRelease, mail } = overview.data;
  const seen = overview.dataUpdatedAt;
  const checksFor = (id: string) =>
    checks.filter((check) => check.node_id === id);
  const rows: Row[] = nodes
    .map((node) => {
      const health = nodeHealth(node, checksFor(node.id), seen);
      return {
        node,
        name: node.name,
        hostname: node.hostname,
        system: node.operating_system,
        state: nodeState(node, seen),
        agent: agentState(node, agentRelease.version, now),
        operation: serverOperation(node, services.data?.actions ?? [], now),
        maintenance: maintenanceSpans(services.data?.actions ?? [], node.id),
        busy:
          services.data?.actions.find(
            (action) =>
              action.nodeId === node.id &&
              action.kind !== "host" &&
              action.action !== "logs" &&
              isPending(action),
          ) ?? null,
        ...health,
      };
    })
    .sort(bySeverity);
  const counts = fleetCounts(rows);
  const visible = rows.filter((row) => matchesFleet(row, filter, query));
  const selected = nodes.find((node) => node.id === selectedId) ?? null;
  const select = (id: string) => setParam("node", id);
  const panel = selected && (
    <NodePanel
      node={selected}
      operation={
        rows.find((row) => row.node.id === selected.id)?.operation ?? null
      }
      maintenance={
        rows.find((row) => row.node.id === selected.id)?.maintenance ?? []
      }
      checks={checksFor(selected.id)}
      recent={recent.data?.nodes[selected.id]}
      release={agentRelease}
      now={now}
      seen={seen}
      asOf={asOf}
      showClose={desktop}
      onClose={closePanel}
    />
  );

  return (
    <>
      <PageHeader
        title="Fleet"
        actions={
          nodes.length > 0 && (
            <Button onClick={() => setParam("enroll", "1")}>Enroll node</Button>
          )
        }
      />

      {mail && (
        <p role="alert" className="mb-3 text-sm text-destructive">
          Alert mail could not be sent {timeAgo(mail.failedAt)}:{" "}
          {mail.error.replace(/\.?$/u, ".")} Failures and offline servers are
          not mailed until this works again.
        </p>
      )}

      {recent.isError && !recent.data && nodes.length > 0 && (
        <p role="status" className="mb-3 text-sm text-destructive">
          Recent history could not be loaded. Live values are still current.
        </p>
      )}

      {nodes.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8">
          <h2 className="text-lg font-semibold">Enroll your first server</h2>
          <ol className="mt-4 list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
            <li>Select Enroll node to get a one-time install command.</li>
            <li>Paste it into a terminal on the server.</li>
            <li>
              The server appears here within a minute, named after its hostname.
            </li>
          </ol>
          <Button className="mt-6" onClick={() => setParam("enroll", "1")}>
            Enroll node
          </Button>
        </div>
      ) : (
        <>
          <FleetSummary
            nodes={nodes}
            checks={checks}
            incidents={incidents}
            now={now}
            seen={seen}
          />
          <UpdateNotice
            nodes={nodes}
            release={agentRelease}
            now={now}
            onShow={() => setParam("filter", "updates")}
          />
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <label className="relative min-w-0 flex-1 basis-56 md:max-w-72">
              <span className="sr-only">Search servers</span>
              <Search
                aria-hidden="true"
                className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
              />
              <Input
                type="search"
                value={query}
                onChange={(event) => setParam("q", event.target.value)}
                placeholder="Search name, host or OS"
                className="pl-8"
              />
            </label>
            <FilterChips
              label="Show servers"
              value={filter}
              onChange={(value) =>
                setParam("filter", value === "all" ? null : value)
              }
              options={[
                { value: "all", label: `All ${counts.all}` },
                { value: "issues", label: `Issues ${counts.issues}` },
                { value: "offline", label: `Offline ${counts.offline}` },
                ...(counts.updates > 0 || filter === "updates"
                  ? [
                      {
                        value: "updates" as const,
                        label: `Updates ${counts.updates}`,
                      },
                    ]
                  : []),
              ]}
            />
            {desktop && (
              <div className="ml-auto flex items-center gap-3">
                <LatestAgent release={agentRelease} now={now} />
                <div
                  role="group"
                  aria-label="Layout"
                  className="flex rounded-md border p-0.5"
                >
                  {(
                    [
                      ["cards", "Cards", LayoutGrid],
                      ["list", "List", List],
                    ] as const
                  ).map(([value, label, Icon]) => (
                    <button
                      key={value}
                      type="button"
                      aria-pressed={view === value}
                      aria-label={label}
                      title={label}
                      onClick={() =>
                        setParam("view", value === "list" ? "list" : null)
                      }
                      className="grid size-7 place-items-center rounded-[5px] text-muted-foreground hover:text-foreground aria-pressed:bg-accent aria-pressed:text-foreground"
                    >
                      <Icon aria-hidden="true" className="size-4" />
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div
            className={cn(
              "grid grid-cols-1 gap-4",
              selected && desktop && "grid-cols-[minmax(0,1fr)_300px]",
            )}
          >
            {visible.length === 0 ? (
              <EmptyState
                title="No servers match"
                body="Change the search or the filter to see the rest."
                action={
                  <Button
                    variant="outline"
                    onClick={() =>
                      setParams(
                        (current) => {
                          const next = new URLSearchParams(current);
                          next.delete("q");
                          next.delete("filter");
                          return next;
                        },
                        { replace: true },
                      )
                    }
                  >
                    Show all servers
                  </Button>
                }
              />
            ) : view === "list" ? (
              <FleetTable
                rows={visible}
                checksFor={checksFor}
                release={agentRelease}
                now={now}
                selectedId={selectedId}
                onSelect={select}
              />
            ) : (
              <div className="canvas-dots grid grid-cols-1 content-start gap-3 rounded-lg border p-3 sm:grid-cols-2 xl:grid-cols-3">
                {visible.map((row) => (
                  <NodeCard
                    key={row.node.id}
                    row={row}
                    checks={checksFor(row.node.id)}
                    recent={recent.data?.nodes[row.node.id]}
                    release={agentRelease}
                    now={now}
                    asOf={asOf}
                    selected={row.node.id === selectedId}
                    onSelect={() => select(row.node.id)}
                  />
                ))}
                {filter === "all" && !query && (
                  <button
                    type="button"
                    onClick={() => setParam("enroll", "1")}
                    className="grid min-h-28 place-items-center rounded-lg border border-dashed text-sm text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground"
                  >
                    <span>
                      <span aria-hidden="true">+ </span>Add another server
                    </span>
                  </button>
                )}
              </div>
            )}
            {selected && desktop && (
              <aside
                aria-label={`${selected.name} details`}
                className="self-start rounded-lg border bg-card p-4 md:sticky md:top-16"
              >
                {panel}
              </aside>
            )}
          </div>
        </>
      )}

      {!desktop && (
        <Sheet
          open={selected !== null}
          onOpenChange={(open) => !open && closePanel()}
        >
          <SheetContent
            side="bottom"
            className="max-h-[85dvh] overflow-y-auto p-4"
          >
            <SheetHeader className="p-0">
              <SheetTitle className="truncate">{selected?.name}</SheetTitle>
              <SheetDescription className="sr-only">
                Node summary
              </SheetDescription>
            </SheetHeader>
            {panel}
          </SheetContent>
        </Sheet>
      )}

      {enrollDialog}
    </>
  );
}

function SummaryTile({
  label,
  value,
  detail,
  tone,
  to,
  onOpen,
  children,
}: {
  label: string;
  value: string;
  detail: string;
  tone?: "bad" | "warn" | "ok";
  to?: string;
  onOpen?: () => void;
  children?: ReactNode;
}) {
  const body = (
    <>
      <p className="text-[11px] tracking-wider text-muted-foreground uppercase">
        {label}
      </p>
      <p className="mt-1.5 font-mono text-2xl leading-none tracking-tight">
        {value}
      </p>
      <p
        className={cn(
          "mt-2 truncate font-mono text-[11px] text-muted-foreground",
          tone === "bad" && "text-destructive",
          tone === "warn" && "text-warning",
          tone === "ok" && "text-success",
        )}
      >
        {detail}
      </p>
      {children}
    </>
  );
  const frame = cn(
    "block min-w-0 rounded-lg border bg-card p-3.5",
    tone === "bad" && "border-destructive/40",
  );
  return to ? (
    <Link
      to={to}
      className={cn(
        frame,
        "transition-colors hover:border-border-strong hover:bg-card-hover",
        tone === "bad" && "hover:border-destructive/70",
      )}
    >
      {body}
    </Link>
  ) : onOpen ? (
    <button
      type="button"
      onClick={onOpen}
      className={cn(
        frame,
        "w-full text-left transition-colors hover:border-border-strong hover:bg-card-hover",
      )}
    >
      {body}
    </button>
  ) : (
    <div className={frame}>{body}</div>
  );
}

function FleetSummary({
  nodes,
  checks,
  incidents,
  now,
  seen,
}: {
  nodes: NodeRecord[];
  checks: CheckRecord[];
  incidents: Incident[];
  now: number;
  seen: number;
}) {
  const summary = fleetSummary(nodes, checks, seen);
  const open = incidents.filter((incident) => incident.status === "OPEN");
  const usage = useUsage();
  const [showUsage, setShowUsage] = useState(false);
  const estimate = estimateDailyUse(nodes);
  const real = usage.data?.source === "cloudflare" ? usage.data.krynodes : null;
  const use = real ?? estimate;
  const budget = usage.data?.budget ?? {
    requests: 20_000,
    writes: 30_000,
    reads: 1_000_000,
  };
  const level = budgetLevel(use, budget);
  const quota = quotaLine(use, budget);
  return (
    <section
      aria-label="Fleet summary"
      className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4"
    >
      <SummaryTile
        label="Servers online"
        value={`${summary.nodes.online}/${summary.nodes.total}`}
        detail={
          summary.nodes.offline > 0
            ? `${summary.nodes.offline} offline`
            : "none offline"
        }
        tone={summary.nodes.offline > 0 ? "bad" : "ok"}
        to={summary.nodes.offline > 0 ? "/?filter=offline" : undefined}
      />
      <SummaryTile
        label="Checks passing"
        value={`${summary.checks.up}/${summary.checks.total}`}
        detail={
          summary.checks.down > 0
            ? `${summary.checks.down} down`
            : summary.checks.stale > 0
              ? `${summary.checks.stale} not reporting`
              : summary.checks.total > 0
                ? "all passing"
                : "no checks yet"
        }
        tone={
          summary.checks.down > 0
            ? "bad"
            : summary.checks.stale > 0
              ? "warn"
              : summary.checks.total > 0
                ? "ok"
                : undefined
        }
        to={summary.checks.down > 0 ? "/checks?status=down" : "/checks"}
      />
      <SummaryTile
        label="Open incidents"
        value={String(open.length)}
        detail={
          open.length > 0
            ? `Longest ${timeAgo(open.at(-1)!.started_at, now).replace(" ago", "")}`
            : "all quiet"
        }
        tone={open.length > 0 ? "bad" : "ok"}
        to={open.length > 0 ? "/incidents?status=open" : "/incidents"}
      />
      <SummaryTile
        label={real ? "Krynodes quota · today" : "Krynodes quota · est."}
        value={`${quota.percent}%`}
        detail={quota.detail}
        tone={level === "over" ? "bad" : level === "warn" ? "warn" : undefined}
        onOpen={() => setShowUsage(true)}
      >
        <div
          aria-hidden="true"
          className="mt-2 h-1.5 overflow-hidden rounded-full bg-accent"
        >
          <div
            className={cn(
              "h-full rounded-full bg-primary",
              level === "warn" && "bg-warning",
              level === "over" && "bg-destructive",
            )}
            style={{ width: `${Math.min(100, quota.percent)}%` }}
          />
        </div>
      </SummaryTile>
      <UsageDialog
        open={showUsage}
        onOpenChange={setShowUsage}
        usage={usage.data}
        estimate={estimate}
      />
    </section>
  );
}

function Attention({
  severity,
  reasons,
}: {
  severity: Severity;
  reasons: string[];
}) {
  if (reasons.length === 0) return null;
  return (
    <p
      className={cn(
        "flex items-center gap-1.5 text-xs font-medium",
        SEVERITY_TEXT[severity],
      )}
    >
      <TriangleAlert aria-hidden="true" className="size-3.5 shrink-0" />
      <span className="truncate">{reasons.join(" · ")}</span>
    </p>
  );
}

function NodeCard({
  row,
  checks,
  recent,
  release,
  now,
  asOf,
  selected,
  onSelect,
}: {
  row: Row;
  checks: CheckRecord[];
  recent: RecentNode | undefined;
  release: AgentRelease;
  now: number;
  asOf: number | null;
  selected: boolean;
  onSelect: () => void;
}) {
  const { node, state, severity, reasons, operation, busy, maintenance } = row;
  const laid = laidSlots(node, recent, now, asOf, maintenance);
  const live = state === "online" || state === "offline";
  return (
    <article
      className={cn(
        "relative flex flex-col gap-3 rounded-lg border bg-card p-3.5 transition-colors hover:border-border-strong hover:bg-card-hover",
        SEVERITY_BORDER[severity],
        selected && "border-primary ring-3 ring-primary/20",
      )}
    >
      <div>
        <div className="flex items-center justify-between gap-2">
          <h2
            className="flex min-w-0 items-center gap-1.5 font-medium"
            title={node.name}
          >
            <button
              type="button"
              onClick={onSelect}
              aria-pressed={selected}
              className="min-w-0 truncate outline-none after:absolute after:inset-0 after:rounded-lg focus-visible:after:ring-2 focus-visible:after:ring-ring"
            >
              {node.name}
            </button>
            <DockerMark nodeId={node.id} />
            <SecurityMark nodeId={node.id} />
          </h2>
          <NodeStatus
            state={state}
            operation={operation}
            offlineDetail={timeAgo(node.last_seen_at, now)}
          />
        </div>
        {systemLine(node) && (
          <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
            {systemLine(node)}
          </p>
        )}
        {busy && !operation && (
          <p className="mt-1 flex items-center gap-1.5 truncate font-mono text-[11px] text-warning">
            <StatusDot tone="warn" pulse />
            <span className="truncate">
              {runningText(busy)} · {handleOf(busy.requestedBy)}
            </span>
          </p>
        )}
      </div>
      {state !== "offline" && (
        <Attention severity={severity} reasons={reasons} />
      )}
      {live ? (
        <>
          {state === "online" ? (
            <div>
              <p className="font-mono text-[10px] text-muted-foreground uppercase">
                CPU · last {spanOf(laid)}
              </p>
              <Sparkline
                values={laid.map((slot) => slot.sample?.cpu ?? null)}
                label={`CPU over the last ${spanOf(laid)}`}
              />
            </div>
          ) : (
            <p className="font-mono text-[10px] text-muted-foreground uppercase">
              Last known values
            </p>
          )}
          <div className="grid grid-cols-3 gap-3">
            {nodeUsage(node).map((item) => (
              <Meter
                key={item.label}
                label={item.label}
                value={item.value}
                stale={state === "offline"}
              />
            ))}
          </div>
          <ReportStrip
            states={laid.map((slot) => slot.state)}
            starts={laid.map((slot) => slot.start)}
          />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">
          {state === "pending" ? "Waiting for agent enrollment" : "Disabled"}
        </p>
      )}
      <div className="mt-auto flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t pt-2.5">
        <span className="font-mono text-[11px] whitespace-nowrap text-muted-foreground">
          {checksLine(checks, state)}
        </span>
        <AgentVersion node={node} release={release} now={now} />
      </div>
    </article>
  );
}

function ChecksCell({
  checks,
  state,
}: {
  checks: CheckRecord[];
  state: NodeState;
}) {
  if (checks.length === 0) {
    return <span className="text-muted-foreground">--</span>;
  }
  const shown = checks.map((check) =>
    checkDisplayStatus(check.status, state, check.enabled),
  );
  const paused = shown.filter((status) => status === "PAUSED").length;
  const active = checks.length - paused;
  const down = shown.filter((status) => status === "DOWN").length;
  if (down > 0) return <span className="text-destructive">{down} down</span>;
  if (active === 0)
    return <span className="text-muted-foreground">Paused</span>;
  if (state !== "online") {
    return <span className="text-muted-foreground">Not reporting</span>;
  }
  return (
    <span>
      {shown.filter((status) => status === "UP").length}/{active} up
      {paused > 0 && (
        <span className="text-muted-foreground"> · {paused} paused</span>
      )}
    </span>
  );
}

function FleetTable({
  rows,
  checksFor,
  release,
  now,
  selectedId,
  onSelect,
}: {
  rows: Row[];
  checksFor: (id: string) => CheckRecord[];
  release: AgentRelease;
  now: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <table className="w-full table-fixed text-sm">
        <thead className="border-b text-left text-[11px] tracking-wider text-muted-foreground uppercase">
          <tr>
            <th className="w-[28%] px-3 py-2 font-normal">Server</th>
            <th className="px-3 py-2 font-normal">CPU</th>
            <th className="px-3 py-2 font-normal">RAM</th>
            <th className="px-3 py-2 font-normal">Disk</th>
            <th className="w-[13%] px-3 py-2 font-normal">Checks</th>
            <th className="w-[16%] px-3 py-2 font-normal">Agent</th>
            <th className="w-[11%] px-3 py-2 text-right font-normal">
              Last seen
            </th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.map(({ node, state, severity, reasons, operation }) => (
            <tr
              key={node.id}
              className={cn(
                "relative transition-colors hover:bg-card-hover",
                node.id === selectedId && "bg-accent hover:bg-accent",
              )}
            >
              <td className="px-3 py-2.5">
                <div className="flex min-w-0 items-center gap-2">
                  <StatusDot
                    tone={operation ? "warn" : nodeTone(state)}
                    pulse={operation !== null}
                  />
                  <button
                    type="button"
                    onClick={() => onSelect(node.id)}
                    aria-pressed={node.id === selectedId}
                    className="min-w-0 truncate text-left font-medium outline-none after:absolute after:inset-0 focus-visible:after:ring-2 focus-visible:after:ring-ring focus-visible:after:ring-inset"
                    title={node.name}
                  >
                    {node.name}
                  </button>
                  <DockerMark nodeId={node.id} />
                  <SecurityMark nodeId={node.id} />
                </div>
                <p
                  className={cn(
                    "mt-0.5 truncate pl-4 font-mono text-[11px] text-muted-foreground",
                    state !== "offline" &&
                      reasons.length > 0 &&
                      SEVERITY_TEXT[severity],
                  )}
                >
                  {operation ? (
                    <span className="text-warning">
                      <OperationText operation={operation} />
                    </span>
                  ) : state === "offline" ? (
                    "Offline"
                  ) : reasons.length > 0 ? (
                    reasons.join(" · ")
                  ) : (
                    systemLine(node)
                  )}
                </p>
              </td>
              {nodeUsage(node).map((item) => (
                <td key={item.label} className="px-3 py-2.5">
                  <Meter
                    label={item.label}
                    value={item.value}
                    stale={state === "offline"}
                    hideLabel
                  />
                </td>
              ))}
              <td className="px-3 py-2.5 font-mono text-xs">
                <ChecksCell checks={checksFor(node.id)} state={state} />
              </td>
              <td className="px-3 py-2.5">
                <AgentVersion node={node} release={release} now={now} />
              </td>
              <td className="px-3 py-2.5 text-right font-mono text-xs text-muted-foreground">
                {timeAgo(node.last_seen_at, now)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">
        {label}
      </dt>
      <dd className="font-mono text-sm break-words">{value}</dd>
    </div>
  );
}

function NodePanel({
  node,
  operation,
  maintenance,
  checks,
  recent,
  release,
  now,
  seen,
  asOf,
  showClose,
  onClose,
}: {
  node: NodeRecord;
  operation: ServerOperation | null;
  maintenance: Span[];
  checks: CheckRecord[];
  recent: RecentNode | undefined;
  release: AgentRelease;
  now: number;
  seen: number;
  asOf: number | null;
  showClose: boolean;
  onClose: () => void;
}) {
  const state = nodeState(node, seen);
  const laid = laidSlots(node, recent, now, asOf, maintenance);
  const { severity, reasons } = nodeHealth(node, checks, seen);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 space-y-1.5">
          {showClose && (
            <h2 className="truncate text-base font-semibold" title={node.name}>
              {node.name}
            </h2>
          )}
          <NodeStatus
            state={state}
            operation={operation}
            offlineDetail={`reported ${timeAgo(node.last_seen_at, now)}`}
          />
          {systemLine(node) && (
            <p className="truncate font-mono text-[11px] text-muted-foreground">
              {systemLine(node)}
            </p>
          )}
        </div>
        {showClose && (
          <Button
            variant="ghost"
            size="icon"
            aria-label="Close details"
            onClick={onClose}
          >
            <X aria-hidden="true" />
          </Button>
        )}
      </div>
      {state !== "offline" && (
        <Attention severity={severity} reasons={reasons} />
      )}
      <div className="space-y-3">
        {nodeUsage(node).map((item) => (
          <Meter
            key={item.label}
            label={item.label}
            value={item.value}
            stale={state === "offline"}
          />
        ))}
      </div>
      <dl className="grid grid-cols-2 gap-2">
        <Stat label="Load 1m" value={metricText(node.load_1)} />
        <Stat label="Uptime" value={formatUptime(node.uptime_seconds)} />
      </dl>
      {state === "online" && (
        <div>
          <p className="mb-1 text-[11px] tracking-wider text-muted-foreground uppercase">
            CPU · last {spanOf(laid)}
          </p>
          <Sparkline
            className="h-12"
            values={laid.map((slot) => slot.sample?.cpu ?? null)}
            label={`CPU over the last ${spanOf(laid)}`}
          />
        </div>
      )}
      <div className="flex items-center justify-between gap-2 font-mono text-xs text-muted-foreground">
        <span>{checksLine(checks, state)}</span>
        <AgentVersion node={node} release={release} now={now} />
      </div>
      <div className="flex flex-wrap gap-2">
        <Button asChild size="sm">
          <Link to={`/nodes/${node.id}`}>Open node</Link>
        </Button>
        <NodeActions node={node} onDeleted={onClose} />
      </div>
    </div>
  );
}
