import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import type { UseQueryResult } from "@tanstack/react-query";
import { errorMessage } from "@/lib/http";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { MetricChart, type ChartRow } from "@/components/metric-chart";
import { DockerMark } from "@/components/docker-mark";
import { PageHeader } from "@/components/page-header";
import { NodeStatus } from "@/components/node-status";
import { StatusDot, checkTone } from "@/components/status";
import { HeartbeatStrip, newestLatency } from "@/components/strips";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { AgentPanel } from "@/features/agent/agent-panel";
import { NodeStacks } from "@/features/deploy/node-stacks";
import { NodeServices, RecentActions } from "@/features/services/node-sections";
import { CheckMenu } from "@/features/checks/check-menu";
import { NodeActions } from "@/features/nodes/node-actions";
import {
  useCheckResults,
  useDevices,
  useNodeMetrics,
  useOverview,
  useServices,
} from "@/lib/api";
import {
  checkDisplayStatus,
  clockTime,
  dayLabel,
  formatBytes,
  formatDuration,
  formatUptime,
  graceSeconds,
  metricText,
  nodeState,
  parseTimestamp,
  percentage,
  shortDate,
  timeAgo,
} from "@/lib/format";
import { usageLevel } from "@/lib/health";
import { findGaps, seriesSummary, withGapBreaks } from "@/lib/series";
import { maintenanceSpans, serverOperation } from "@/lib/operations";
import { useNow } from "@/lib/use-now";
import type { MetricRange, NodeMetrics, NodeRecord } from "@/types";

const RANGES: { value: MetricRange; label: string }[] = [
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

function readRange(value: string | null): MetricRange {
  return RANGES.find((option) => option.value === value)?.value ?? "6h";
}

const round1 = (value: number | null) =>
  value === null ? null : Math.round(value * 10) / 10;

const sectionTitle =
  "mb-2 flex min-h-8 items-center text-[11px] tracking-wider text-muted-foreground uppercase";

export function NodeDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const range = readRange(params.get("range"));
  const overview = useOverview();
  const metrics = useNodeMetrics(id, range);
  const results = useCheckResults();
  const services = useServices();
  const now = useNow(5_000);

  if (!overview.data) {
    return (
      <>
        <PageHeader title="Node" />
        <Skeleton className="h-96" />
      </>
    );
  }

  const node = overview.data.nodes.find((item) => item.id === id);
  if (!node) {
    return (
      <EmptyState
        title="Node not found"
        body="It may have been deleted."
        action={
          <Button asChild variant="outline">
            <Link to="/">Back to Fleet</Link>
          </Button>
        }
      />
    );
  }

  const state = nodeState(node, overview.dataUpdatedAt);
  const checks = overview.data.checks.filter(
    (check) => check.node_id === node.id,
  );
  const incidents = overview.data.incidents.filter(
    (incident) => incident.node_id === node.id,
  );

  return (
    <>
      <PageHeader
        crumb={
          <>
            <Link to="/" className="hover:underline">
              Fleet
            </Link>{" "}
            / {node.name}
          </>
        }
        title={node.name}
        meta={
          <span className="flex items-center gap-2">
            <NodeStatus
              state={state}
              operation={serverOperation(
                node,
                services.data?.actions ?? [],
                now,
              )}
              offlineDetail={`reported ${timeAgo(node.last_seen_at, now)}`}
            />
            <DockerMark nodeId={node.id} />
          </span>
        }
        actions={
          <>
            <FilterChips
              label="Time range"
              value={range}
              options={RANGES}
              onChange={(value) =>
                setParams(
                  (current) => {
                    const next = new URLSearchParams(current);
                    next.set("range", value);
                    return next;
                  },
                  { replace: true },
                )
              }
            />
            <NodeActions
              node={node}
              onDeleted={() => void navigate("/", { replace: true })}
              restart={params.get("restart") === "1"}
              onRestartClosed={() =>
                setParams(
                  (current) => {
                    const next = new URLSearchParams(current);
                    next.delete("restart");
                    return next;
                  },
                  { replace: true },
                )
              }
            />
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <Charts node={node} query={metrics} />
        <aside className="space-y-4">
          <section
            aria-labelledby="node-details"
            className="rounded-lg border bg-card p-4"
          >
            <h2 id="node-details" className={sectionTitle}>
              Details
            </h2>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
              <Fact label="Host" value={node.hostname} />
              <Fact label="System" value={node.operating_system} />
              <Fact label="Architecture" value={node.architecture} />
              <Fact
                label="Interval"
                value={`Every ${formatDuration(node.interval_seconds * 1000)}`}
              />
              <Fact label="Uptime" value={formatUptime(node.uptime_seconds)} />
              <Fact
                label="Reports"
                value={
                  node.connected_at
                    ? `Live since ${liveSince(node.connected_at, now)}`
                    : "Not connected"
                }
              />
              <AccessFact nodeId={node.id} />
              <Fact
                label="Enrolled"
                value={
                  node.enrolled_at
                    ? shortDate(parseTimestamp(node.enrolled_at))
                    : null
                }
              />
            </dl>
          </section>
          <AgentPanel
            node={node}
            release={overview.data.agentRelease}
            now={now}
          />
        </aside>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <div className="contents lg:flex lg:flex-col lg:gap-6">
          <div className="order-1 empty:hidden lg:order-none">
            <NodeServices node={node} seen={overview.dataUpdatedAt} />
          </div>
          <div className="order-2 empty:hidden lg:order-none">
            <NodeStacks node={node} seen={overview.dataUpdatedAt} />
          </div>
        </div>
        <div className="contents lg:flex lg:flex-col lg:gap-6">
          <div className="order-3 empty:hidden lg:order-none">
            <section aria-labelledby="node-checks">
              <h2 id="node-checks" className={sectionTitle}>
                Checks · {checks.length}
              </h2>
              {checks.length === 0 ? (
                <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
                  No checks configured. Use Actions to add one.
                </p>
              ) : (
                <ul className="divide-y rounded-lg border bg-card">
                  {checks.map((check) => (
                    <li
                      key={check.id}
                      className="grid grid-cols-[auto_minmax(0,1fr)_56px_36px] items-center gap-x-3 gap-y-2 py-2.5 pr-1 pl-3 sm:grid-cols-[auto_minmax(0,1fr)_minmax(120px,1.5fr)_56px_36px]"
                    >
                      <span className="flex items-center gap-1.5 font-mono text-[11px]">
                        <StatusDot
                          tone={checkTone(
                            checkDisplayStatus(
                              check.status,
                              state,
                              check.enabled,
                            ),
                          )}
                        />
                        {checkDisplayStatus(check.status, state, check.enabled)}
                      </span>
                      <span className="min-w-0 truncate" title={check.name}>
                        {check.name}{" "}
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {check.kind}
                        </span>
                      </span>
                      <HeartbeatStrip
                        maintenance={maintenanceSpans(
                          services.data?.actions ?? [],
                          node.id,
                        )}
                        results={results.data?.checks[check.id]?.results}
                        since={
                          check.enabled
                            ? parseTimestamp(check.created_at)
                            : null
                        }
                        incidents={incidents.filter(
                          (incident) => incident.check_id === check.id,
                        )}
                        windowSeconds={Math.max(300, node.interval_seconds)}
                        graceSeconds={graceSeconds(node.interval_seconds)}
                        settleSeconds={Math.max(300, node.interval_seconds)}
                        now={now}
                        asOf={results.data ? results.dataUpdatedAt : undefined}
                        count={24}
                        className="col-span-4 row-start-2 sm:col-span-1 sm:row-start-auto"
                      />
                      <span className="col-start-3 row-start-1 text-right font-mono text-xs sm:col-start-auto sm:row-start-auto">
                        {newestLatency(results.data?.checks[check.id])}
                      </span>
                      <span className="col-start-4 row-start-1 sm:col-start-auto sm:row-start-auto">
                        <CheckMenu check={check} nodes={overview.data.nodes} />
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
          <div className="order-4 empty:hidden lg:order-none">
            <section aria-labelledby="node-incidents">
              <h2 id="node-incidents" className={sectionTitle}>
                Incidents
              </h2>
              {incidents.length === 0 ? (
                <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
                  {checks.some((check) => Boolean(check.enabled))
                    ? "No incidents recorded."
                    : "Add a check to start recording incidents."}
                </p>
              ) : (
                <ul className="divide-y rounded-lg border bg-card">
                  {incidents.map((incident) => {
                    const open = incident.status === "OPEN";
                    const start = parseTimestamp(incident.started_at);
                    const end = incident.resolved_at
                      ? parseTimestamp(incident.resolved_at)
                      : now;
                    return (
                      <li
                        key={incident.id}
                        className="flex items-center gap-3 px-3 py-2.5"
                      >
                        <StatusDot tone={open ? "bad" : "idle"} />
                        <span className="min-w-0 flex-1 truncate">
                          <span className="sr-only">
                            {open ? "Open: " : "Resolved: "}
                          </span>
                          <Link
                            to={`/incidents/${incident.id}`}
                            className="hover:underline"
                          >
                            {incident.check_name}
                          </Link>
                          {incident.summary && (
                            <span className="text-muted-foreground">
                              {" "}
                              · {incident.summary}
                            </span>
                          )}
                        </span>
                        <span className="shrink-0 font-mono text-xs text-muted-foreground">
                          {open
                            ? `Ongoing ${formatDuration(end - start)}`
                            : `${shortDate(start)} · ${formatDuration(end - start)}`}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          </div>
          <div className="order-5 lg:relative lg:order-none lg:min-h-40 lg:flex-1">
            <RecentActions node={node} />
          </div>
        </div>
      </div>
    </>
  );
}

function AccessFact({ nodeId }: { nodeId: string }) {
  const services = useServices();
  const devices = useDevices();
  if (!services.data || !devices.data) return null;
  const trust =
    services.data.nodes.find((entry) => entry.id === nodeId)?.trust ?? null;
  const names = devices.data.devices
    .filter((device) => trust?.access.includes(device.fingerprint))
    .map((device) => device.name);
  const text =
    (trust?.core.length ?? 0) === 0
      ? "Not trusted yet"
      : names.length > 0
        ? names.join(", ")
        : "No access";
  return (
    <>
      <dt className="text-muted-foreground">Access</dt>
      <dd className="min-w-0 truncate text-right font-mono text-xs leading-5">
        <Link
          to="/devices"
          className="underline-offset-4 hover:underline"
          title="Change access in Trusted devices"
        >
          {text}
        </Link>
      </dd>
    </>
  );
}

function liveSince(at: string, now: number): string {
  const time = clockTime(at);
  return dayLabel(at, now) === "Today" ? time : `${shortDate(at)}, ${time}`;
}

function Fact({ label, value }: { label: string; value: string | null }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 truncate text-right font-mono text-xs leading-5">
        {value ?? "--"}
      </dd>
    </>
  );
}

function Charts({
  node,
  query,
}: {
  node: NodeRecord;
  query: UseQueryResult<NodeMetrics>;
}) {
  if (!query.data) {
    if (query.isError) {
      return (
        <p
          role="alert"
          className="rounded-lg border p-4 text-sm text-destructive"
        >
          Metric history could not be loaded: {errorMessage(query.error)}
        </p>
      );
    }
    return (
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {[0, 1, 2, 3].map((key) => (
          <Skeleton key={key} className="h-48" />
        ))}
      </div>
    );
  }

  const data = query.data;
  const from = Date.parse(data.from);
  const to = Date.parse(data.to);
  const rows: ChartRow[] = data.points.map((point) => ({
    time: Date.parse(point.t),
    cpu: round1(point.cpu),
    mem: round1(percentage(point.memUsed, point.memTotal)),
    disk: round1(percentage(point.diskUsed, point.diskTotal)),
    load1: round1(point.load1),
    load5: round1(point.load5),
    load15: round1(point.load15),
  }));
  const gaps = findGaps(
    rows.map((row) => row.time),
    Math.max(data.bucketSeconds, graceSeconds(node.interval_seconds)),
    { from, to },
    data.bucketSeconds,
  );
  const chartRows = withGapBreaks(rows, gaps, (time) => ({
    time,
    cpu: null,
    mem: null,
    disk: null,
    load1: null,
    load5: null,
    load15: null,
  }));
  const values = (key: string) => rows.map((row) => row[key] ?? null);
  const percent = (value: number) => `${metricText(value)}%`;
  const last = data.points.at(-1);
  const memory = percentage(node.memory_used_bytes, node.memory_total_bytes);
  const disk = percentage(node.disk_used_bytes, node.disk_total_bytes);
  const shared = {
    gaps,
    from,
    to,
    range: data.range,
    rows: chartRows,
  };

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
      <MetricChart
        {...shared}
        id="cpu"
        title="CPU"
        value={metricText(node.cpu_percent, "%")}
        level={usageLevel(node.cpu_percent)}
        summary={seriesSummary(values("cpu"), percent)}
        series={[{ key: "cpu", label: "CPU %" }]}
        max={100}
      />
      <MetricChart
        {...shared}
        id="mem"
        title="RAM"
        value={`${formatBytes(node.memory_used_bytes)} / ${formatBytes(node.memory_total_bytes)} · ${metricText(memory, "%")}`}
        level={usageLevel(memory)}
        summary={seriesSummary(values("mem"), percent)}
        series={[{ key: "mem", label: "RAM %" }]}
        max={100}
      />
      <MetricChart
        {...shared}
        id="disk"
        title="Disk"
        value={`${formatBytes(node.disk_used_bytes)} / ${formatBytes(node.disk_total_bytes)} · ${metricText(disk, "%")}`}
        level={usageLevel(disk)}
        summary={seriesSummary(values("disk"), percent)}
        series={[{ key: "disk", label: "Disk %" }]}
        max={100}
      />
      <MetricChart
        {...shared}
        id="load"
        title="Load 1 · 5 · 15"
        value={[last?.load1, last?.load5, last?.load15]
          .map((value) => metricText(value ?? null))
          .join(" · ")}
        summary={seriesSummary(values("load1"), (value) => metricText(value))}
        series={[
          { key: "load1", label: "Load 1m" },
          { key: "load5", label: "Load 5m" },
          { key: "load15", label: "Load 15m" },
        ]}
      />
    </div>
  );
}
