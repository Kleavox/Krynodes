import { Hourglass } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { Elapsed } from "@/components/node-status";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  useDevices,
  useHistoryAttention,
  useOverview,
  useServices,
} from "@/lib/api";
import { failedLine } from "@/lib/history";
import { activity, hourglassLabel, type ActivityItem } from "@/lib/operations";
import { jobTitle, namesServer, runningJob } from "@/lib/packages";
import { runningText } from "@/lib/services";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import type { AttentionItem, NodeRecord, ServicesResponse } from "@/types";

const ROW =
  "grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-accent";

const HEADING = "px-2 pt-1 pb-1.5 text-[11px] text-muted-foreground";

function Running({
  item,
  now,
  onPick,
}: {
  item: ActivityItem;
  now: number;
  onPick: () => void;
}) {
  const job =
    item.kind === "apt" || namesServer(item.action)
      ? runningJob(item.action, item.nodeName, now)
      : null;
  return (
    <li>
      <Link
        to={
          job
            ? `/nodes/${item.nodeId}/packages`
            : item.action.kind === "network"
              ? "/network"
              : `/nodes/${item.nodeId}`
        }
        onClick={onPick}
        className={ROW}
      >
        <StatusDot tone="warn" pulse className="mt-1.5" />
        <span className="min-w-0">
          <span className="block truncate">
            {job
              ? jobTitle(item.action, item.nodeName)
              : runningText(item.action, item.nodeName)}
          </span>
          <span className="block font-mono text-[11px] text-muted-foreground">
            {item.by} · <Elapsed since={item.at} />
            {item.status === "queued" && " · Waiting"}
          </span>
          {job?.step && (
            <span className="block truncate font-mono text-[11px] text-muted-foreground">
              {job.step}
            </span>
          )}
        </span>
      </Link>
    </li>
  );
}

function Failed({
  item,
  nodes,
  services,
  devices,
  now,
  onPick,
}: {
  item: AttentionItem;
  nodes: NodeRecord[];
  services: ServicesResponse | undefined;
  devices: { id: string; name: string }[] | undefined;
  now: number;
  onPick: () => void;
}) {
  const { nodeId } = item.action;
  const line = failedLine(
    item.action,
    {
      name: nodes.find((node) => node.id === nodeId)?.name,
      stacks: services?.nodes.find((entry) => entry.id === nodeId)?.stacks,
    },
    now,
    devices,
  );
  return (
    <li>
      <Link to="/history" onClick={onPick} className={ROW}>
        <span aria-hidden="true" className="text-destructive">
          ✕
        </span>
        <span className="min-w-0">
          <span className="block truncate">{line.text}</span>
          <span className="block font-mono text-[11px] text-muted-foreground">
            {line.time}
            {line.failure && (
              <span className="text-destructive"> · {line.failure}</span>
            )}
          </span>
        </span>
      </Link>
    </li>
  );
}

export function ActivityMenu() {
  const services = useServices();
  const overview = useOverview();
  const devices = useDevices();
  const attention = useHistoryAttention();
  const [open, setOpen] = useState(false);
  const now = useNow(open ? 5_000 : 30_000);
  const nodes = overview.data?.nodes ?? [];
  const list = activity(
    services.data?.actions ?? [],
    nodes,
    now,
    devices.data?.devices,
  );
  const failures = attention.data?.items ?? [];
  const running = list.length;
  const label = hourglassLabel(running, failures.length);
  const first = label.parts[0]?.tone;
  const close = () => setOpen(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          aria-label={label.aria}
          className={cn(
            first === "warn" && "border-warning/40",
            first === "bad" && "border-destructive/40",
          )}
        >
          {label.parts.length > 0 ? (
            label.parts.map((part) => (
              <span
                key={part.tone}
                className={cn(
                  "inline-flex items-center gap-1.5 font-mono text-xs",
                  part.tone === "bad" && "text-destructive",
                )}
              >
                <StatusDot tone={part.tone} pulse={part.tone === "warn"} />
                {part.count}
                <span className="hidden md:inline"> {part.word}</span>
              </span>
            ))
          ) : (
            <Hourglass aria-hidden="true" />
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        className="max-h-[70dvh] w-[min(22rem,calc(100vw-2rem))] overflow-y-auto p-2"
      >
        <h2 className={HEADING}>In Progress</h2>
        {running === 0 ? (
          <p className="px-2 pb-2 text-sm text-muted-foreground">
            Nothing is running.
          </p>
        ) : (
          <ul>
            {list.map((item) => (
              <Running key={item.id} item={item} now={now} onPick={close} />
            ))}
          </ul>
        )}
        {failures.length > 0 && (
          <>
            <h2 className={cn(HEADING, "mt-1.5")}>Failed, Not Fixed</h2>
            <ul>
              {failures.map((item) => (
                <Failed
                  key={item.action.id}
                  item={item}
                  nodes={nodes}
                  services={services.data}
                  devices={devices.data?.devices}
                  now={now}
                  onPick={close}
                />
              ))}
            </ul>
          </>
        )}
        <Link
          to="/history"
          onClick={close}
          className="mt-1 block border-t px-2 pt-2.5 pb-1 text-sm text-muted-foreground hover:text-foreground"
        >
          View History
        </Link>
      </PopoverContent>
    </Popover>
  );
}
