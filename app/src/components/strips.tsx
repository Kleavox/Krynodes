import { Link } from "react-router";

import { clockTime } from "@/lib/format";
import {
  barTone,
  heartbeatSummary,
  incidentDuring,
  layoutReportSlots,
  overlaps,
  slotTip,
  type BarTone,
  type SlotState,
  type Span,
} from "@/lib/series";
import { cn } from "@/lib/utils";
import type { CheckResult, Incident } from "@/types";

const SLOT_CLASS: Record<SlotState, string> = {
  received: "bg-success/85",
  missed: "bg-destructive",
  pending: "bg-border",
  none: "bg-border/50",
  maintenance: "bg-primary/40",
};

const BAR_CLASS: Record<BarTone, string> = {
  up: "bg-success/85",
  down: "bg-destructive",
  brief: "bg-warning",
  missed: "bg-destructive",
  maintenance: "bg-primary/40",
  empty: "bg-border",
};

const SLOT_LABEL: Record<SlotState, string> = {
  received: "reported",
  missed: "no report",
  pending: "waiting",
  none: "not enrolled",
  maintenance: "maintenance",
};

export function ReportStrip({
  states,
  starts,
  className,
}: {
  states: SlotState[];
  starts?: number[];
  className?: string;
}) {
  const received = states.filter((state) => state === "received").length;
  const missed = states.filter((state) => state === "missed").length;
  return (
    <div
      role="img"
      aria-label={`${received} windows with reports, ${missed} missed, in the last ${states.length} history windows`}
      className={cn("flex h-3.5 gap-0.5", className)}
    >
      {states.map((state, index) => (
        <span
          key={index}
          data-tip={
            starts?.[index] === undefined
              ? undefined
              : `${clockTime(starts[index])} · ${SLOT_LABEL[state]}`
          }
          className={cn("bar-tip flex-1 rounded-[2px]", SLOT_CLASS[state])}
        />
      ))}
    </div>
  );
}

function spanText(seconds: number): string {
  return seconds % 3600 === 0
    ? `${seconds / 3600} hours`
    : `${seconds / 60} minutes`;
}

export function HeartbeatStrip({
  results,
  incidents,
  since,
  windowSeconds,
  graceSeconds,
  settleSeconds = 0,
  now,
  asOf,
  count = 48,
  maintenance = [],
  className,
}: {
  results: CheckResult[] | undefined;
  incidents: Pick<Incident, "id" | "started_at" | "resolved_at">[];
  since: number | null;
  windowSeconds: number;
  graceSeconds: number;
  settleSeconds?: number;
  now: number;
  asOf: number | undefined;
  count?: number;
  maintenance?: Span[];
  className?: string;
}) {
  const laid = layoutReportSlots({
    slots: results ?? [],
    slotSeconds: windowSeconds,
    graceSeconds,
    settleSeconds,
    since,
    now,
    asOf,
    count,
    maintenance,
  });
  const summary = heartbeatSummary(
    laid.map((slot) => slot.sample?.status ?? null),
    spanText(count * windowSeconds),
  );
  return (
    <div
      role="group"
      aria-label={summary}
      className={cn("flex h-[18px] min-w-0 gap-0.5", className)}
    >
      {laid.map((slot) => {
        const down = slot.sample?.status === "DOWN";
        const incident = down
          ? incidentDuring(slot.start, windowSeconds * 1000, incidents)
          : undefined;
        const planned =
          slot.state === "maintenance" ||
          overlaps(maintenance, slot.start, windowSeconds * 1000);
        const tip = slotTip(
          slot.start,
          slot.sample,
          down && !incident,
          clockTime,
          planned && !incident,
        );
        const tone = cn(
          "bar-tip flex-1 rounded-[2px]",
          BAR_CLASS[
            barTone(
              slot.state,
              slot.sample?.status ?? null,
              Boolean(incident),
              planned,
            )
          ],
        );
        return incident ? (
          <Link
            key={slot.start}
            to={`/incidents/${incident.id}`}
            data-tip={tip}
            aria-label={`${tip}. Open the incident`}
            className={tone}
          />
        ) : (
          <span key={slot.start} data-tip={tip} className={tone} />
        );
      })}
    </div>
  );
}
