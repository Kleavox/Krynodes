import { Link } from "react-router";

import { clockTime, titleCase } from "@/lib/format";
import {
  heartbeatSummary,
  slotTip,
  uptimeOf,
  type BarTone,
  type SlotState,
  type WorkSpan,
} from "@/lib/series";
import { cn } from "@/lib/utils";

const SLOT_CLASS: Record<SlotState, string> = {
  received: "bg-success/85",
  missed: "bg-destructive",
  pending: "bg-border",
  none: "bg-border/50",
  work: "bg-primary/80",
  routine: "bg-info/80",
  offline: "bg-muted-foreground/70",
  quarantined: "bg-muted-foreground/35",
};

const BAR_CLASS: Record<BarTone, string> = {
  up: "bg-success/85",
  down: "bg-destructive",
  brief: "bg-warning",
  missed: "bg-destructive",
  work: "bg-primary/80",
  routine: "bg-info/80",
  offline: "bg-muted-foreground/70",
  quarantined: "bg-muted-foreground/35",
  empty: "bg-border",
};

const SLOT_LABEL: Record<SlotState, string> = {
  received: "Reported",
  missed: "No Report",
  pending: "Waiting",
  none: "Not Enrolled",
  work: "By You",
  routine: "Routine Restart",
  offline: "Offline",
  quarantined: "Quarantined",
};

export function ReportStrip({
  states,
  starts,
  labels,
  className,
}: {
  states: SlotState[];
  starts?: number[];
  labels?: (string | undefined)[];
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
              : `${clockTime(starts[index])} · ${
                  state === "work" && labels?.[index]
                    ? titleCase(`${labels[index]} by you`)
                    : SLOT_LABEL[state]
                }`
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

export interface StripSlot {
  start: number;
  tone: BarTone;
  sample: { latencyMs: number | null } | null;
  work: WorkSpan | undefined;
  incident: { id: string } | undefined;
}

export function HeartbeatStrip({
  slots,
  windowSeconds,
  className,
}: {
  slots: StripSlot[];
  windowSeconds: number;
  className?: string;
}) {
  const summary = heartbeatSummary(
    uptimeOf(slots),
    spanText(slots.length * windowSeconds),
  );
  return (
    <div
      role="group"
      aria-label={summary}
      className={cn("flex h-[18px] min-w-0 gap-0.5", className)}
    >
      {slots.map((slot) => {
        const tip = slotTip(slot, slot.tone, clockTime);
        const tone = cn("bar-tip flex-1 rounded-[2px]", BAR_CLASS[slot.tone]);
        return slot.incident ? (
          <Link
            key={slot.start}
            to={`/incidents/${slot.incident.id}`}
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
