import type { ReactNode } from "react";

import { capitalize, type CheckDisplay, type NodeState } from "@/lib/format";
import { cn } from "@/lib/utils";

type Tone = "ok" | "bad" | "warn" | "idle";

const TONE: Record<Tone, string> = {
  ok: "bg-success",
  bad: "bg-destructive",
  warn: "bg-warning",
  idle: "bg-muted-foreground",
};

export function nodeTone(state: NodeState): Tone {
  if (state === "online") return "ok";
  if (state === "offline") return "bad";
  if (state === "pending") return "warn";
  return "idle";
}

export function checkTone(status: CheckDisplay): Tone {
  if (status === "UP") return "ok";
  if (status === "DOWN") return "bad";
  return "idle";
}

export function StatusDot({
  tone,
  pulse = false,
  className,
}: {
  tone: Tone;
  pulse?: boolean;
  className?: string;
}) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "inline-block size-2 shrink-0 rounded-full transition-colors duration-500",
        TONE[tone],
        pulse && "motion-safe:animate-pulse",
        className,
      )}
    />
  );
}

export function SmallLabel({
  children,
  title,
}: {
  children: ReactNode;
  title?: string;
}) {
  return (
    <span
      title={title}
      className="shrink-0 rounded border px-1 font-mono text-[10px] leading-4 text-muted-foreground"
    >
      {children}
    </span>
  );
}

export function StatusChip({
  tone,
  label,
  detail,
  pulse = false,
}: {
  tone: Tone;
  label: string;
  detail?: ReactNode;
  pulse?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[11px] whitespace-nowrap text-muted-foreground transition-colors duration-500",
        pulse && "border-warning/40",
      )}
    >
      <StatusDot tone={tone} pulse={pulse} />
      <span className="text-foreground">{capitalize(label)}</span>
      {detail && <span>· {detail}</span>}
    </span>
  );
}
