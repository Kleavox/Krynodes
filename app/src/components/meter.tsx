import { metricText } from "@/lib/format";
import { usageLevel, type UsageLevel } from "@/lib/health";
import { cn } from "@/lib/utils";

const FILL: Record<UsageLevel, string> = {
  ok: "bg-primary",
  warn: "bg-warning",
  critical: "bg-destructive",
};

export const LEVEL_TEXT: Record<UsageLevel, string> = {
  ok: "text-foreground",
  warn: "text-warning",
  critical: "text-destructive",
};

export function Meter({
  label,
  value,
  stale = false,
  hideLabel = false,
}: {
  label: string;
  value: number | null;
  stale?: boolean;
  hideLabel?: boolean;
}) {
  const level = stale ? null : usageLevel(value);
  const width = value === null ? 0 : Math.min(100, Math.max(0, value));
  return (
    <div className={cn("min-w-0", stale && "opacity-50")}>
      <div className="flex items-baseline justify-between gap-2 font-mono text-[11px]">
        <span className={cn("text-muted-foreground", hideLabel && "sr-only")}>
          {label}
        </span>
        <span
          className={cn("font-medium", level ? LEVEL_TEXT[level] : undefined)}
        >
          {metricText(value, "%")}
        </span>
      </div>
      <div
        aria-hidden="true"
        className="mt-1 h-1.5 overflow-hidden rounded-full bg-accent"
      >
        <div
          className={cn(
            "h-full rounded-full",
            level ? FILL[level] : "bg-muted-foreground",
          )}
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}
