import { Badge } from "@/components/ui/badge";
import { stampTime } from "@/lib/format";
import { checkLabel } from "@/lib/stacks";
import { cn } from "@/lib/utils";
import type { CheckView } from "@/types";

import { CheckMenu } from "./check-menu";

const TONE = {
  Up: "bg-success",
  Down: "bg-destructive",
  Paused: "bg-muted-foreground",
  "--": "bg-border",
} as const;

export function CheckList({ checks }: { checks: CheckView[] }) {
  return (
    <ul className="divide-y rounded-lg border bg-card">
      {checks.map((check) => {
        const label = checkLabel(check);
        return (
          <li key={check.id} className="flex items-center gap-3 px-4 py-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className="truncate font-medium">{check.name}</span>
                <span className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[11px]">
                  <span
                    aria-hidden="true"
                    className={cn("size-2 shrink-0 rounded-full", TONE[label])}
                  />
                  {label}
                </span>
                {check.public && <Badge variant="outline">Public</Badge>}
              </div>
              <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                <span>{check.nodeName}</span>
                <span className="font-mono">{check.container}</span>
                <span>
                  {!check.online
                    ? `${check.nodeName} is offline`
                    : label === "--" || !check.since
                      ? "Since --"
                      : `Since ${stampTime(check.since)}`}
                </span>
              </p>
              {check.note && (
                <p className="mt-1 text-xs text-muted-foreground">
                  {check.note}
                </p>
              )}
            </div>
            <CheckMenu check={check} />
          </li>
        );
      })}
    </ul>
  );
}
