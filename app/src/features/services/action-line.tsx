import { useDevices, useServices } from "@/lib/api";
import { actionLine } from "@/lib/history";
import { isPending } from "@/lib/services";
import { cn } from "@/lib/utils";
import type { ActionRecord } from "@/types";

import { PendingText } from "./service-list";

export function ActionLine({
  action,
  nodeName = "",
  showServer = false,
  now,
}: {
  action: ActionRecord;
  nodeName?: string;
  showServer?: boolean;
  now?: number;
}) {
  const devices = useDevices().data?.devices;
  const stacks = useServices().data?.nodes.find(
    (node) => node.id === action.nodeId,
  )?.stacks;
  const line = actionLine(action, {
    nodeName,
    showServer,
    devices,
    stacks,
    now,
  });
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-1 px-3 py-2.5 text-sm sm:grid-cols-[auto_minmax(0,1fr)_auto]">
      <span className="font-mono text-xs leading-5 text-muted-foreground">
        {line.time}
      </span>
      <span className="min-w-0 break-words">
        {line.mark && (
          <span
            aria-hidden
            className={cn(
              "mr-1",
              line.mark === "✓" ? "text-success" : "text-destructive",
            )}
          >
            {line.mark}
          </span>
        )}
        {line.text}
        {line.server && (
          <span className="text-muted-foreground"> on {line.server}</span>
        )}
      </span>
      <span className="col-start-2 flex min-w-0 flex-wrap items-baseline gap-x-1 font-mono text-xs text-muted-foreground sm:col-start-auto sm:justify-end">
        {isPending(action) ? (
          <PendingText action={action} nodeName={nodeName} />
        ) : (
          <span>{line.device}</span>
        )}
        {line.duration && <span>· {line.duration}</span>}
      </span>
      {line.failure &&
        (action.output ? (
          <details className="col-start-2 min-w-0 sm:col-span-2">
            <summary className="cursor-pointer truncate font-mono text-xs text-destructive">
              {line.failure}
            </summary>
            <pre className="mt-1 max-h-40 overflow-auto rounded border bg-background p-2 text-[11px] whitespace-pre-wrap">
              {action.output}
            </pre>
          </details>
        ) : (
          <span className="col-start-2 font-mono text-xs text-destructive sm:col-span-2">
            {line.failure}
          </span>
        ))}
    </li>
  );
}
