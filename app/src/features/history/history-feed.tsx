import { Link } from "react-router";

import { ActionLine } from "@/features/services/action-line";
import { clockTime } from "@/lib/format";
import { incidentText, type dayGroups } from "@/lib/history";
import { cn } from "@/lib/utils";
import type { HistoryEntry } from "@/types";

function IncidentLine({
  entry,
  showServer,
}: {
  entry: Extract<HistoryEntry, { type: "incident" }>;
  showServer: boolean;
}) {
  const resolved = entry.event === "resolved";
  const { incident } = entry;
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-1 px-3 py-2.5 text-sm sm:grid-cols-[auto_minmax(0,1fr)_auto]">
      <span className="font-mono text-xs leading-5 text-muted-foreground">
        {clockTime(entry.at)}
      </span>
      <span className="min-w-0 break-words">
        <span
          aria-hidden
          className={cn("mr-1", resolved ? "text-success" : "text-destructive")}
        >
          {resolved ? "✓" : "!"}
        </span>
        {incidentText(entry)}
        {showServer && (
          <span className="text-muted-foreground"> on {incident.nodeName}</span>
        )}
      </span>
      <Link
        to={`/incidents/${incident.id}`}
        className="col-start-2 font-mono text-xs text-primary underline-offset-4 hover:underline sm:col-start-auto sm:text-right"
      >
        Incident →
      </Link>
      {incident.summary && (
        <span className="col-start-2 font-mono text-xs break-words text-muted-foreground sm:col-span-2">
          {incident.summary}
        </span>
      )}
    </li>
  );
}

export function HistoryFeed({
  groups,
  names,
  showServer,
}: {
  groups: ReturnType<typeof dayGroups>;
  names: Map<string, string>;
  showServer: boolean;
}) {
  return (
    <ul className="divide-y rounded-lg border bg-card">
      {groups.flatMap((group) => [
        <li
          key={`day-${group.label}`}
          className="flex flex-wrap justify-between gap-x-3 bg-muted/40 px-3 py-1 font-mono text-[11px] tracking-wider text-muted-foreground"
        >
          <span className="uppercase">{group.label}</span>
          <span>{group.counts}</span>
        </li>,
        ...group.entries.map((entry) =>
          entry.type === "action" ? (
            <ActionLine
              key={`action-${entry.action.id}`}
              action={entry.action}
              nodeName={names.get(entry.action.nodeId) ?? ""}
              showServer={showServer}
            />
          ) : (
            <IncidentLine
              key={`${entry.incident.id}-${entry.event}`}
              entry={entry}
              showServer={showServer}
            />
          ),
        ),
      ])}
    </ul>
  );
}
