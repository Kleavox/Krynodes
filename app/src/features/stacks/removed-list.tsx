import { stampTime } from "@/lib/format";
import type { FleetNode, StackNode } from "@/types";

import { removedItems, VerbMenu } from "./stack-menu";

export function RemovedList({
  entry,
  node,
}: {
  entry: StackNode;
  node: FleetNode | undefined;
}) {
  if (entry.removed.length === 0) return null;
  return (
    <div className="space-y-1">
      <h3 className="text-sm font-medium">Removed</h3>
      <ul className="divide-y rounded-lg border bg-card">
        {entry.removed.map((removed) => (
          <li
            key={removed.project}
            className="flex items-center gap-3 px-4 py-2"
          >
            <div className="min-w-0 flex-1">
              <p className="truncate font-mono text-sm">{removed.project}</p>
              <p className="text-xs text-muted-foreground">
                Removed {stampTime(removed.removedAt)}. Deleted after 7 days.
              </p>
            </div>
            <VerbMenu
              label={`Actions for ${removed.project}`}
              items={removedItems(entry, removed.project)}
              node={node}
            />
          </li>
        ))}
      </ul>
    </div>
  );
}
