import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ActionRow } from "@/features/services/service-list";
import { useHistory, useOverview } from "@/lib/api";
import { byDay } from "@/lib/history";

const ALL = "all";

export function HistoryPage() {
  const overview = useOverview();
  const [node, setNode] = useState(ALL);
  const history = useHistory(node === ALL ? "" : node);
  const nodes = (overview.data?.nodes ?? []).filter(
    (entry) => entry.enrolled_at !== null,
  );
  const names = new Map(nodes.map((entry) => [entry.id, entry.name]));
  const actions = (history.data?.pages ?? [])
    .flatMap((page) => page.actions)
    .filter((action) => names.has(action.nodeId));
  const groups = byDay(actions, Date.now());

  return (
    <>
      <PageHeader
        title="History"
        meta={
          <span className="font-mono text-xs text-muted-foreground">
            Kept for 90 days
          </span>
        }
        actions={
          <Select value={node} onValueChange={setNode}>
            <SelectTrigger aria-label="Server" className="h-9 w-44 md:h-8">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All servers</SelectItem>
              {nodes.map((entry) => (
                <SelectItem key={entry.id} value={entry.id}>
                  {entry.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      />
      {groups.length === 0 ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          {history.isPending
            ? "Loading history…"
            : node === ALL
              ? "No actions in the last 90 days."
              : `No actions on ${names.get(node) ?? "this server"} in the last 90 days.`}
        </p>
      ) : (
        groups.map((group) => (
          <section key={group.label} aria-label={group.label} className="mb-5">
            <h2 className="mb-2 text-xs font-medium text-muted-foreground">
              {group.label}
            </h2>
            <ul className="divide-y rounded-lg border bg-card">
              {group.actions.map((action) => (
                <ActionRow
                  key={action.id}
                  action={action}
                  nodeName={names.get(action.nodeId)!}
                  where={node === ALL}
                />
              ))}
            </ul>
          </section>
        ))
      )}
      {history.hasNextPage && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            size="sm"
            className="h-9 md:h-8"
            disabled={history.isFetchingNextPage}
            onClick={() => void history.fetchNextPage()}
          >
            {history.isFetchingNextPage ? "Loading…" : "Load older"}
          </Button>
        </div>
      )}
    </>
  );
}
