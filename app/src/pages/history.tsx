import { useQuery } from "@tanstack/react-query";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useFleet } from "@/features/fleet/use-fleet";
import { useNetworkChanges } from "@/features/network/use-network";
import { byNewest, stampTime } from "@/lib/format";
import { apiFetch, errorMessage } from "@/lib/http";
import { queryKeys } from "@/lib/query-client";
import { cn } from "@/lib/utils";
import type { ActionRow, NetworkChange } from "@/types";

const PAGE = 50;

const STATUS: Record<ActionRow["status"], string> = {
  sent: "Sent",
  running: "Running",
  done: "Done",
  failed: "Failed",
};

export function HistoryPage() {
  const actions = useQuery({
    queryKey: queryKeys.actions,
    queryFn: () => apiFetch<ActionRow[]>(`/api/actions?limit=${PAGE}`),
  });
  const fleet = useFleet();
  const changes = useNetworkChanges();
  const names = new Map(fleet.data?.map((node) => [node.id, node.name]));
  const rows = byNewest<
    { at: string; action: ActionRow } | { at: string; change: NetworkChange }
  >(
    [
      ...(actions.data ?? []).map((action) => ({
        at: action.createdAt,
        action,
      })),
      ...(changes.data ?? []).map((change) => ({ at: change.at, change })),
    ],
    (row) => row.at,
  );
  return (
    <>
      <PageHeader title="History" />
      {changes.isError && (
        <p role="alert" className="mb-3 text-sm text-destructive">
          Network changes can't load: {errorMessage(changes.error)}
        </p>
      )}
      {actions.data ? (
        rows.length === 0 ? (
          <EmptyState
            title="No actions yet"
            body="Actions you sign to your servers appear here."
          />
        ) : (
          <>
            <ul className="divide-y rounded-lg border bg-card">
              {rows.map((entry) => {
                if ("change" in entry) {
                  const { change } = entry;
                  return (
                    <li key={`change-${change.id}`} className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="font-medium">Network</span>
                        <span>{change.change}</span>
                      </div>
                      <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                        <span>{stampTime(change.at)}</span>
                        <span>{change.detail ?? "--"}</span>
                      </p>
                    </li>
                  );
                }
                const row = entry.action;
                return (
                  <li key={row.id} className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="font-medium">
                        {names.get(row.nodeId) ?? "--"}
                      </span>
                      <span>{row.title}</span>
                      <span
                        className={cn(
                          "ml-auto rounded-full border px-2 py-0.5 font-mono text-[11px]",
                          row.status === "failed" && "text-destructive",
                        )}
                      >
                        {STATUS[row.status]}
                      </span>
                    </div>
                    <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                      <span>{stampTime(row.createdAt)}</span>
                      <span>{row.message ?? "--"}</span>
                    </p>
                  </li>
                );
              })}
            </ul>
            {(actions.data.length === PAGE ||
              changes.data?.length === PAGE) && (
              <p className="mt-3 text-xs text-muted-foreground">
                Showing the newest {PAGE} actions and the newest {PAGE} network
                changes.
              </p>
            )}
          </>
        )
      ) : actions.isError ? (
        <EmptyState
          title="The history can't load"
          body={errorMessage(actions.error)}
          action={<Button onClick={() => void actions.refetch()}>Retry</Button>}
        />
      ) : (
        <div role="status" aria-label="Loading history" className="space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      )}
    </>
  );
}
