import { useState } from "react";
import { Link } from "react-router";

import { RowMenu } from "@/components/row-menu";
import { Button } from "@/components/ui/button";
import { ActionOutcome, PendingText } from "@/features/services/service-list";
import { useCancelActions } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { isPending } from "@/lib/services";
import { daysLeft, type RemovedMember } from "@/lib/stacks";
import { cn } from "@/lib/utils";

import {
  StackActionDialog,
  type StackActionRequest,
} from "./stack-action-dialog";
import { useSignedAction } from "./use-signed-action";

const ROW =
  "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-0.5 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.2fr)_7.5rem]";

function untilDeleted(item: RemovedMember, seen: number) {
  const days = daysLeft(item.removedAt, seen);
  if (days === 0) return "Deleted permanently soon";
  return `Deleted permanently in ${days} ${days === 1 ? "day" : "days"}`;
}

function Controls({ item }: { item: RemovedMember }) {
  const run = useSignedAction();
  const cancel = useCancelActions();
  const [confirming, setConfirming] = useState<StackActionRequest | null>(null);
  const { action, node, project } = item;
  if (action && isPending(action)) {
    return action.status === "queued" ? (
      <div className="flex justify-end">
        <Button
          variant="ghost"
          size="sm"
          className="h-9 md:h-8"
          onClick={() => cancel.mutate(action.batchId)}
        >
          Cancel
        </Button>
      </div>
    ) : null;
  }
  if (item.blocker) {
    return (
      <p className="text-right text-xs text-muted-foreground">
        {item.blocker === "Not trusted yet" ? (
          <Link
            to="/devices"
            className="underline underline-offset-4 hover:text-foreground"
          >
            {item.blocker}
          </Link>
        ) : (
          item.blocker
        )}
      </p>
    );
  }
  return (
    <div className="flex items-center justify-end gap-1">
      <Button
        variant="outline"
        size="sm"
        className="h-9 md:h-8"
        aria-label={`Restore ${project} on ${node.name}`}
        disabled={run.isPending}
        onClick={() =>
          run.mutate({
            action: "restore",
            targets: [{ nodeId: node.id, kind: "compose", name: project }],
          })
        }
      >
        Restore
      </Button>
      <RowMenu
        label={`${project} on ${node.name} actions`}
        items={[
          {
            label: "Delete permanently",
            destructive: true,
            onSelect: () =>
              setConfirming({
                action: "purge",
                project,
                node,
                directory: item.directory,
              }),
          },
        ]}
      />
      <StackActionDialog
        request={confirming}
        onClose={() => setConfirming(null)}
      />
    </div>
  );
}

export function RemovedList({
  items,
  seen,
  showServer,
}: {
  items: RemovedMember[];
  seen: number;
  showServer: boolean;
}) {
  if (items.length === 0) return null;
  return (
    <section aria-labelledby="removed-stacks">
      <div className="mb-2 flex min-h-8 items-baseline gap-2">
        <h2
          id="removed-stacks"
          className="shrink-0 text-[11px] tracking-wider text-muted-foreground uppercase"
        >
          Removed · {items.length}
        </h2>
        <p className="text-xs text-muted-foreground">
          Kept for 7 days, then deleted with their volumes.
        </p>
      </div>
      <ul className="divide-y rounded-lg border bg-card">
        {items.map((item) => (
          <li
            key={`${item.node.id}|${item.project}`}
            className={cn(ROW, "px-3 py-2.5")}
          >
            <span className="truncate font-medium text-muted-foreground">
              {item.project}
            </span>
            <span className="col-span-2 font-mono text-xs text-muted-foreground md:col-span-1">
              {untilDeleted(item, seen)}
              {showServer && ` · ${item.node.name}`}
            </span>
            <span
              className="col-span-2 min-w-0 font-mono text-xs text-muted-foreground md:col-span-1"
              aria-live="polite"
            >
              {item.action && isPending(item.action) ? (
                <PendingText action={item.action} nodeName={item.node.name} />
              ) : item.action ? (
                <ActionOutcome action={item.action} nodeName={item.node.name} />
              ) : (
                `Removed ${timeAgo(item.removedAt, seen)}`
              )}
            </span>
            <div className="col-start-2 row-start-1 md:col-start-auto md:row-start-auto">
              <Controls item={item} />
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
