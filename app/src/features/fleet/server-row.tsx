import { useState } from "react";

import { RowMenu } from "@/components/row-menu";
import { ActionDialog, type Ask } from "@/features/actions/action-dialog";
import { DeleteDialog } from "@/features/fleet/delete-dialog";
import { stampTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { FleetNode } from "@/types";

export function serverActions(
  node: FleetNode,
): { label: string; ask?: Ask; destructive?: boolean; erase?: boolean }[] {
  return [
    {
      label: "Update Agent",
      ask: node.update
        ? {
            kind: "agent",
            action: "update",
            title: `Update Agent to ${node.update}`,
            args: { version: node.update },
            heading: `Update ${node.name}`,
            body: `${node.name} updates its agent to ${node.update} and restarts it.`,
            confirm: "Update",
          }
        : undefined,
    },
    {
      label: "Restart Server",
      ask: {
        kind: "host",
        action: "restart",
        title: "Restart Server",
        heading: `Restart ${node.name}?`,
        body: `${node.name} reboots. What runs on it stops until it is back.`,
        confirm: "Restart",
      },
    },
    {
      label: "Remove Server",
      destructive: true,
      ask: {
        kind: "agent",
        action: "remove",
        title: "Remove Server",
        heading: `Remove ${node.name}?`,
        body: `Krynodes takes its agent off ${node.name}. The server keeps running.`,
        confirm: "Remove",
        destructive: true,
      },
    },
    ...(node.online
      ? []
      : [{ label: "Delete Server", destructive: true, erase: true }]),
  ];
}

export function ServerRow({ node }: { node: FleetNode }) {
  const [asked, setAsked] = useState<Ask | null>(null);
  const [erasing, setErasing] = useState(false);
  return (
    <li
      id={`server-${node.id}`}
      className="flex items-center gap-3 px-4 py-3 target:bg-primary-subtle"
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="truncate font-medium">{node.name}</span>
          <span className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[11px]">
            <span
              aria-hidden="true"
              className={cn(
                "size-2 shrink-0 rounded-full",
                node.online ? "bg-success" : "bg-destructive",
              )}
            />
            {node.online ? "Online" : "Offline"}
          </span>
        </div>
        <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
          <span>
            {node.os ?? "--"} · {node.arch ?? "--"}
          </span>
          <span>Agent {node.version ?? "--"}</span>
          {node.update && (
            <span className="text-primary-text">Update to {node.update}</span>
          )}
          {!node.online && (
            <span>
              Last seen {node.lastSeenAt ? stampTime(node.lastSeenAt) : "--"}
            </span>
          )}
        </p>
      </div>
      <RowMenu
        label={`Actions for ${node.name}`}
        items={serverActions(node).map(
          ({ label, ask, destructive, erase }) => ({
            label,
            destructive,
            onSelect: erase
              ? () => setErasing(true)
              : ask && (() => setAsked(ask)),
          }),
        )}
      />
      {asked && (
        <ActionDialog node={node} ask={asked} onClose={() => setAsked(null)} />
      )}
      {erasing && (
        <DeleteDialog node={node} onClose={() => setErasing(false)} />
      )}
    </li>
  );
}
