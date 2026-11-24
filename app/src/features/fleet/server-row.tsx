import { useState } from "react";
import { toast } from "sonner";

import { RowMenu } from "@/components/row-menu";
import { Badge } from "@/components/ui/badge";
import { ActionDialog, type Ask } from "@/features/actions/action-dialog";
import { DeleteDialog } from "@/features/fleet/delete-dialog";
import { networkApi } from "@/lib/api";
import { stampTime } from "@/lib/format";
import { fleetRow, networkFailure } from "@/lib/network";
import { cn } from "@/lib/utils";
import type { FleetNode } from "@/types";

interface Item {
  label: string;
  ask?: Ask;
  destructive?: boolean;
  erase?: boolean;
  again?: boolean;
}

export function serverActions(node: FleetNode): Item[] {
  const again: Item[] =
    node.request === "rejected"
      ? [{ label: "Ask to Join Again", again: true }]
      : [];
  if (node.kind === "laptop") {
    return node.address === null
      ? [...again, { label: "Delete Laptop", destructive: true, erase: true }]
      : again;
  }
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
    ...again,
  ];
}

const askAgain = (node: FleetNode) =>
  void networkApi.askAgain(node.id).catch((error: unknown) => {
    toast.error(networkFailure(error));
  });

export function ServerRow({
  node,
  names,
}: {
  node: FleetNode;
  names: ReadonlyMap<string, string>;
}) {
  const [asked, setAsked] = useState<Ask | null>(null);
  const [erasing, setErasing] = useState(false);
  const network = fleetRow(node, names);
  const items = serverActions(node);
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
          {node.kind === "laptop" && <Badge variant="outline">Laptop</Badge>}
          {node.request === "requested" && (
            <Badge variant="secondary">Wants to Join</Badge>
          )}
          {node.request === "rejected" && (
            <Badge variant="secondary">Join Rejected</Badge>
          )}
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
        {network && (
          <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
            <span className="font-mono">{network.address}</span>
            <span>{network.path}</span>
            <span>{network.ms}</span>
          </p>
        )}
      </div>
      {items.length > 0 && (
        <RowMenu
          label={`Actions for ${node.name}`}
          items={items.map(({ label, ask, destructive, erase, again }) => ({
            label,
            destructive,
            onSelect: again
              ? () => askAgain(node)
              : erase
                ? () => setErasing(true)
                : ask && (() => setAsked(ask)),
          }))}
        />
      )}
      {asked && (
        <ActionDialog node={node} ask={asked} onClose={() => setAsked(null)} />
      )}
      {erasing && (
        <DeleteDialog node={node} onClose={() => setErasing(false)} />
      )}
    </li>
  );
}
