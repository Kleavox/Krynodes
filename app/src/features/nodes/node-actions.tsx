import { useState } from "react";
import { ChevronDown, Ellipsis } from "lucide-react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { CheckDialog } from "@/features/checks/check-dialog";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import {
  useOverview,
  useRefreshServices,
  useRequestAgentUpdate,
  useServices,
} from "@/lib/api";
import { agentState } from "@/lib/agent";
import { canRestartServer, orchestrationReady } from "@/lib/devices";
import { serverOperation } from "@/lib/operations";
import type { NodeRecord } from "@/types";

import { DeleteNodeDialog } from "./delete-node-dialog";
import { EditNodeDialog } from "./edit-node-dialog";

type OpenDialog =
  "add-check" | "edit" | "delete" | "restart" | "lockdown" | "unlock" | null;

export function NodeActions({
  node,
  onDeleted,
  restart = false,
  onRestartClosed,
  compact = false,
}: {
  node: NodeRecord;
  onDeleted?: () => void;
  restart?: boolean;
  onRestartClosed?: () => void;
  compact?: boolean;
}) {
  const [dialog, setDialog] = useState<OpenDialog>(restart ? "restart" : null);
  const reboot = useSignedAction(false);
  const lock = useSignedAction(false);
  const refresh = useRefreshServices();
  const update = useRequestAgentUpdate();
  const services = useServices();
  const release = useOverview().data?.agentRelease;
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const trust = entry?.trust ?? null;
  const locked = entry?.security?.lockdown ?? false;
  const now = Date.now();
  const busy =
    serverOperation(node, services.data?.actions ?? [], now) !== null;
  const restartable = canRestartServer(node, trust) && !busy;
  const lockable =
    orchestrationReady(node) && trust !== null && !!entry?.security && !busy;
  const updatable =
    !busy &&
    release?.version &&
    ["available", "failed"].includes(agentState(node, release.version, now));

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          {compact ? (
            <Button
              variant="ghost"
              size="icon"
              className="size-9 text-muted-foreground md:size-8"
              aria-label={`Actions for ${node.name}`}
            >
              <Ellipsis aria-hidden="true" />
            </Button>
          ) : (
            <Button variant="outline" size="sm">
              Actions
              <ChevronDown aria-hidden="true" />
            </Button>
          )}
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => refresh.mutate([node.id])}>
            Refresh services
          </DropdownMenuItem>
          {updatable && (
            <DropdownMenuItem onSelect={() => update.mutate(node.id)}>
              Update agent to {release.version}
            </DropdownMenuItem>
          )}
          <DropdownMenuItem onSelect={() => setDialog("add-check")}>
            Add check
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setDialog("edit")}>
            Rename node
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          {lockable && (
            <DropdownMenuItem
              variant={locked ? "default" : "destructive"}
              onSelect={() => setDialog(locked ? "unlock" : "lockdown")}
            >
              {locked ? "Unlock server" : "Lock down server"}
            </DropdownMenuItem>
          )}
          {restartable && (
            <DropdownMenuItem
              variant="destructive"
              onSelect={() => setDialog("restart")}
            >
              Restart server
            </DropdownMenuItem>
          )}
          <DropdownMenuItem
            variant="destructive"
            onSelect={() => setDialog("delete")}
          >
            Delete node
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <CheckDialog
        open={dialog === "add-check"}
        onOpenChange={(open) => setDialog(open ? "add-check" : null)}
        nodeId={node.id}
      />

      <EditNodeDialog
        key={`${node.name}:${node.interval_seconds}`}
        node={node}
        open={dialog === "edit"}
        onOpenChange={(open) => setDialog(open ? "edit" : null)}
      />

      <ConfirmDialog
        open={dialog === "restart" && canRestartServer(node, trust)}
        onOpenChange={(open) => {
          setDialog(open ? "restart" : null);
          if (!open) onRestartClosed?.();
        }}
        title={`Restart ${node.name}?`}
        description="The server goes offline for a minute or two. Everyone sees it as restarting until it reports again, and its checks open no incidents meanwhile. Services that don't start on boot stay stopped."
        confirmLabel="Restart server"
        mutation={reboot}
        variables={{
          action: "reboot",
          targets: [{ nodeId: node.id, kind: "host", name: "server" }],
        }}
      />

      <ConfirmDialog
        open={dialog === "lockdown" || dialog === "unlock"}
        onOpenChange={(open) => setDialog(open ? dialog : null)}
        title={
          dialog === "unlock"
            ? `Unlock ${node.name}?`
            : `Lock down ${node.name}?`
        }
        description={
          dialog === "unlock"
            ? "The containers the lock down stopped start again, its web addresses come back, and SSH goes back to how it was."
            : "Containers that publish ports to the internet stop, its web addresses go offline, and SSH stops accepting passwords when a key is set up. Unlock brings it all back."
        }
        confirmLabel={dialog === "unlock" ? "Unlock server" : "Lock down"}
        mutation={lock}
        variables={{
          action: dialog === "unlock" ? "unlock" : "lockdown",
          targets: [{ nodeId: node.id, kind: "host", name: "server" }],
        }}
      />

      <DeleteNodeDialog
        node={node}
        open={dialog === "delete"}
        onOpenChange={(open) => setDialog(open ? "delete" : null)}
        onDeleted={onDeleted}
      />
    </>
  );
}
