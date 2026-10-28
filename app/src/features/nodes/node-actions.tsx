import { useState } from "react";
import { ChevronDown, Ellipsis } from "lucide-react";
import { Link } from "react-router";

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
import { agentCurrent, canRestartServer } from "@/lib/devices";
import { serverOperation } from "@/lib/operations";
import { actionsFor } from "@/lib/quarantine";
import type { NodeRecord } from "@/types";

import { AdminUserDialog } from "./admin-user-dialog";
import { DeleteNodeDialog } from "./delete-node-dialog";
import { EditNodeDialog } from "./edit-node-dialog";
import { InstallDockerDialog } from "./install-docker-dialog";
import { ReleaseDialog } from "./release-dialog";

type OpenDialog =
  | "add-check"
  | "edit"
  | "delete"
  | "restart"
  | "lockdown"
  | "unlock"
  | "docker"
  | "release"
  | "admin"
  | null;

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
  const limited = actionsFor(node);
  const services = useServices();
  const release = useOverview().data?.agentRelease;
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const trust = entry?.trust ?? null;
  const locked = entry?.security?.lockdown ?? false;
  const now = Date.now();
  const operation = serverOperation(node, services.data?.actions ?? [], now);
  const busy =
    operation !== null && !(operation.kind === "deleting" && operation.stopped);
  const restartable = canRestartServer(node, trust) && !busy;
  const lockable =
    agentCurrent(node) && trust !== null && !!entry?.security && !busy;
  const platform = entry?.security?.platform;
  const dockerless =
    entry?.docker === "missing" || entry?.docker === "no-compose";
  const installable =
    !!platform?.family && dockerless && trust !== null && !busy;
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
        {limited ? (
          <DropdownMenuContent align="end">
            {limited.map((label) =>
              label === "Refresh Services" ? (
                <DropdownMenuItem
                  key={label}
                  onSelect={() => refresh.mutate([node.id])}
                >
                  {label}
                </DropdownMenuItem>
              ) : label === "Release Server" ? (
                <DropdownMenuItem
                  key={label}
                  onSelect={() => setDialog("release")}
                >
                  {label}
                </DropdownMenuItem>
              ) : label === "Remove from Network" ? (
                <DropdownMenuItem key={label} asChild>
                  <Link to={`/network?remove=${node.id}`}>{label}</Link>
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem
                  key={label}
                  variant="destructive"
                  onSelect={() => setDialog("delete")}
                >
                  {label}
                </DropdownMenuItem>
              ),
            )}
          </DropdownMenuContent>
        ) : (
          <DropdownMenuContent align="end">
            <DropdownMenuItem onSelect={() => refresh.mutate([node.id])}>
              Refresh Services
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to={`/nodes/${node.id}/packages`}>Packages</Link>
            </DropdownMenuItem>
            {updatable && (
              <DropdownMenuItem onSelect={() => update.mutate(node.id)}>
                Update Agent to {release.version}
              </DropdownMenuItem>
            )}
            <DropdownMenuItem onSelect={() => setDialog("add-check")}>
              Add Check
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setDialog("edit")}>
              Rename Node
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {installable && (
              <DropdownMenuItem onSelect={() => setDialog("docker")}>
                {entry?.docker === "no-compose"
                  ? "Add Compose"
                  : "Install Docker"}
              </DropdownMenuItem>
            )}
            {trust !== null && !busy && (
              <DropdownMenuItem onSelect={() => setDialog("admin")}>
                Add Admin User
              </DropdownMenuItem>
            )}
            {lockable && (
              <DropdownMenuItem
                variant={locked ? "default" : "destructive"}
                onSelect={() => setDialog(locked ? "unlock" : "lockdown")}
              >
                {locked ? "Unlock Server" : "Lock Down Server"}
              </DropdownMenuItem>
            )}
            {restartable && (
              <DropdownMenuItem
                variant="destructive"
                onSelect={() => setDialog("restart")}
              >
                Restart Server
              </DropdownMenuItem>
            )}
            <DropdownMenuItem
              variant="destructive"
              onSelect={() => setDialog("delete")}
            >
              Delete Node
            </DropdownMenuItem>
          </DropdownMenuContent>
        )}
      </DropdownMenu>

      {limited && (
        <ReleaseDialog
          node={node}
          open={dialog === "release"}
          onOpenChange={(open) => setDialog(open ? "release" : null)}
        />
      )}

      {!limited && (
        <AdminUserDialog
          node={node}
          open={dialog === "admin"}
          onOpenChange={(open) => setDialog(open ? "admin" : null)}
        />
      )}
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
        open={dialog === "restart" && !limited && canRestartServer(node, trust)}
        onOpenChange={(open) => {
          setDialog(open ? "restart" : null);
          if (!open) onRestartClosed?.();
        }}
        title={`Restart ${node.name}?`}
        description="The server goes offline for a minute or two. Everyone sees it as restarting until it reports again, and its checks open no incidents meanwhile. Services that don't start on boot stay stopped."
        confirmLabel="Restart Server"
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
            : "Containers that publish ports to the internet stop and stay stopped after a restart, its web addresses go offline, and SSH stops accepting passwords when a key is set up. Until you unlock it, nothing starts there: deploys, starts, restarts and new stacks are refused. Unlock brings it all back."
        }
        confirmLabel={dialog === "unlock" ? "Unlock Server" : "Lock Down"}
        mutation={lock}
        variables={{
          action: dialog === "unlock" ? "unlock" : "lockdown",
          targets: [{ nodeId: node.id, kind: "host", name: "server" }],
        }}
      />

      {platform && (
        <InstallDockerDialog
          node={node}
          platform={platform}
          composeOnly={entry?.docker === "no-compose"}
          open={dialog === "docker"}
          onOpenChange={(open) => setDialog(open ? "docker" : null)}
        />
      )}

      <DeleteNodeDialog
        node={node}
        open={dialog === "delete"}
        onOpenChange={(open) => setDialog(open ? "delete" : null)}
        onDeleted={onDeleted}
      />
    </>
  );
}
