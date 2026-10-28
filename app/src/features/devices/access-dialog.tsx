import { MIN_AGENT_VERSION } from "@krynodes/protocol/versions";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import {
  accessChange,
  accessIds,
  agentCurrent,
  buildChange,
  type FleetServer,
} from "@/lib/devices";
import { cn } from "@/lib/utils";
import type { DeviceRecord } from "@/types";

import { SHEET } from "./approval-dialog";
import { plural } from "./parts";
import type { Fleet } from "./use-fleet";

export type AccessScope =
  | { device: DeviceRecord; server?: undefined }
  | { server: FleetServer; device?: undefined };

type Access = Record<string, string[]>;

export function AccessDialog({
  fleet,
  scope,
  onClose,
  onReview,
}: {
  fleet: Fleet;
  scope: AccessScope | null;
  onClose: () => void;
  onReview: (text: string) => void;
}) {
  return (
    <Dialog open={scope !== null} onOpenChange={(open) => !open && onClose()}>
      {scope && (
        <Body
          fleet={fleet}
          scope={scope}
          onClose={onClose}
          onReview={onReview}
        />
      )}
    </Dialog>
  );
}

function Body({
  fleet,
  scope,
  onClose,
  onReview,
}: {
  fleet: Fleet;
  scope: AccessScope;
  onClose: () => void;
  onReview: (text: string) => void;
}) {
  const servers = fleet.trusted.filter((server) => agentCurrent(server.node));
  const blocked = fleet.trusted.filter((server) => !agentCurrent(server.node));
  const current: Access = Object.fromEntries(
    servers.map((server) => [
      server.node.id,
      accessIds(fleet.devices, server.trust),
    ]),
  );
  const [desired, setDesired] = useState<Access>(current);
  const rows = scope.device
    ? servers.map((server) => ({
        key: server.node.id,
        label: server.node.name,
        nodeId: server.node.id,
        device: scope.device,
        server,
      }))
    : fleet.core.map((device) => ({
        key: device.id,
        label: device.name,
        nodeId: scope.server.node.id,
        device,
        server: scope.server,
      }));
  const on = (access: Access, nodeId: string, id: string) =>
    access[nodeId]?.includes(id) ?? false;
  const changed = (nodeId: string, id: string) =>
    on(desired, nodeId, id) !== on(current, nodeId, id);
  const changes = rows.filter((row) =>
    changed(row.nodeId, row.device.id),
  ).length;
  const toggle = (nodeId: string, id: string, next: boolean) =>
    setDesired((previous) => {
      const list = (previous[nodeId] ?? []).filter((entry) => entry !== id);
      return { ...previous, [nodeId]: next ? [...list, id] : list };
    });
  const name = scope.device ? scope.device.name : scope.server.node.name;

  return (
    <DialogContent className={cn(SHEET, "sm:max-w-md")}>
      <DialogHeader>
        <DialogTitle>
          {scope.device ? `Servers for ${name}` : `Passkeys on ${name}`}
        </DialogTitle>
        <DialogDescription>
          {scope.device
            ? `Choose where ${name} can run actions.`
            : `Choose which passkeys can run actions on ${name}.`}{" "}
          Another passkey that already reaches a server approves giving it.
        </DialogDescription>
      </DialogHeader>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No server trusts your passkeys yet.
        </p>
      ) : (
        <ul className="max-h-[55dvh] divide-y overflow-auto rounded-md border">
          {rows.map((row) => {
            const id = `access-${row.nodeId}-${row.device.id}`;
            const moved = changed(row.nodeId, row.device.id);
            return (
              <li
                key={row.key}
                className={cn(
                  "flex min-h-11 items-center gap-3 px-3 transition-colors",
                  moved && "bg-primary/10",
                )}
              >
                <label htmlFor={id} className="min-w-0 flex-1 truncate text-sm">
                  {row.label}
                  {moved && (
                    <span className="text-muted-foreground"> · Changed</span>
                  )}
                </label>
                <Switch
                  id={id}
                  aria-label={`${row.device.name} on ${row.server.node.name}`}
                  checked={on(desired, row.nodeId, row.device.id)}
                  onCheckedChange={(next) =>
                    toggle(row.nodeId, row.device.id, next)
                  }
                />
              </li>
            );
          })}
        </ul>
      )}
      {scope.device && blocked.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {blocked.map((server) => server.node.name).join(", ")}{" "}
          {blocked.length === 1 ? "needs" : "need"} agent {MIN_AGENT_VERSION}{" "}
          first.
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          disabled={changes === 0}
          onClick={() =>
            onReview(buildChange(fleet.view, accessChange(fleet.view, desired)))
          }
        >
          {changes === 0 ? "Review" : `Review ${plural(changes, "change")}`}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
