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
import {
  accessChange,
  accessIds,
  agentCurrent,
  buildChange,
  formatPrint,
  syncText,
  type FleetServer,
} from "@/lib/devices";
import { displayHandle, shortDate, timeAgo } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { DeviceRecord } from "@/types";

import { SHEET } from "./approval-dialog";
import { plural } from "./parts";
import type { Fleet } from "./use-fleet";

export type AccessScope =
  | { device: DeviceRecord; server?: undefined }
  | { server: FleetServer; device?: undefined };

type Access = Record<string, string[]>;

export interface Tick {
  key: string;
  label: string;
  checked: boolean;
  was: boolean;
}

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

export function DeviceFacts({ device }: { device: DeviceRecord }) {
  const facts: [string, string, boolean?][] = [
    ["Fingerprint", formatPrint(device.fingerprint), true],
    ["Saved", syncText(device.synced)],
    [
      "Last Used",
      device.lastUsedAt ? timeAgo(device.lastUsedAt) : "Never Used",
    ],
    ["Added", shortDate(device.createdAt)],
  ];
  if (!device.mine) {
    facts.push([
      "Owner",
      device.owner ? displayHandle(null, device.owner) : "Not Claimed Yet",
    ]);
  }
  return (
    <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 gap-y-1.5 rounded-md bg-muted px-3 py-2.5 text-sm">
      {facts.map(([label, value, mono]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd
            className={cn(
              "min-w-0 truncate",
              mono && "font-mono text-xs leading-5",
            )}
          >
            {value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function Ticks({
  ticks,
  all,
  onTick,
  onAll,
}: {
  ticks: Tick[];
  all?: string;
  onTick: (key: string, next: boolean) => void;
  onAll?: (next: boolean) => void;
}) {
  const every = ticks.every((tick) => tick.checked);
  const some = ticks.some((tick) => tick.checked);
  return (
    <ul className="max-h-[55dvh] divide-y overflow-auto rounded-md border">
      {all && (
        <li>
          <label className="flex min-h-11 items-center gap-3 px-3 text-sm font-medium">
            <input
              type="checkbox"
              className="size-4 accent-primary"
              checked={every}
              ref={(box) => {
                if (box) box.indeterminate = some && !every;
              }}
              onChange={() => onAll?.(!every)}
            />
            {all}
          </label>
        </li>
      )}
      {ticks.map((tick) => {
        const moved = tick.checked !== tick.was;
        return (
          <li
            key={tick.key}
            className={cn("transition-colors", moved && "bg-primary/10")}
          >
            <label className="flex min-h-11 items-center gap-3 px-3 text-sm">
              <input
                type="checkbox"
                className="size-4 accent-primary"
                checked={tick.checked}
                onChange={() => onTick(tick.key, !tick.checked)}
              />
              <span className="min-w-0 flex-1 truncate">{tick.label}</span>
              {moved && (
                <span className="font-mono text-xs text-primary-text">
                  {tick.checked ? "Adds" : "Removes"}
                </span>
              )}
            </label>
          </li>
        );
      })}
    </ul>
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
        id: scope.device.id,
      }))
    : fleet.core.map((device) => ({
        key: device.id,
        label: device.name,
        nodeId: scope.server.node.id,
        id: device.id,
      }));
  const on = (access: Access, nodeId: string, id: string) =>
    access[nodeId]?.includes(id) ?? false;
  const ticks: Tick[] = rows.map((row) => ({
    key: row.key,
    label: row.label,
    checked: on(desired, row.nodeId, row.id),
    was: on(current, row.nodeId, row.id),
  }));
  const changes = ticks.filter((tick) => tick.checked !== tick.was).length;
  const toggle = (nodeId: string, id: string, next: boolean) =>
    setDesired((previous) => {
      const list = (previous[nodeId] ?? []).filter((entry) => entry !== id);
      return { ...previous, [nodeId]: next ? [...list, id] : list };
    });
  const tick = (key: string, next: boolean) => {
    const row = rows.find((entry) => entry.key === key);
    if (row) toggle(row.nodeId, row.id, next);
  };
  const name = scope.device ? scope.device.name : scope.server.node.name;

  return (
    <DialogContent className={cn(SHEET, "sm:max-w-md")}>
      <DialogHeader>
        <DialogTitle>{scope.device ? name : `Passkeys on ${name}`}</DialogTitle>
        <DialogDescription>
          {scope.device
            ? `${name} runs actions only on the servers ticked below.`
            : `Only the passkeys ticked below run actions on ${name}.`}
        </DialogDescription>
      </DialogHeader>
      {scope.device && <DeviceFacts device={scope.device} />}
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No server trusts your passkeys yet.
        </p>
      ) : (
        <div className="grid gap-1.5">
          {scope.device && <p className="text-sm font-medium">Servers</p>}
          <Ticks
            ticks={ticks}
            all={scope.device && rows.length > 1 ? "All Servers" : undefined}
            onTick={tick}
            onAll={(next) =>
              rows.forEach((row) => toggle(row.nodeId, row.id, next))
            }
          />
        </div>
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
          {changes === 0 ? "Review" : `Review ${plural(changes, "Change")}`}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
