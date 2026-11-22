import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Busy } from "@/components/busy";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { RowMenu } from "@/components/row-menu";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useFleet } from "@/features/fleet/use-fleet";
import { RegisterDialog } from "@/features/passkeys/register-dialog";
import { TrustDialog } from "@/features/passkeys/trust-dialog";
import { useDevices } from "@/lib/api";
import { apiFetch, errorMessage } from "@/lib/http";
import { queryKeys } from "@/lib/query-client";
import type { Device, FleetNode } from "@/types";

type Open =
  | { kind: "register" }
  | { kind: "rename" | "trust" | "remove"; device: Device };

export function trustedBy(device: Device, nodes: FleetNode[] | undefined) {
  if (!nodes) return "--";
  const names = nodes
    .filter((node) => node.trust?.core.includes(device.id))
    .map((node) => node.name);
  return names.length > 0 ? names.join(", ") : "No Servers";
}

function useDeviceChange<T>(
  change: (input: T) => Promise<unknown>,
  done: () => void,
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: change,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.devices });
      done();
    },
  });
}

function RenameDialog({
  device,
  onClose,
}: {
  device: Device;
  onClose: () => void;
}) {
  const [name, setName] = useState(device.name);
  const rename = useDeviceChange(
    (next: string) =>
      apiFetch(`/api/devices/${encodeURIComponent(device.id)}`, {
        method: "PATCH",
        body: JSON.stringify({ name: next }),
      }),
    onClose,
  );
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rename {device.name}</DialogTitle>
          <DialogDescription>
            Servers keep the name they were given until their trust changes
            again.
          </DialogDescription>
        </DialogHeader>
        <form
          id="rename-passkey"
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault();
            rename.mutate(name.trim());
          }}
        >
          <Label htmlFor="rename-passkey-name">Passkey Name</Label>
          <Input
            id="rename-passkey-name"
            value={name}
            maxLength={40}
            autoComplete="off"
            onChange={(event) => setName(event.target.value)}
          />
        </form>
        {rename.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(rename.error)}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="rename-passkey"
            disabled={rename.isPending || name.trim() === ""}
          >
            {rename.isPending ? <Busy>Saving</Busy> : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RemoveDialog({
  device,
  onClose,
}: {
  device: Device;
  onClose: () => void;
}) {
  const remove = useDeviceChange(
    () =>
      apiFetch(`/api/devices/${encodeURIComponent(device.id)}`, {
        method: "DELETE",
      }),
    onClose,
  );
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Remove {device.name}?</DialogTitle>
          <DialogDescription>
            Krynodes forgets this passkey. A passkey a server still trusts
            cannot be removed; take it off those servers first.
          </DialogDescription>
        </DialogHeader>
        {remove.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(remove.error)}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={remove.isPending}
            onClick={() => remove.mutate(undefined)}
          >
            {remove.isPending ? <Busy>Removing</Busy> : "Remove"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function PasskeysPage() {
  const devices = useDevices();
  const fleet = useFleet();
  const [open, setOpen] = useState<Open | null>(null);
  const close = () => setOpen(null);
  return (
    <>
      <PageHeader
        title="Passkeys"
        actions={
          <Button onClick={() => setOpen({ kind: "register" })}>
            Add Passkey
          </Button>
        }
      />
      {devices.data ? (
        devices.data.length === 0 ? (
          <EmptyState
            title="No passkeys yet"
            body="Servers act only on commands signed with a passkey they trust. Add your first one."
          />
        ) : (
          <ul className="divide-y rounded-lg border bg-card">
            {devices.data.map((device) => (
              <li key={device.id} className="flex items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <span className="truncate font-medium">{device.name}</span>
                  <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                    <span>{device.synced ? "Synced" : "This Device Only"}</span>
                    <span>{trustedBy(device, fleet.data)}</span>
                  </p>
                </div>
                <RowMenu
                  label={`Actions for ${device.name}`}
                  items={[
                    {
                      label: "Rename",
                      onSelect: () => setOpen({ kind: "rename", device }),
                    },
                    {
                      label: "Trust on Servers",
                      onSelect: fleet.data
                        ? () => setOpen({ kind: "trust", device })
                        : undefined,
                    },
                    {
                      label: "Remove",
                      destructive: true,
                      onSelect: () => setOpen({ kind: "remove", device }),
                    },
                  ]}
                />
              </li>
            ))}
          </ul>
        )
      ) : devices.isError ? (
        <EmptyState
          title="The passkeys can't load"
          body={errorMessage(devices.error)}
          action={<Button onClick={() => void devices.refetch()}>Retry</Button>}
        />
      ) : (
        <div role="status" aria-label="Loading passkeys" className="space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      )}
      {open?.kind === "register" && <RegisterDialog onClose={close} />}
      {open?.kind === "rename" && (
        <RenameDialog device={open.device} onClose={close} />
      )}
      {open?.kind === "remove" && (
        <RemoveDialog device={open.device} onClose={close} />
      )}
      {open?.kind === "trust" && devices.data && fleet.data && (
        <TrustDialog
          device={open.device}
          devices={devices.data}
          nodes={fleet.data}
          onClose={close}
        />
      )}
    </>
  );
}
