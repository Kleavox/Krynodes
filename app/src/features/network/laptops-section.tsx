import { useState } from "react";

import { Busy, Waiting } from "@/components/busy";
import { Field } from "@/components/field";
import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  NotFollowing,
  Said,
  SHEET,
  SignButton,
} from "@/features/packages/lines";
import { useDismissLaptop, useNetworkNext, useUpdateNode } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { laptopJoiner, laptopRow, networkText } from "@/lib/network";
import { cn } from "@/lib/utils";
import type { NetworkLaptop, NetworkView } from "@/types";

import { card, sectionTitle } from "./sections";
import { useNetworkKeys, useSignChange } from "./use-network-sign";

export function LaptopsSection({
  view,
  now,
  blocker,
  onApprove,
  onDismiss,
  onRename,
  onRemove,
}: {
  view: NetworkView;
  now: number;
  blocker: string | null;
  onApprove: (laptop: NetworkLaptop) => void;
  onDismiss: (laptop: NetworkLaptop) => void;
  onRename: (laptop: NetworkLaptop) => void;
  onRemove: (laptop: NetworkLaptop) => void;
}) {
  const shown = view.laptops.filter(
    (laptop) => laptop.state === "waiting" || laptop.state === "in",
  );
  const next = useNetworkNext(
    shown
      .filter((laptop) => laptop.state === "waiting")
      .map((laptop) => laptop.nodeId),
  );
  if (shown.length === 0) return null;
  return (
    <section>
      <h2 className={sectionTitle}>Laptops</h2>
      <ul className={card}>
        {shown.map((laptop) => {
          const row = laptopRow(laptop, now, view.version);
          const waiting = laptop.state === "waiting";
          const gets =
            next.data?.addresses.find((entry) => entry.nodeId === laptop.nodeId)
              ?.address ?? "--";
          return (
            <li
              key={laptop.nodeId}
              className="flex items-center gap-3 py-3 pr-2 pl-3.5 text-sm"
            >
              <StatusDot tone={waiting ? "warn" : row.online ? "ok" : "idle"} />
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-x-2">
                  <span className="font-medium">
                    {waiting ? `${row.name} wants to join` : row.name}
                  </span>
                  <span className="truncate font-mono text-xs text-muted-foreground">
                    {waiting ? `Gets ${gets}` : row.address}
                  </span>
                </span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  {row.status}
                  {row.behind && (
                    <>
                      {" · "}
                      <span
                        className={cn(
                          row.behind.startsWith("Behind") && "text-warning",
                        )}
                      >
                        {row.behind}
                      </span>
                    </>
                  )}
                </span>
              </span>
              {waiting && (
                <Button
                  size="sm"
                  className="h-9 md:h-8"
                  disabled={blocker !== null}
                  onClick={() => onApprove(laptop)}
                >
                  Approve
                </Button>
              )}
              <RowMenu
                label={`More for ${laptop.name}`}
                items={
                  waiting
                    ? [
                        {
                          label: "Dismiss",
                          destructive: true,
                          onSelect: () => onDismiss(laptop),
                        },
                      ]
                    : [
                        {
                          label: "Rename",
                          disabled: blocker !== null,
                          onSelect: () => onRename(laptop),
                        },
                        {
                          label: "Remove Laptop",
                          destructive: true,
                          disabled: blocker !== null,
                          onSelect: () => onRemove(laptop),
                        },
                      ]
                }
              />
            </li>
          );
        })}
      </ul>
      {blocker && (
        <p role="status" className="mt-2 text-xs text-muted-foreground">
          {blocker}
        </p>
      )}
    </section>
  );
}

export function ApproveLaptopDialog({
  laptop,
  view,
  blocker,
  onClose,
}: {
  laptop: NetworkLaptop;
  view: NetworkView;
  blocker: string | null;
  onClose: () => void;
}) {
  const next = useNetworkNext([laptop.nodeId]);
  const address =
    next.data?.addresses.find((entry) => entry.nodeId === laptop.nodeId)
      ?.address ?? null;
  const waiting = view.waiting.find((entry) => entry.nodeId === laptop.nodeId);
  const keys = useNetworkKeys(view.members, [laptop.nodeId]);
  const sign = useSignChange();
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[480px]")}>
        <DialogHeader>
          <DialogTitle>Approve {laptop.name}?</DialogTitle>
          <DialogDescription>
            {laptop.name} joins the private network as {address ?? "--"}. It
            reaches every server, and the servers learn its key in the same
            step. Remove Laptop takes it out again.
          </DialogDescription>
        </DialogHeader>
        <NotFollowing lines={keys.unfollowed} />
        <Said text={blocker ?? sign.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label="Approve"
            pending={sign.isPending}
            disabled={blocker !== null || !waiting || address === null}
            onClick={() =>
              sign.mutate(
                {
                  change: {
                    kind: "add",
                    join: [laptopJoiner(waiting!, address!)],
                  },
                  text: networkText.addLaptop(laptop.name),
                  signers: keys.signers,
                  sealKeys: keys.sealKeys,
                },
                { onSuccess: onClose },
              )
            }
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function RemoveLaptopDialog({
  laptop,
  view,
  blocker,
  onClose,
}: {
  laptop: NetworkLaptop;
  view: NetworkView;
  blocker: string | null;
  onClose: () => void;
}) {
  const keys = useNetworkKeys(
    view.members.filter((member) => member.nodeId !== laptop.nodeId),
  );
  const sign = useSignChange();
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[480px]")}>
        <DialogHeader>
          <DialogTitle>Remove {laptop.name}?</DialogTitle>
          <DialogDescription>
            Every server drops {laptop.name} at once and stops accepting its
            key, even if the agent is still installed on it. To use it again,
            add it as a new laptop.
          </DialogDescription>
        </DialogHeader>
        <NotFollowing lines={keys.unfollowed} />
        <Said text={blocker ?? sign.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label="Remove Laptop"
            destructive
            pending={sign.isPending}
            disabled={blocker !== null}
            onClick={() =>
              sign.mutate(
                {
                  change: { kind: "remove", nodeId: laptop.nodeId },
                  text: networkText.removeLaptop(laptop.name),
                  signers: keys.signers,
                },
                { onSuccess: onClose },
              )
            }
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function DismissLaptopDialog({
  laptop,
  onClose,
}: {
  laptop: NetworkLaptop;
  onClose: () => void;
}) {
  const dismiss = useDismissLaptop();
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[480px]")}>
        <DialogHeader>
          <DialogTitle>Dismiss {laptop.name}?</DialogTitle>
          <DialogDescription>
            {laptop.name} is forgotten and can no longer connect. To add it
            again, make a new code.
          </DialogDescription>
        </DialogHeader>
        <Said text={dismiss.error ? errorMessage(dismiss.error) : null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button
            variant="destructive"
            disabled={dismiss.isPending}
            onClick={() =>
              dismiss.mutate(laptop.nodeId, { onSuccess: onClose })
            }
          >
            {dismiss.isPending ? <Busy>Dismissing</Busy> : "Dismiss"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function RenameLaptopDialog({
  laptop,
  view,
  blocker,
  onClose,
}: {
  laptop: NetworkLaptop;
  view: NetworkView;
  blocker: string | null;
  onClose: () => void;
}) {
  const [name, setName] = useState(laptop.name);
  const save = useUpdateNode();
  const told = useSignChange();
  const keys = useNetworkKeys(view.members);
  const trimmed = name.trim();
  const changed = trimmed !== "" && trimmed !== laptop.name;
  const tell = () =>
    told.mutate(
      {
        change: { kind: "rename", nodeId: laptop.nodeId, name: trimmed },
        text: networkText.rename(laptop.name, trimmed),
        signers: keys.signers,
      },
      { onSuccess: onClose },
    );
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (save.isSuccess) return tell();
            save.mutate(
              { id: laptop.nodeId, name: trimmed },
              { onSuccess: tell },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Rename {laptop.name}</DialogTitle>
            <DialogDescription>
              Your passkey tells the servers its new name.
            </DialogDescription>
          </DialogHeader>
          <Field id="laptop-name" label="Name">
            <Input
              id="laptop-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={100}
              required
            />
          </Field>
          <NotFollowing lines={keys.unfollowed} />
          <Said
            text={
              blocker ??
              (save.error || told.error
                ? errorMessage(save.error ?? told.error)
                : null)
            }
          />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={
                blocker !== null ||
                save.isPending ||
                told.isPending ||
                (!changed && !save.isSuccess)
              }
            >
              {save.isPending ? (
                <Busy>Saving</Busy>
              ) : told.isPending ? (
                <Waiting />
              ) : (
                "Save"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
