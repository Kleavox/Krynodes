import { useState } from "react";

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
import { Said, SHEET, SignButton } from "@/features/packages/lines";
import { useUpdateCheck } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import {
  deleteLines,
  listOf,
  networkChecks,
  networkText,
  type Presence,
} from "@/lib/network";
import { cn } from "@/lib/utils";
import type { CheckRecord, NetworkView, NodeRecord } from "@/types";

import { MarkRows } from "./sections";
import { useNetworkKeys, useSignChange } from "./use-network-sign";

export function DeleteDialog({
  view,
  presence,
  checks,
  nodes,
  onClose,
}: {
  view: NetworkView;
  presence: Presence;
  checks: CheckRecord[];
  nodes: NodeRecord[];
  onClose: () => void;
}) {
  const members = view.members.filter((member) => member.state === "in");
  const keys = useNetworkKeys(members);
  const remove = useSignChange();
  const update = useUpdateCheck();
  const [off, setOff] = useState(true);
  const [left, setLeft] = useState<string | null>(null);
  const names = Object.fromEntries(nodes.map((node) => [node.id, node.name]));
  const rows = deleteLines(view, presence, { keep: [], names }, checks);
  const turnOff = rows.find((row) => row.mark === "✓");
  const through = view.network ? networkChecks(checks, view.network.range) : [];

  const go = () =>
    remove.mutate(
      {
        change: { kind: "delete" },
        text: networkText.delete,
        signers: keys.signers,
      },
      {
        onSuccess: async () => {
          if (off) {
            try {
              for (const check of through) {
                await update.mutateAsync({ id: check.id, enabled: false });
              }
            } catch (error) {
              setLeft(
                `The network is deleted, but a check could not be turned off: ${errorMessage(error)}`,
              );
              return;
            }
          }
          onClose();
        },
      },
    );

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[560px]")}>
        <DialogHeader>
          <DialogTitle>Delete the Private Network?</DialogTitle>
          <DialogDescription>
            {listOf(members.map((member) => member.name))} leave it. They stay
            in Krynodes with their stacks and checks.
          </DialogDescription>
        </DialogHeader>
        <MarkRows rows={rows.filter((row) => row !== turnOff)} />
        {turnOff && (
          <label className="flex items-start gap-2.5 rounded-lg border bg-card px-3.5 py-2.5 text-sm">
            <input
              type="checkbox"
              className="mt-1 size-4 accent-primary"
              checked={off}
              disabled={remove.isPending}
              onChange={() => setOff(!off)}
            />
            <span className="min-w-0 flex-1 break-words">
              {turnOff.text}
              <span className="mt-0.5 block text-xs text-muted-foreground">
                {turnOff.detail}
              </span>
            </span>
          </label>
        )}
        <Said text={left ?? remove.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">{left ? "Close" : "Cancel"}</Button>
          </DialogClose>
          {!left && (
            <SignButton
              label="Delete Network"
              destructive
              pending={remove.isPending || update.isPending}
              onClick={go}
            />
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
