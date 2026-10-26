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
import { Said, SignButton } from "@/features/packages/lines";
import { missingSeals, rekeyNote, type Presence } from "@/lib/network";
import type { NetworkView } from "@/types";

import { useMakeNewKeys, useNetworkKeys } from "./use-network-sign";

export function KeysDialog({
  view,
  presence,
  onClose,
}: {
  view: NetworkView;
  presence: Presence;
  onClose: () => void;
}) {
  const members = view.members.filter((member) => member.state === "in");
  const keys = useNetworkKeys(members);
  const make = useMakeNewKeys();
  const note = rekeyNote(view, presence);
  const missing = missingSeals(view, keys.sealKeys);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>Make new keys for the network?</DialogTitle>
          <DialogDescription>
            Every server makes a new WireGuard key and the others learn it.
            Links drop for a few seconds while they switch, and the old keys
            stop working at once.
          </DialogDescription>
        </DialogHeader>
        {note && <p className="text-sm text-muted-foreground">{note}</p>}
        {make.isPending && (
          <p role="status" className="text-sm text-muted-foreground">
            Making new keys… The servers finish this even if you close it.
          </p>
        )}
        <Said text={missing ?? make.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label={make.isPending ? "Making New Keys…" : "Make New Keys"}
            destructive
            pending={false}
            disabled={make.isPending || missing !== null}
            onClick={() =>
              make.mutate(
                {
                  view,
                  online: members
                    .filter((member) => presence[member.nodeId]?.online)
                    .map((member) => member.nodeId),
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
