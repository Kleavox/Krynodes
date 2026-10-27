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

import { CONSOLE, useDisconnect } from "./use-tailscale";

export function DisconnectDialog({ onClose }: { onClose: () => void }) {
  const disconnect = useDisconnect();
  return (
    <Dialog
      open
      onOpenChange={(open) => !open && !disconnect.isPending && onClose()}
    >
      <DialogContent className="sm:max-w-[512px]">
        <DialogHeader>
          <DialogTitle>Disconnect Tailscale?</DialogTitle>
          <DialogDescription>
            Your rules stay in your policy file, so your servers do not open up
            again.
          </DialogDescription>
        </DialogHeader>
        <p className="text-sm">
          Every server erases its piece of the credential, and Krynodes stops
          keeping your rules. Delete the trust credential in Tailscale's admin
          console too.
        </p>
        <Button asChild variant="outline" size="sm" className="w-fit">
          <a href={CONSOLE.credentials} target="_blank" rel="noreferrer">
            Open Trust Credentials ↗
          </a>
        </Button>
        <Said text={disconnect.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" disabled={disconnect.isPending}>
              Cancel
            </Button>
          </DialogClose>
          <SignButton
            label="Disconnect"
            destructive
            pending={disconnect.isPending}
            onClick={() => disconnect.mutate(null, { onSuccess: onClose })}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
