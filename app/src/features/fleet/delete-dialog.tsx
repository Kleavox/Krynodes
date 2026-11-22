import { Busy } from "@/components/busy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useDeleteNode } from "@/features/fleet/use-fleet";
import { errorMessage } from "@/lib/http";
import type { FleetNode } from "@/types";

export function DeleteDialog({
  node,
  onClose,
}: {
  node: FleetNode;
  onClose: () => void;
}) {
  const drop = useDeleteNode(node.id, onClose);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{`Delete ${node.name} from the dashboard?`}</DialogTitle>
          <DialogDescription>
            Its history goes with it. Install it again to bring it back.
          </DialogDescription>
        </DialogHeader>
        {drop.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(drop.error)}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={drop.isPending}
            onClick={() => drop.mutate()}
          >
            {drop.isPending ? <Busy>Deleting</Busy> : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
