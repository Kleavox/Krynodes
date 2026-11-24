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

export const deleteTarget = (node: Pick<FleetNode, "id" | "name" | "kind">) =>
  node.kind === "laptop"
    ? {
        path: `/api/laptops/${encodeURIComponent(node.id)}`,
        heading: `Delete ${node.name} from the dashboard?`,
        body: "Its history goes with it and it can no longer connect to Krynodes. Add it again with a new code to bring it back.",
      }
    : {
        path: `/api/nodes/${node.id}`,
        heading: `Delete ${node.name} from the dashboard?`,
        body: "Its history goes with it. Install it again to bring it back.",
      };

export function DeleteDialog({
  node,
  onClose,
}: {
  node: FleetNode;
  onClose: () => void;
}) {
  const target = deleteTarget(node);
  const drop = useDeleteNode(node.id, onClose, target.path);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{target.heading}</DialogTitle>
          <DialogDescription>{target.body}</DialogDescription>
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
