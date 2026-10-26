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
import { useServices } from "@/lib/api";
import { hostingOf, networkText, removeLines, seatOf } from "@/lib/network";
import { cn } from "@/lib/utils";
import type { NetworkServer, NetworkView, NodeRecord } from "@/types";

import { MarkRows } from "./sections";
import { useNetworkKeys, useSignChange } from "./use-network-sign";

export function RemoveDialog({
  server,
  view,
  nodes,
  onClose,
}: {
  server: NetworkServer;
  view: NetworkView;
  nodes: NodeRecord[];
  onClose: () => void;
}) {
  const reports = useServices().data?.nodes ?? [];
  const keys = useNetworkKeys(view.members);
  const remove = useSignChange();
  const node = nodes.find((entry) => entry.id === server.nodeId);
  const seat = node
    ? seatOf(
        node,
        reports.find((entry) => entry.id === server.nodeId),
      )
    : null;
  const rows = removeLines(
    server,
    view,
    {
      firewall: seat?.firewall ?? null,
      docker: seat?.docker ?? false,
      tools: false,
    },
    hostingOf(reports, nodes),
  );
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[560px]")}>
        <DialogHeader>
          <DialogTitle>Remove {server.name} from the network?</DialogTitle>
          <DialogDescription>
            {server.name} stays in Krynodes with its stacks and checks. Only its
            private network goes.
          </DialogDescription>
        </DialogHeader>
        <MarkRows rows={rows} />
        <Said text={remove.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label="Remove"
            destructive
            pending={remove.isPending}
            onClick={() =>
              remove.mutate(
                {
                  change: { kind: "remove", nodeId: server.nodeId },
                  text: networkText.remove(server.name),
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
