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
import {
  NotFollowing,
  Said,
  SHEET,
  SignButton,
} from "@/features/packages/lines";
import {
  useNetworkKeys,
  useSignChange,
} from "@/features/network/use-network-sign";
import {
  exitDnsLine,
  exitState,
  laptopBlocker,
  networkText,
} from "@/lib/network";
import { cn } from "@/lib/utils";
import type { NetworkView, NodeRecord } from "@/types";

export function ExitDialog({
  node,
  view,
  nodes,
  onClose,
}: {
  node: Pick<NodeRecord, "id" | "name">;
  view: NetworkView;
  nodes: Pick<NodeRecord, "id" | "name" | "agent_version">[];
  onClose: () => void;
}) {
  const keys = useNetworkKeys(view.members);
  const sign = useSignChange();
  const [turningOn] = useState(() => exitState(view, node.id) !== "on");
  const blocker = laptopBlocker(view, nodes);
  const dnsLine = exitDnsLine(view, turningOn);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[480px]")}>
        <DialogHeader>
          <DialogTitle>Exit Node for Laptops on {node.name}</DialogTitle>
          <DialogDescription>
            {turningOn
              ? `Laptops in the private network can then send all their internet traffic out through ${node.name}. Sites see ${node.name}'s address, not the laptop's.`
              : `Laptops stop sending their internet traffic out through ${node.name} and go back to their own connection.`}
          </DialogDescription>
        </DialogHeader>
        {dnsLine && <p className="text-sm text-muted-foreground">{dnsLine}</p>}
        <NotFollowing lines={keys.unfollowed} />
        <Said text={blocker ?? sign.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label={turningOn ? "Turn On" : "Turn Off"}
            destructive={!turningOn}
            pending={sign.isPending}
            disabled={blocker !== null}
            onClick={() =>
              sign.mutate(
                {
                  change: { kind: "exit", nodeId: node.id, on: turningOn },
                  text: networkText.exit(node.name, turningOn),
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
