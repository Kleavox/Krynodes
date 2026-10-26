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
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { errorMessage } from "@/lib/http";
import type { AptReport, NodeRecord } from "@/types";

import { Said, SHEET, SignButton } from "./lines";

export function HoldDialog({
  node,
  report,
  name,
  held,
  onClose,
}: {
  node: NodeRecord;
  report: AptReport;
  name: string;
  held: boolean;
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const version = report.packages.find((entry) => entry.name === name)?.version;
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>
            {held
              ? `Release the hold on ${name}?`
              : `Hold ${name} at ${version ?? "this version"}?`}
          </DialogTitle>
          <DialogDescription>
            {held
              ? `${name} upgrades again with Upgrade All and the daily security updates on ${node.name}.`
              : `Upgrade All and the daily security updates leave it at this version. A held package gets no security fixes either, so its rows say Held until you release it.`}
          </DialogDescription>
        </DialogHeader>
        <Said text={run.error ? errorMessage(run.error) : null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label={held ? "Release Hold" : "Hold"}
            pending={run.isPending}
            onClick={() =>
              run.mutate(
                {
                  action: held ? "unhold" : "hold",
                  mode: "parallel",
                  targets: [{ nodeId: node.id, kind: "apt", name }],
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
