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
import { upgradeLines, type UpgradePreview } from "@/lib/packages";
import type { AptReport, NodeRecord } from "@/types";

import { Lines, Said, SHEET, SignButton } from "./lines";
import { useQuestion } from "./use-question";

export function UpgradeDialog({
  node,
  report,
  stacks,
  reached,
  onClose,
  onStarted,
}: {
  node: NodeRecord;
  report: AptReport;
  stacks: string[];
  reached: string[];
  onClose: () => void;
  onStarted: (id: string) => void;
}) {
  const preview = useQuestion<UpgradePreview>({
    nodeId: node.id,
    action: "preview",
    name: "system",
    args: { what: "upgrade" },
  });
  const run = useSignedAction(false);
  const tried = preview.value
    ? upgradeLines(preview.value, {
        nodeName: node.name,
        report,
        stacks,
        reached,
      })
    : null;
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>Upgrade All · {node.name}</DialogTitle>
          <DialogDescription>
            {preview.waiting
              ? `Trying it on ${node.name} without changing anything…`
              : (tried?.header ?? "")}
          </DialogDescription>
        </DialogHeader>
        <Said text={preview.error} />
        {tried && <Lines lines={tried.lines} />}
        <Said text={run.error ? errorMessage(run.error) : null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label="Upgrade"
            pending={run.isPending}
            disabled={!preview.value || preview.value.upgrades.length === 0}
            onClick={() =>
              run.mutate(
                {
                  action: "upgrade",
                  mode: "parallel",
                  targets: [{ nodeId: node.id, kind: "apt", name: "system" }],
                },
                { onSuccess: (sent) => onStarted(sent.actions[0]!.id) },
              )
            }
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
