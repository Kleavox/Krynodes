import { useState } from "react";

import { Busy } from "@/components/busy";
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
import { removeChoices, removeLines, type RemovePreview } from "@/lib/packages";
import { cn } from "@/lib/utils";
import type { AptReport, NodeRecord } from "@/types";

import { Lines, Said, SHEET, SignButton } from "./lines";
import { useQuestion } from "./use-question";

export function RemoveDialog({
  node,
  report,
  name,
  onClose,
  onStarted,
}: {
  node: NodeRecord;
  report: AptReport;
  name: string;
  onClose: () => void;
  onStarted: (id: string) => void;
}) {
  const [what, setWhat] = useState<"remove" | "purge">("remove");
  const ask = (choice: "remove" | "purge") => ({
    nodeId: node.id,
    action: "preview" as const,
    name,
    args: { what: choice },
  });
  const preview = useQuestion<RemovePreview>(ask("remove"));
  const run = useSignedAction(false);
  const from = report.packages.find((entry) => entry.name === name)?.from;
  const publicAddress =
    node.addresses?.find(
      (address) => address.label === `IPv${address.family}` && !address.router,
    )?.address ?? null;
  const shown = preview.value?.what === what ? preview.value : null;
  const choose = (choice: "remove" | "purge") => {
    setWhat(choice);
    preview.ask(ask(choice));
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>
            Remove {name} · {node.name}
          </DialogTitle>
          <DialogDescription>
            Tried first without removing anything.
          </DialogDescription>
        </DialogHeader>
        <div
          role="radiogroup"
          aria-label="How to remove it"
          className="space-y-2"
        >
          {removeChoices(name, node.name).map((choice) => (
            <button
              key={choice.id}
              type="button"
              role="radio"
              aria-checked={what === choice.id}
              onClick={() => choose(choice.id)}
              className={cn(
                "w-full rounded-md border px-3 py-2 text-left text-sm hover:bg-accent",
                what === choice.id && "border-primary bg-accent",
              )}
            >
              <span className="block font-medium">{choice.title}</span>
              <span className="block text-xs text-muted-foreground">
                {choice.detail}
              </span>
            </button>
          ))}
        </div>
        {preview.waiting ? (
          <p className="text-sm text-muted-foreground">
            <Busy>{`Trying it on ${node.name}`}</Busy>
          </p>
        ) : (
          <>
            <Said text={preview.error} />
            {shown && (
              <Lines
                lines={removeLines(shown, {
                  nodeName: node.name,
                  repository: report.sources.some(
                    (source) => !source.system && source.name === from,
                  ),
                  tailscale: node.tailscale,
                  publicAddress,
                })}
              />
            )}
          </>
        )}
        <Said text={run.error ? errorMessage(run.error) : null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label="Remove"
            destructive
            pending={run.isPending}
            disabled={preview.waiting || !shown || shown.refused !== null}
            onClick={() =>
              run.mutate(
                {
                  action: what,
                  mode: "parallel",
                  targets: [{ nodeId: node.id, kind: "apt", name }],
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
