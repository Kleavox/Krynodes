import { KeyRound } from "lucide-react";
import { toast } from "sonner";

import { Busy, Waiting } from "@/components/busy";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useDenials } from "@/lib/api";
import {
  confineText,
  denialLines,
  systemName,
  type ConfineStep,
} from "@/lib/confine";
import { stampTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import type { Confinement, NodeRecord } from "@/types";

const UNREAD = { count: null, lines: [] };

export function ConfineDialog({
  node,
  found,
  step,
  stacks,
  onClose,
}: {
  node: NodeRecord;
  found: Confinement;
  step: Exclude<ConfineStep, "denials">;
  stacks: string[];
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const denials = useDenials(node.id, step === "on");
  const text = confineText(
    step,
    found,
    node.name,
    denials.data ?? UNREAD,
    stacks,
  );
  const containers = step === "containers" || step === "uncontain";
  const submit = () =>
    run.mutate(
      {
        action: step === "undo" ? "undo" : containers ? "containers" : "apply",
        targets: [
          {
            nodeId: node.id,
            kind: "host",
            name: "confinement",
            ...(containers
              ? { args: { on: step === "containers" ? "1" : "0" } }
              : {}),
          },
        ],
      },
      {
        onSuccess: () => {
          toast.success(`Sent to ${node.name}.`);
          onClose();
        },
      },
    );
  return (
    <AlertDialog open onOpenChange={(open) => !open && onClose()}>
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <AlertDialogHeader>
          <AlertDialogTitle>{text.title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              {text.lines.map((line) => (
                <p key={line}>{line}</p>
              ))}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {run.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(run.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            variant={text.destructive ? "destructive" : "default"}
            disabled={run.isPending}
            onClick={submit}
          >
            <KeyRound aria-hidden="true" />
            {run.isPending ? <Waiting /> : text.button}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function DenialsDialog({
  node,
  found,
  seen,
  onClose,
}: {
  node: NodeRecord;
  found: Confinement;
  seen: number;
  onClose: () => void;
}) {
  const denials = useDenials(node.id, true);
  const shown = denials.data ? denialLines(denials.data) : null;
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Denials on {node.name}</DialogTitle>
          <DialogDescription>
            {shown ? (
              `${systemName(found.system)} · ${shown.summary}`
            ) : denials.error ? (
              errorMessage(denials.error)
            ) : (
              <Busy>Loading</Busy>
            )}
          </DialogDescription>
        </DialogHeader>
        {shown && shown.rows.length > 0 && (
          <ul className="max-h-96 divide-y overflow-y-auto rounded-md border text-sm">
            {shown.rows.map((row) => (
              <li
                key={`${row.at} ${row.program} ${row.wanted}`}
                className="px-3 py-2"
              >
                <span className="block font-mono text-xs break-all">
                  {row.program} · {row.wanted}
                </span>
                <span className="block text-xs text-muted-foreground">
                  {stampTime(row.at, seen)} · Stack {row.stack}
                </span>
              </li>
            ))}
          </ul>
        )}
      </DialogContent>
    </Dialog>
  );
}
