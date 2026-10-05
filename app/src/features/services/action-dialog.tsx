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
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { errorMessage } from "@/lib/http";
import { displayName, verb, type ActionTarget } from "@/lib/services";
import type { ServiceAction } from "@/types";

export interface ActionRequest {
  action: ServiceAction | "remove";
  target: ActionTarget;
}

const DESCRIPTION: Record<ActionRequest["action"], string> = {
  start: "The server runs it at its next report, within about a minute.",
  restart: "The server runs it at its next report, within about a minute.",
  stop: "It stays stopped until you start it.",
  remove:
    "The container is deleted. One that belongs to a stack comes back on the stack's next Deploy.",
};

export function ActionDialog({
  request,
  onClose,
}: {
  request: ActionRequest | null;
  onClose: () => void;
}) {
  return (
    <AlertDialog
      open={request !== null}
      onOpenChange={(open) => !open && onClose()}
    >
      {request && <ActionForm request={request} onClose={onClose} />}
    </AlertDialog>
  );
}

function ActionForm({
  request,
  onClose,
}: {
  request: ActionRequest;
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const { action, target } = request;
  return (
    <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
      <AlertDialogHeader>
        <AlertDialogTitle>
          {verb(action)} {displayName(target.kind, target.name)} on{" "}
          {target.nodeName}?
        </AlertDialogTitle>
        <AlertDialogDescription>{DESCRIPTION[action]}</AlertDialogDescription>
      </AlertDialogHeader>
      {run.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(run.error)}
        </p>
      )}
      <AlertDialogFooter>
        <AlertDialogCancel>Cancel</AlertDialogCancel>
        <Button
          variant={
            action === "stop" || action === "remove" ? "destructive" : "default"
          }
          disabled={run.isPending}
          onClick={() =>
            run.mutate({ action, targets: [target] }, { onSuccess: onClose })
          }
        >
          {run.isPending ? "Working…" : verb(action)}
        </Button>
      </AlertDialogFooter>
    </AlertDialogContent>
  );
}
