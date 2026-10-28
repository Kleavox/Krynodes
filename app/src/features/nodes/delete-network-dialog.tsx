import { KeyRound } from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { deleteText, type BridgeNetwork } from "@/lib/bridges";
import { errorMessage } from "@/lib/http";

export function DeleteNetworkActions({
  network,
  pending,
  error,
  onDelete,
  onCancel,
}: {
  network: BridgeNetwork;
  pending: boolean;
  error?: string | null;
  onDelete: () => void;
  onCancel: () => void;
}) {
  const { ok } = deleteText(network);
  return (
    <>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          variant="destructive"
          disabled={pending || !ok}
          onClick={onDelete}
        >
          {!pending && <KeyRound aria-hidden="true" />}
          {pending ? "Waiting for the Passkey…" : "Delete"}
        </Button>
      </div>
    </>
  );
}

export function DeleteNetworkDialog({
  nodeId,
  serverName,
  network,
  onClose,
}: {
  nodeId: string;
  serverName: string;
  network: BridgeNetwork | null;
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const close = () => {
    run.reset();
    onClose();
  };
  const text = network ? deleteText(network) : null;
  const remove = () => {
    if (!network) return;
    run.mutate(
      {
        action: "remove",
        targets: [{ nodeId, kind: "bridge", name: network.name }],
      },
      {
        onSuccess: () => {
          toast.success(`Deleting ${network.name} on ${serverName}.`);
          close();
        },
      },
    );
  };
  return (
    <AlertDialog
      open={network !== null}
      onOpenChange={(open) => !open && close()}
    >
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        {network && text && (
          <>
            <AlertDialogHeader>
              <AlertDialogTitle>{text.title}</AlertDialogTitle>
              <AlertDialogDescription>{text.body}</AlertDialogDescription>
            </AlertDialogHeader>
            <DeleteNetworkActions
              network={network}
              pending={run.isPending}
              error={run.error ? errorMessage(run.error) : null}
              onDelete={remove}
              onCancel={close}
            />
          </>
        )}
      </AlertDialogContent>
    </AlertDialog>
  );
}
