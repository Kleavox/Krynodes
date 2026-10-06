import { Fingerprint } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

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
import type { NodeRecord, Platform } from "@/types";

export function InstallDockerDialog({
  node,
  platform,
  composeOnly,
  open,
  onOpenChange,
}: {
  node: NodeRecord;
  platform: Platform;
  composeOnly: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const run = useSignedAction(false);
  const [anyway, setAnyway] = useState(false);
  const close = (next: boolean) => {
    if (!next) {
      run.reset();
      setAnyway(false);
    }
    onOpenChange(next);
  };
  const submit = () =>
    run.mutate(
      {
        action: "install",
        targets: [
          {
            nodeId: node.id,
            kind: "host",
            name: "docker",
            ...(anyway ? { args: { anyway: "yes" } } : {}),
          },
        ],
      },
      {
        onSuccess: () => {
          toast.success(`Installing Docker on ${node.name}.`);
          close(false);
        },
      },
    );
  return (
    <AlertDialog open={open} onOpenChange={close}>
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <AlertDialogHeader>
          <AlertDialogTitle>
            {composeOnly
              ? `Add Compose to ${node.name}?`
              : `Install Docker on ${node.name}?`}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {composeOnly
              ? "Adds the Compose plugin from Docker's own repository. Docker itself stays as it is."
              : "Installs Docker and Compose from Docker's own repository. Takes a few minutes."}
          </AlertDialogDescription>
        </AlertDialogHeader>
        {!platform.verified && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={anyway}
              onChange={() => setAnyway(!anyway)}
            />
            Run it on {platform.name} anyway
          </label>
        )}
        {run.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(run.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            disabled={run.isPending || (!platform.verified && !anyway)}
            onClick={submit}
          >
            {!run.isPending && <Fingerprint aria-hidden="true" />}
            {run.isPending
              ? "Waiting for the fingerprint…"
              : composeOnly
                ? "Add Compose"
                : "Install Docker"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
