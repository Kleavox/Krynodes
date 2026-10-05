import { useState } from "react";

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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorMessage } from "@/lib/http";
import { ownFolder } from "@/lib/stacks";
import type { NodeRecord } from "@/types";

import { useSignedAction } from "./use-signed-action";

export interface StackActionRequest {
  action: "stop" | "remove" | "purge";
  project: string;
  node: NodeRecord;
  directory: string;
}

const COPY = {
  stop: {
    title: (project: string, server: string) => `Stop ${project} on ${server}?`,
    body: () => "Its containers stay until you start the stack again.",
    confirm: "Stop",
  },
  remove: {
    title: (project: string, server: string) =>
      `Remove ${project} on ${server}?`,
    body: () =>
      "Its containers and networks go. It waits in Removed for 7 days, where you can restore it or delete it permanently. After that its volumes are deleted.",
    confirm: "Remove",
  },
  purge: {
    title: (project: string, server: string) =>
      `Delete ${project} permanently on ${server}?`,
    body: (directory: string) =>
      ownFolder(directory)
        ? "Its containers, networks and volumes are deleted, and so is the folder Krynodes made for it. This cannot be undone."
        : `Its containers, networks and volumes are deleted. Its folder ${directory} stays. This cannot be undone.`,
    confirm: "Delete permanently",
  },
};

export function StackActionDialog({
  request,
  onClose,
}: {
  request: StackActionRequest | null;
  onClose: () => void;
}) {
  return (
    <AlertDialog
      open={request !== null}
      onOpenChange={(open) => !open && onClose()}
    >
      {request && <StackActionForm request={request} onClose={onClose} />}
    </AlertDialog>
  );
}

function StackActionForm({
  request,
  onClose,
}: {
  request: StackActionRequest;
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const [typed, setTyped] = useState("");
  const { action, project, node, directory } = request;
  const copy = COPY[action];
  const guarded = action === "purge";
  return (
    <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
      <AlertDialogHeader>
        <AlertDialogTitle>{copy.title(project, node.name)}</AlertDialogTitle>
        <AlertDialogDescription>{copy.body(directory)}</AlertDialogDescription>
      </AlertDialogHeader>
      {guarded && (
        <div className="space-y-1.5">
          <Label htmlFor="stack-confirm">Type {project} to confirm</Label>
          <Input
            id="stack-confirm"
            value={typed}
            autoComplete="off"
            onChange={(event) => setTyped(event.target.value)}
          />
        </div>
      )}
      {run.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(run.error)}
        </p>
      )}
      <AlertDialogFooter>
        <AlertDialogCancel>Cancel</AlertDialogCancel>
        <Button
          variant="destructive"
          disabled={run.isPending || (guarded && typed !== project)}
          onClick={() =>
            run.mutate(
              {
                action,
                targets: [{ nodeId: node.id, kind: "compose", name: project }],
              },
              { onSuccess: onClose },
            )
          }
        >
          {run.isPending ? "Working…" : copy.confirm}
        </Button>
      </AlertDialogFooter>
    </AlertDialogContent>
  );
}
