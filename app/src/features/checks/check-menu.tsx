import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { Busy } from "@/components/busy";
import { RowMenu } from "@/components/row-menu";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { checksApi, useRefreshStacks } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import type { CheckView } from "@/types";

import { CheckTextDialog } from "./check-dialog";

function DeleteCheck({
  check,
  onClose,
}: {
  check: CheckView;
  onClose: () => void;
}) {
  const refresh = useRefreshStacks();
  const drop = useMutation({
    mutationFn: () => checksApi.remove(check.id),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <AlertDialog open onOpenChange={(open) => !open && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete {check.name}?</AlertDialogTitle>
          <AlertDialogDescription>
            The check and its history are deleted. The container keeps running.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {drop.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(drop.error)}
          </p>
        )}
        <AlertDialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={drop.isPending}
            onClick={() => drop.mutate()}
          >
            {drop.isPending ? <Busy>Deleting</Busy> : "Delete"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function CheckMenu({ check }: { check: CheckView }) {
  const [open, setOpen] = useState<"name" | "note" | "delete" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = useRefreshStacks();
  const flip = useMutation({
    mutationFn: () => checksApi.change(check.id, { public: !check.public }),
    onSuccess: () => {
      setError(null);
      refresh();
    },
    onError: (failed) => setError(errorMessage(failed)),
  });
  const close = () => setOpen(null);
  return (
    <>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <RowMenu
        label={`Actions for ${check.name}`}
        items={[
          { label: "Rename", onSelect: () => setOpen("name") },
          {
            label: check.public ? "Make Private" : "Make Public",
            onSelect: flip.isPending ? undefined : () => flip.mutate(),
          },
          { label: "Edit Note", onSelect: () => setOpen("note") },
          {
            label: "Delete",
            destructive: true,
            onSelect: () => setOpen("delete"),
          },
        ]}
      />
      {(open === "name" || open === "note") && (
        <CheckTextDialog
          id={check.id}
          field={open}
          value={(open === "name" ? check.name : check.note) ?? ""}
          onClose={close}
        />
      )}
      {open === "delete" && <DeleteCheck check={check} onClose={close} />}
    </>
  );
}
