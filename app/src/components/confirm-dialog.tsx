import type { UseMutationResult } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";

import { useDevices } from "@/lib/api";
import { errorMessage } from "@/lib/http";

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

export function GuardIcon() {
  const core = useDevices().data?.devices.some((device) => device.core);
  return core ? <KeyRound aria-hidden="true" /> : null;
}

export function ConfirmDialog<TData, TVariables>({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  mutation,
  variables,
  onDone,
  guarded = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  mutation: UseMutationResult<TData, Error, TVariables>;
  variables: TVariables;
  onDone?: () => void;
  guarded?: boolean;
}) {
  const close = (next: boolean) => {
    if (!next) mutation.reset();
    onOpenChange(next);
  };
  return (
    <AlertDialog open={open} onOpenChange={close}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {mutation.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(mutation.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            variant="destructive"
            disabled={mutation.isPending}
            onClick={() =>
              mutation.mutate(variables, {
                onSuccess: () => {
                  close(false);
                  onDone?.();
                },
              })
            }
          >
            {guarded && !mutation.isPending && <GuardIcon />}
            {mutation.isPending ? "Working…" : confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
