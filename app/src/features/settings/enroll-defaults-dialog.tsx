import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { SetupOptions } from "@/features/nodes/setup-options";
import {
  useEnrollDefaults,
  useSaveEnrollDefaults,
  type EnrollDefaults,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";

export function EnrollDefaultsDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const current = useEnrollDefaults(open);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && current.data && (
        <DefaultsForm
          initial={current.data}
          onDone={() => onOpenChange(false)}
        />
      )}
      {open && current.error && (
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enroll defaults</DialogTitle>
            <DialogDescription>{errorMessage(current.error)}</DialogDescription>
          </DialogHeader>
        </DialogContent>
      )}
    </Dialog>
  );
}

function DefaultsForm({
  initial,
  onDone,
}: {
  initial: EnrollDefaults;
  onDone: () => void;
}) {
  const save = useSaveEnrollDefaults();
  const [value, setValue] = useState(initial);
  const submit = () =>
    save.mutate(value, {
      onSuccess: () => {
        toast.success("Saved.");
        onDone();
      },
    });
  return (
    <DialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
      <DialogHeader>
        <DialogTitle>Enroll defaults</DialogTitle>
        <DialogDescription>
          What a new install command sets up. You can still change it for one
          server when you enroll it.
        </DialogDescription>
      </DialogHeader>
      <SetupOptions value={value} onChange={setValue} />
      {save.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(save.error)}
        </p>
      )}
      <DialogFooter>
        <Button type="button" variant="ghost" onClick={onDone}>
          Cancel
        </Button>
        <Button type="button" disabled={save.isPending} onClick={submit}>
          {save.isPending ? "Saving…" : "Save"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
