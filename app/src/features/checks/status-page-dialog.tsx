import { useState } from "react";

import { Busy } from "@/components/busy";
import { Field } from "@/components/field";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useUpdateCheck } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import type { CheckRecord } from "@/types";

const NOTE_LIMIT = 200;

export function StatusPageDialog({
  check,
  open,
  onOpenChange,
}: {
  check: CheckRecord;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <StatusPageForm check={check} onDone={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  );
}

function StatusPageForm({
  check,
  onDone,
}: {
  check: CheckRecord;
  onDone: () => void;
}) {
  const [shown, setShown] = useState(Boolean(check.public));
  const [note, setNote] = useState(check.public_note ?? "");
  const save = useUpdateCheck();
  const changed =
    shown !== Boolean(check.public) ||
    (shown && note.trim() !== (check.public_note ?? ""));

  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(
          {
            id: check.id,
            public: shown,
            ...(shown ? { publicNote: note } : {}),
          },
          { onSuccess: onDone },
        );
      }}
    >
      <DialogHeader>
        <DialogTitle>Status Page</DialogTitle>
        <DialogDescription>
          The public status page shows a check&apos;s name, note, state and
          incidents. Never its kind, target, server or error messages.
        </DialogDescription>
      </DialogHeader>
      <label className="flex min-h-9 cursor-pointer items-center justify-between gap-4 md:min-h-0">
        <span className="text-sm">Show {check.name} on the status page</span>
        <Switch checked={shown} onCheckedChange={setShown} />
      </label>
      {shown && (
        <Field id="public-note" label="Public Note">
          <Input
            id="public-note"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            maxLength={NOTE_LIMIT}
            placeholder="Main website"
          />
          <p className="text-right font-mono text-[11px] text-muted-foreground">
            {note.length}/{NOTE_LIMIT}
          </p>
        </Field>
      )}
      {save.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(save.error)}
        </p>
      )}
      <DialogFooter>
        <Button type="button" variant="ghost" onClick={onDone}>
          Cancel
        </Button>
        <Button type="submit" disabled={save.isPending || !changed}>
          {save.isPending ? <Busy>Saving</Busy> : "Save"}
        </Button>
      </DialogFooter>
    </form>
  );
}
