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
import { usePrivateRanges, useSavePrivateRanges } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { rangeLines } from "@/lib/security";

const AREA =
  "w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

export function PrivateRangesDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const current = usePrivateRanges(open);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && current.data && (
        <RangesForm
          initial={current.data.ranges}
          onDone={() => onOpenChange(false)}
        />
      )}
      {open && current.error && (
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Addresses that are not public</DialogTitle>
            <DialogDescription>{errorMessage(current.error)}</DialogDescription>
          </DialogHeader>
        </DialogContent>
      )}
    </Dialog>
  );
}

function RangesForm({
  initial,
  onDone,
}: {
  initial: string[];
  onDone: () => void;
}) {
  const save = useSavePrivateRanges();
  const [text, setText] = useState(initial.join("\n"));
  const submit = () =>
    save.mutate(rangeLines(text), {
      onSuccess: () => {
        toast.success("Saved.");
        onDone();
      },
    });
  return (
    <DialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
      <DialogHeader>
        <DialogTitle>Addresses that are not public</DialogTitle>
        <DialogDescription>
          Listeners bound to these ranges are left out of the public-address
          finding on every server. One range per line, such as 10.8.0.0/24.
        </DialogDescription>
      </DialogHeader>
      <textarea
        aria-label="Address ranges"
        value={text}
        rows={6}
        spellCheck={false}
        autoCapitalize="off"
        onChange={(event) => setText(event.target.value)}
        className={AREA}
      />
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
