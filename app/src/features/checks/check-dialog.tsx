import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";

import { Busy } from "@/components/busy";
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
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { checksApi, useRefreshStacks } from "@/lib/api";
import { errorMessage } from "@/lib/http";

function Shell({
  heading,
  body,
  confirm,
  pending,
  error,
  disabled,
  onSubmit,
  onClose,
  children,
}: {
  heading: string;
  body: string;
  confirm: string;
  pending: boolean;
  error: unknown;
  disabled: boolean;
  onSubmit: () => void;
  onClose: () => void;
  children: ReactNode;
}) {
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!disabled) onSubmit();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{heading}</DialogTitle>
            <DialogDescription>{body}</DialogDescription>
          </DialogHeader>
          {children}
          {error !== null && (
            <p role="alert" className="text-sm text-destructive">
              {errorMessage(error)}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={disabled || pending}>
              {pending ? <Busy>Saving</Busy> : confirm}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function AddCheckDialog({
  nodeId,
  server,
  containers,
  onClose,
}: {
  nodeId: string;
  server: string;
  containers: string[];
  onClose: () => void;
}) {
  const refresh = useRefreshStacks();
  const [container, setContainer] = useState(containers[0] ?? "");
  const [name, setName] = useState(containers[0] ?? "");
  const add = useMutation({
    mutationFn: () => checksApi.add({ nodeId, container, name: name.trim() }),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <Shell
      heading="Add Check"
      body={`${server} tells the dashboard when this container stops running or turns unhealthy.`}
      confirm="Add Check"
      pending={add.isPending}
      error={add.error}
      disabled={container === "" || name.trim() === ""}
      onSubmit={() => add.mutate()}
      onClose={onClose}
    >
      <div className="space-y-2">
        <Label htmlFor="check-container">Container</Label>
        <Select
          value={container}
          onValueChange={(value) => {
            if (name === container) setName(value);
            setContainer(value);
          }}
        >
          <SelectTrigger id="check-container" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {containers.map((one) => (
              <SelectItem key={one} value={one}>
                {one}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-2">
        <Label htmlFor="check-name">Name</Label>
        <Input
          id="check-name"
          value={name}
          maxLength={64}
          onChange={(event) => setName(event.target.value)}
        />
      </div>
    </Shell>
  );
}

export function CheckTextDialog({
  id,
  field,
  value,
  onClose,
}: {
  id: string;
  field: "name" | "note";
  value: string;
  onClose: () => void;
}) {
  const refresh = useRefreshStacks();
  const [text, setText] = useState(value);
  const save = useMutation({
    mutationFn: () =>
      checksApi.change(
        id,
        field === "name"
          ? { name: text.trim() }
          : { note: text.trim() === "" ? null : text.trim() },
      ),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  const naming = field === "name";
  return (
    <Shell
      heading={naming ? "Rename Check" : "Edit Note"}
      body={
        naming
          ? "The name shows here and, when the check is public, on the status page."
          : "A public check shows its note on the status page. Leave it blank for none."
      }
      confirm="Save"
      pending={save.isPending}
      error={save.error}
      disabled={naming && text.trim() === ""}
      onSubmit={() => save.mutate()}
      onClose={onClose}
    >
      <div className="space-y-2">
        <Label htmlFor="check-text">{naming ? "Name" : "Note"}</Label>
        <Input
          id="check-text"
          value={text}
          maxLength={naming ? 64 : 280}
          onChange={(event) => setText(event.target.value)}
        />
      </div>
    </Shell>
  );
}
