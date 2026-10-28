import type { BridgesReport } from "@krynodes/protocol";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Waiting } from "@/components/busy";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { nameLine, pickSubnet, subnetLine, type Access } from "@/lib/bridges";
import { errorMessage } from "@/lib/http";
import { cn } from "@/lib/utils";
import type { StackEntry } from "@/types";

interface Server {
  name: string;
  bridges: BridgesReport | null;
  stacks: StackEntry[];
}

interface Value {
  name: string;
  kind: Access;
  subnet: string;
}

const KINDS: { value: Access; label: string; detail: string }[] = [
  {
    value: "contained",
    label: "Contained",
    detail: "Contained stacks only. Full Access stacks join as guests.",
  },
  {
    value: "full",
    label: "Full Access",
    detail: "A plain bridge. Contained stacks cannot join it.",
  },
];

const EMPTY: Value = { name: "", kind: "contained", subnet: "" };

const LINE = "text-xs";

export function CreateNetworkForm({
  server,
  privateRange,
  value,
  onChange,
  pending,
  error,
  onCreate,
  onCancel,
}: {
  server: Server;
  privateRange: string | null;
  value: Value;
  onChange: (value: Value) => void;
  pending: boolean;
  error?: string | null;
  onCreate: () => void;
  onCancel: () => void;
}) {
  const name = nameLine(value.name, server);
  const subnet = subnetLine(value.subnet, server, privateRange);
  const typed = value.name.trim() !== "";
  return (
    <div className="grid gap-4">
      <div className="grid gap-1.5">
        <label htmlFor="network-name" className="text-sm font-medium">
          Name
        </label>
        <Input
          id="network-name"
          className="font-mono"
          autoComplete="off"
          spellCheck={false}
          value={value.name}
          aria-invalid={typed && !name.ok}
          onChange={(event) => onChange({ ...value, name: event.target.value })}
        />
        <span
          className={cn(
            LINE,
            typed && !name.ok ? "text-destructive" : "text-muted-foreground",
          )}
        >
          {name.text}
        </span>
      </div>
      <div className="grid gap-1.5">
        <span id="network-kind" className="text-sm font-medium">
          Kind
        </span>
        <div
          role="radiogroup"
          aria-labelledby="network-kind"
          className="grid gap-2 sm:grid-cols-2"
        >
          {KINDS.map((option) => (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={value.kind === option.value}
              onClick={() => onChange({ ...value, kind: option.value })}
              className={cn(
                "rounded-md border px-3 py-2 text-left transition-colors",
                value.kind === option.value
                  ? "border-primary bg-primary/10"
                  : "hover:bg-muted/50",
              )}
            >
              <span className="block text-sm font-medium">{option.label}</span>
              <span className="block text-xs text-muted-foreground">
                {option.detail}
              </span>
            </button>
          ))}
        </div>
      </div>
      {value.kind === "contained" && (
        <div className="grid gap-2 rounded-md border p-3.5 text-xs text-muted-foreground">
          <span className="text-[13px] font-medium text-foreground">
            On a Contained Network
          </span>
          <span>
            Members reach each other only on the ports they offer, and only when
            a Contained stack chooses to reach them.
          </span>
          <span>
            Nothing leaves through it. The internet and the server stay on each
            stack&apos;s own network.
          </span>
          <span>Guests answer; they never start a connection here.</span>
        </div>
      )}
      <div className="grid gap-1.5">
        <label htmlFor="network-subnet" className="text-sm font-medium">
          Subnet
        </label>
        <Input
          id="network-subnet"
          className="font-mono"
          autoComplete="off"
          spellCheck={false}
          placeholder="Leave empty for a free one"
          value={value.subnet}
          aria-invalid={!subnet.ok}
          onChange={(event) =>
            onChange({ ...value, subnet: event.target.value })
          }
        />
        <span
          className={cn(
            LINE,
            !subnet.ok
              ? "text-destructive"
              : value.subnet.trim() === ""
                ? "text-muted-foreground"
                : "text-success",
          )}
        >
          {subnet.text}
        </span>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button disabled={pending || !name.ok || !subnet.ok} onClick={onCreate}>
          <KeyRound aria-hidden="true" />
          {pending ? <Waiting /> : "Create"}
        </Button>
      </div>
    </div>
  );
}

export function CreateNetworkDialog({
  nodeId,
  server,
  privateRange,
  open,
  onOpenChange,
}: {
  nodeId: string;
  server: Server;
  privateRange: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const run = useSignedAction(false);
  const [value, setValue] = useState<Value>(EMPTY);
  const close = (next: boolean) => {
    if (!next) {
      run.reset();
      setValue(EMPTY);
    }
    onOpenChange(next);
  };
  const create = () => {
    const name = value.name.trim();
    const subnet =
      value.subnet.trim() ||
      pickSubnet(server.bridges?.taken ?? [], privateRange) ||
      "";
    run.mutate(
      {
        action: "create",
        targets: [
          {
            nodeId,
            kind: "bridge",
            name,
            args: { kind: value.kind, subnet },
          },
        ],
      },
      {
        onSuccess: () => {
          toast.success(`Creating ${name} on ${server.name}.`);
          close(false);
        },
      },
    );
  };
  return (
    <AlertDialog open={open} onOpenChange={close}>
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <AlertDialogHeader>
          <AlertDialogTitle>Create Network on {server.name}</AlertDialogTitle>
          <AlertDialogDescription>
            Stacks join it by name in their compose file.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <CreateNetworkForm
          server={server}
          privateRange={privateRange}
          value={value}
          onChange={setValue}
          pending={run.isPending}
          error={run.error ? errorMessage(run.error) : null}
          onCreate={create}
          onCancel={() => close(false)}
        />
      </AlertDialogContent>
    </AlertDialog>
  );
}
