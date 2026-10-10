import { useState, type FormEvent } from "react";

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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  useCreateCheck,
  useOverview,
  useServices,
  useUpdateCheck,
} from "@/lib/api";
import {
  checkTargetProblem,
  containerChecksReady,
  pickedKind,
  TARGET_HINT,
  TARGET_PLACEHOLDER,
  targetOptions,
} from "@/lib/checks";
import { errorMessage } from "@/lib/http";
import { cn } from "@/lib/utils";
import type { CheckKind, CheckRecord, NodeRecord } from "@/types";

import { TargetPicker } from "./target-picker";

const KINDS: { value: CheckKind; label: string }[] = [
  { value: "HTTP", label: "HTTP" },
  { value: "TCP", label: "TCP" },
  { value: "SERVICE", label: "Systemd" },
  { value: "CONTAINER", label: "Docker" },
];

const EMPTY: Partial<Record<CheckKind, string>> = {
  SERVICE: "No systemd services on this server.",
  CONTAINER: "No Docker containers on this server.",
};

const SEARCH: Partial<Record<CheckKind, string>> = {
  SERVICE: "Search services",
  CONTAINER: "Search containers",
};
const TIMEOUTS = [5, 10, 15, 20, 30];

export function CheckDialog({
  open,
  onOpenChange,
  check,
  nodeId,
  nodes = [],
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  check?: CheckRecord;
  nodeId?: string;
  nodes?: NodeRecord[];
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <CheckForm
          check={check}
          nodeId={nodeId}
          nodes={nodes}
          onDone={() => onOpenChange(false)}
        />
      )}
    </Dialog>
  );
}

function CheckForm({
  check,
  nodeId,
  nodes,
  onDone,
}: {
  check?: CheckRecord;
  nodeId?: string;
  nodes: NodeRecord[];
  onDone: () => void;
}) {
  const create = useCreateCheck();
  const update = useUpdateCheck();
  const mutation = check ? update : create;
  const [node, setNode] = useState(check?.node_id ?? nodeId ?? "");
  const [name, setName] = useState(check?.name ?? "");
  const [kind, setKind] = useState<CheckKind>(check?.kind ?? "HTTP");
  const [target, setTarget] = useState(check?.target ?? "");
  const [seconds, setSeconds] = useState(check?.timeout_seconds ?? 10);
  const [touched, setTouched] = useState(false);
  const overview = useOverview();
  const services = useServices();
  const problem = checkTargetProblem(kind, target);
  const showProblem = touched && problem !== null;
  const choosesNode = Boolean(check) || !nodeId;
  const enrolled = nodes.filter(
    (entry) => entry.enrolled_at !== null && entry.disabled_at === null,
  );
  const known = nodes.length > 0 ? nodes : (overview.data?.nodes ?? []);
  const dockerReady =
    check?.kind === "CONTAINER" ||
    containerChecksReady(
      known.find((entry) => entry.id === node)?.agent_version ?? null,
    );
  const listed = (nextNode: string) =>
    services.data?.nodes.find((entry) => entry.id === nextNode)?.services;
  const options = targetOptions(listed(node), kind, target);
  const fits = (nextKind: CheckKind, nextNode: string) =>
    pickedKind(nextKind)
      ? targetOptions(listed(nextNode), nextKind, "").some(
          (option) => option.name === target,
        )
      : !pickedKind(kind);
  const chooseKind = (value: CheckKind) => {
    if (!fits(value, node)) setTarget("");
    setKind(value);
  };
  const chooseNode = (value: string) => {
    if (!fits(kind, value)) setTarget("");
    setNode(value);
  };
  const fresh =
    check !== undefined &&
    (kind !== check.kind ||
      target.trim() !== check.target ||
      node !== check.node_id);
  const changed =
    !check ||
    fresh ||
    name.trim() !== check.name ||
    seconds !== check.timeout_seconds;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (problem || !node || name.trim() === "") return;
    const fields = {
      name: name.trim(),
      kind,
      target: target.trim(),
      timeoutSeconds: seconds,
    };
    if (check) {
      update.mutate(
        { id: check.id, nodeId: node, ...fields },
        { onSuccess: onDone },
      );
    } else {
      create.mutate({ nodeId: node, ...fields }, { onSuccess: onDone });
    }
  };

  return (
    <DialogContent className="max-h-[92dvh] overflow-y-auto max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
      <form className="space-y-4" onSubmit={submit} noValidate>
        <DialogHeader>
          <DialogTitle>
            {check ? `Edit ${check.name}` : "Add check"}
          </DialogTitle>
          <DialogDescription>
            {check
              ? "Servers with a live connection pick it up at once; the rest at their next report."
              : "The agent on the node runs it on every cycle."}
          </DialogDescription>
        </DialogHeader>
        {choosesNode && (
          <Field id="check-node" label="Runs on">
            <Select value={node} onValueChange={chooseNode}>
              <SelectTrigger id="check-node" className="w-full">
                <SelectValue placeholder="Choose a node" />
              </SelectTrigger>
              <SelectContent>
                {enrolled.map((entry) => (
                  <SelectItem key={entry.id} value={entry.id}>
                    {entry.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        )}
        <Field id="check-name" label="Name">
          <Input
            id="check-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Public API"
            maxLength={100}
            required
            aria-invalid={touched && name.trim() === ""}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Field id="check-kind" label="Kind">
            <Select
              value={kind}
              onValueChange={(value) => chooseKind(value as CheckKind)}
            >
              <SelectTrigger id="check-kind" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {KINDS.map((entry) =>
                  entry.value === "CONTAINER" && !dockerReady ? (
                    <SelectItem key={entry.value} value={entry.value} disabled>
                      {entry.label} · Needs agent 0.6.3 or newer
                    </SelectItem>
                  ) : (
                    <SelectItem key={entry.value} value={entry.value}>
                      {entry.label}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
          </Field>
          <Field id="check-timeout" label="Timeout">
            <Select
              value={String(seconds)}
              onValueChange={(value) => setSeconds(Number(value))}
            >
              <SelectTrigger id="check-timeout" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {[...new Set([...TIMEOUTS, seconds])]
                  .sort((a, b) => a - b)
                  .map((option) => (
                    <SelectItem key={option} value={String(option)}>
                      {option} seconds
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </Field>
        </div>
        <div className="space-y-2">
          <Field id="check-target" label="Target">
            {pickedKind(kind) ? (
              <TargetPicker
                id="check-target"
                options={node ? options : []}
                value={target}
                onChange={setTarget}
                placeholder={TARGET_PLACEHOLDER[kind]}
                empty={node ? EMPTY[kind]! : "Choose a node first."}
                search={SEARCH[kind]!}
                invalid={showProblem}
                describedBy="check-target-hint"
              />
            ) : (
              <Input
                id="check-target"
                className="font-mono"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                onBlur={() => setTouched(true)}
                placeholder={TARGET_PLACEHOLDER[kind]}
                maxLength={2048}
                required
                aria-invalid={showProblem}
                aria-describedby="check-target-hint"
                spellCheck={false}
                autoCapitalize="off"
              />
            )}
          </Field>
          <p
            id="check-target-hint"
            className={cn(
              "text-xs",
              showProblem ? "text-destructive" : "text-muted-foreground",
            )}
          >
            {showProblem ? problem : TARGET_HINT[kind]}
          </p>
        </div>
        {fresh && (
          <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
            Changing the kind, target or node starts the status fresh and closes
            an open incident. Its history stays.
          </p>
        )}
        {mutation.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(mutation.error)}
          </p>
        )}
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onDone}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending || !changed}>
            {mutation.isPending
              ? "Saving…"
              : check
                ? "Save changes"
                : "Add check"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
