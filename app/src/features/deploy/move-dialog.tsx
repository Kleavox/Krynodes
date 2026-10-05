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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useOverview, useServices } from "@/lib/api";
import { moveCompose, servicesOf } from "@/lib/compose";
import { orchestrationReady } from "@/lib/devices";
import { errorMessage } from "@/lib/http";
import { moveSteps } from "@/lib/vault";

import { Reading, SHEET, type StackTarget } from "./compose-dialog";
import {
  AccessChoice,
  FullAccessSummary,
  SecretsEditor,
  sealSecrets,
  secretsProblem,
  type Access,
  type SecretRow,
} from "./stack-fields";
import { useComposeRead } from "./use-compose-read";
import { useSignedAction, useSignedOperation } from "./use-signed-action";

type Original = "now" | "later" | "keep";

const ORIGINAL: { value: Original; label: string; detail: string }[] = [
  {
    value: "later",
    label: "Delete later",
    detail: "It waits in Removed for 7 days, then goes.",
  },
  {
    value: "now",
    label: "Delete now",
    detail: "Its containers, volumes and folder are deleted for good.",
  },
  {
    value: "keep",
    label: "Keep it",
    detail: "It keeps running; the move is a copy.",
  },
];

const AREA =
  "w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

export function MoveDialog({
  target,
  open,
  onOpenChange,
}: {
  target: StackTarget;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && <MoveForm source={target} onClose={() => onOpenChange(false)} />}
    </Dialog>
  );
}

function MoveForm({
  source,
  onClose,
}: {
  source: StackTarget;
  onClose: () => void;
}) {
  const { read, failure, retry } = useComposeRead({
    nodeId: source.nodeId,
    name: source.project,
  });
  const services = useServices();
  const overview = useOverview();
  const operate = useSignedOperation(false);
  const entries = new Map(
    (services.data?.nodes ?? []).map((entry) => [entry.id, entry]),
  );
  const servers = (overview.data?.nodes ?? []).filter((node) => {
    const entry = entries.get(node.id);
    return (
      node.id !== source.nodeId &&
      node.enrolled_at !== null &&
      orchestrationReady(node) &&
      entry?.docker === "ready" &&
      entry.sealKey &&
      !entry.stacks.some((stack) => stack.project === source.project) &&
      !(entry.removed ?? []).some((stack) => stack.project === source.project)
    );
  });
  const [server, setServer] = useState<string | null>(null);
  const chosen = server ?? servers[0]?.id ?? "";
  const [access, setAccess] = useState<Access | null>(null);
  const chosenAccess: Access =
    access ?? (read?.access === "full" ? "full" : "contained");
  const all = read ? servicesOf(read.compose) : [];
  const [keep, setKeep] = useState<string[] | null>(null);
  const kept = keep ?? all;
  const moved = read ? moveCompose(read.compose, kept, read.images) : null;
  const [edited, setEdited] = useState<string | null>(null);
  const text = edited ?? moved?.text ?? "";
  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [original, setOriginal] = useState<Original>("later");
  const [sealing, setSealing] = useState(false);
  const problem = secretsProblem(secrets);
  const targetKey = entries.get(chosen)?.sealKey ?? "";

  const toggle = (name: string) => {
    setEdited(null);
    setKeep(
      kept.includes(name)
        ? kept.filter((item) => item !== name)
        : [...kept, name],
    );
  };

  const move = async () => {
    if (!read || !chosen || problem || kept.length === 0) return;
    setSealing(true);
    let sealed: string | undefined;
    try {
      sealed = await sealSecrets(targetKey, secrets);
    } catch (error) {
      toast.error(errorMessage(error));
      return;
    } finally {
      setSealing(false);
    }
    operate.mutate(
      {
        kind: "move",
        reach: [source.nodeId, chosen],
        build: () =>
          moveSteps({
            source: source.nodeId,
            target: chosen,
            targetKey,
            project: source.project,
            compose: text,
            access: chosenAccess,
            ...(sealed ? { secrets: sealed } : {}),
            original,
          }),
      },
      {
        onSuccess: () => {
          toast.success(`Moving ${source.project}.`);
          onClose();
        },
      },
    );
  };

  return (
    <DialogContent className={SHEET}>
      <DialogHeader>
        <DialogTitle>
          Move {source.project} from {source.nodeName}
        </DialogTitle>
        <DialogDescription>
          The compose file, its secrets and small files beside it move; app data
          starts fresh. Images are pinned to the versions running now.
        </DialogDescription>
      </DialogHeader>
      {!read ? (
        <Reading server={source.nodeName} failure={failure} retry={retry} />
      ) : servers.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No other server runs agent 0.5.0 with Docker and a free name{" "}
          {source.project}.
        </p>
      ) : (
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="move-server">To</Label>
            <Select value={chosen} onValueChange={setServer}>
              <SelectTrigger id="move-server" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {servers.map((node) => (
                  <SelectItem key={node.id} value={node.id}>
                    {node.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Access there</Label>
            <AccessChoice value={chosenAccess} onChange={setAccess} />
          </div>
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">Services that move</legend>
            <div className="flex flex-wrap gap-3">
              {all.map((name) => (
                <label
                  key={name}
                  className="flex items-center gap-2 font-mono text-xs"
                >
                  <input
                    type="checkbox"
                    checked={kept.includes(name)}
                    onChange={() => toggle(name)}
                  />
                  {name}
                </label>
              ))}
            </div>
          </fieldset>
          {moved && moved.flagged.length > 0 && (
            <ul className="list-disc space-y-1 rounded-md border border-warning/40 bg-warning/5 p-3 pl-7 text-xs">
              {moved.flagged.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          )}
          <div className="space-y-1.5">
            <Label htmlFor="move-compose">Compose file there</Label>
            <textarea
              id="move-compose"
              value={text}
              rows={14}
              spellCheck={false}
              onChange={(event) => setEdited(event.target.value)}
              className={AREA}
            />
          </div>
          {chosenAccess === "full" && <FullAccessSummary text={text} />}
          <div className="space-y-1.5">
            <Label>More secrets</Label>
            <SecretsEditor rows={secrets} onChange={setSecrets} />
            {problem && <p className="text-xs text-destructive">{problem}</p>}
          </div>
          <div
            role="radiogroup"
            aria-label="The original"
            className="space-y-2"
          >
            <p className="text-sm font-medium">
              The original on {source.nodeName}, once the move runs
            </p>
            {ORIGINAL.map((option) => (
              <label
                key={option.value}
                className="flex cursor-pointer gap-2 rounded-md border px-3 py-2"
              >
                <input
                  type="radio"
                  name="move-original"
                  checked={original === option.value}
                  onChange={() => setOriginal(option.value)}
                />
                <span>
                  <span className="block text-sm font-medium">
                    {option.label}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {option.detail}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </div>
      )}
      {operate.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(operate.error)}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          disabled={
            !read ||
            !chosen ||
            kept.length === 0 ||
            problem !== null ||
            sealing ||
            operate.isPending
          }
          onClick={() => void move()}
        >
          {!operate.isPending && <Fingerprint aria-hidden="true" />}
          {operate.isPending ? "Waiting for the fingerprint…" : "Move"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

export function AdoptDialog({
  target,
  directory,
  open,
  onOpenChange,
}: {
  target: StackTarget;
  directory: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const run = useSignedAction(false);
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <AlertDialogHeader>
          <AlertDialogTitle>
            Move {target.project} into Krynodes?
          </AlertDialogTitle>
          <AlertDialogDescription>
            Krynodes stops it, copies {directory} into its own folder and starts
            it from the copy. The old folder stays as it is. The stack becomes
            Full access, as it ran before.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {run.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(run.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            disabled={run.isPending}
            onClick={() =>
              run.mutate(
                {
                  action: "adopt",
                  targets: [
                    {
                      nodeId: target.nodeId,
                      kind: "compose",
                      name: target.project,
                    },
                  ],
                },
                { onSuccess: () => onOpenChange(false) },
              )
            }
          >
            {run.isPending
              ? "Waiting for the fingerprint…"
              : "Move into Krynodes"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
