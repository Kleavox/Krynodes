import { MIN_AGENT_VERSION } from "@krynodes/protocol/versions";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Waiting } from "@/components/busy";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useNetwork, useOverview, useServices } from "@/lib/api";
import { moveLines } from "@/lib/bridges";
import { moveCompose, servicesOf } from "@/lib/compose";
import { agentCurrent } from "@/lib/devices";
import { errorMessage } from "@/lib/http";
import {
  hostingOf,
  inside,
  moveBlock,
  moveProblem,
  privateIpProblem,
  readServes,
  servesArg,
} from "@/lib/network";
import { moveBlocker, moveConfirmed } from "@/lib/stacks";
import { cn } from "@/lib/utils";
import { moveSteps } from "@/lib/vault";
import type { WebAddress } from "@/types";

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
    label: "Delete Later",
    detail: "It waits in Removed for 7 days, then goes.",
  },
  {
    value: "now",
    label: "Delete Now",
    detail: "Its containers, volumes and folder are deleted for good.",
  },
  {
    value: "keep",
    label: "Keep It",
    detail: "It keeps running; the move is a copy.",
  },
];

const AREA =
  "w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

export function MoveDialog({
  target,
  addresses,
  open,
  onOpenChange,
}: {
  target: StackTarget;
  addresses: WebAddress[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <MoveForm
          source={target}
          addresses={addresses}
          onClose={() => onOpenChange(false)}
        />
      )}
    </Dialog>
  );
}

function MoveForm({
  source,
  addresses,
  onClose,
}: {
  source: StackTarget;
  addresses: WebAddress[];
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
      agentCurrent(node) &&
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
  const [typed, setTyped] = useState("");
  const [sealing, setSealing] = useState(false);
  const [skipped, setSkipped] = useState<string[]>([]);
  const view = useNetwork().data;
  const there =
    (view && inside(view).find((member) => member.nodeId === chosen)) ?? null;
  const targetName =
    servers.find((node) => node.id === chosen)?.name ?? "the server";
  const stack = entries
    .get(source.nodeId)
    ?.stacks.find((entry) => entry.project === source.project);
  const block =
    view && chosen
      ? moveBlock(
          {
            project: source.project,
            network:
              stack?.network && chosenAccess === "full"
                ? { ...stack.network, serves: [], reaches: [] }
                : stack?.network,
          },
          { nodeId: source.nodeId, name: source.nodeName },
          { nodeId: chosen, name: targetName },
          view,
          hostingOf(services.data?.nodes ?? [], overview.data?.nodes ?? []),
        )
      : null;
  const bridging = stack
    ? moveLines(
        stack,
        {
          name: source.nodeName,
          bridges: entries.get(source.nodeId)?.bridges ?? null,
          stacks: entries.get(source.nodeId)?.stacks ?? [],
        },
        { name: targetName, bridges: entries.get(chosen)?.bridges ?? null },
      )
    : { lines: [], refusal: null, creates: [] };
  const changes = (block?.changes ?? []).filter(
    (change) => !skipped.includes(`${change.nodeId}:${change.project}`),
  );
  const secretsWrong = secretsProblem(secrets);
  const privateWrong = privateIpProblem(text, targetName, there !== null);
  const tooMany = block && !block.red ? moveProblem(changes) : null;
  const problem = secretsWrong ?? privateWrong ?? tooMany ?? bridging.refusal;
  const carried = chosenAccess === "contained" ? (read?.hostPorts ?? []) : [];
  const blocked = moveBlocker(addresses, original);
  const targetKey = entries.get(chosen)?.sealKey ?? "";
  const skip = (key: string) =>
    setSkipped(
      skipped.includes(key)
        ? skipped.filter((item) => item !== key)
        : [...skipped, key],
    );

  const toggle = (name: string) => {
    setEdited(null);
    setKeep(
      kept.includes(name)
        ? kept.filter((item) => item !== name)
        : [...kept, name],
    );
  };

  const move = async () => {
    if (!read || !chosen || problem || blocked || kept.length === 0) return;
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
        reach: [
          source.nodeId,
          chosen,
          ...changes.map((change) => change.nodeId),
        ],
        build: () =>
          moveSteps({
            source: source.nodeId,
            target: chosen,
            targetKey,
            project: source.project,
            compose: text,
            access: chosenAccess,
            ...(sealed ? { secrets: sealed } : {}),
            hostPorts: carried,
            networks: bridging.creates,
            offers: stack?.network?.offers?.join(",") ?? "",
            title: stack?.title ?? "",
            names: Object.entries(stack?.names ?? {})
              .map(([service, name]) => `${service}=${name}`)
              .join(","),
            peers:
              chosenAccess === "contained"
                ? (stack?.network?.peers?.join(",") ?? "")
                : "",
            ...(block && !block.red
              ? {
                  serves: servesArg(
                    readServes(
                      block.serves,
                      block.serves.map((serve) => serve.port),
                    ),
                  ),
                  reaches: block.reaches.join(","),
                  reach: changes,
                }
              : {}),
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
          No other server runs agent {MIN_AGENT_VERSION} with Docker and a free
          name {source.project}.
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
            <Label>Access There</Label>
            <AccessChoice value={chosenAccess} onChange={setAccess} />
          </div>
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">Services That Move</legend>
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
            <Label htmlFor="move-compose">Compose File There</Label>
            <textarea
              id="move-compose"
              value={text}
              rows={14}
              spellCheck={false}
              onChange={(event) => setEdited(event.target.value)}
              className={AREA}
            />
          </div>
          {privateWrong && (
            <p className="text-xs text-destructive">{privateWrong}</p>
          )}
          {chosenAccess === "full" && (
            <FullAccessSummary text={text} member={there} onText={setEdited} />
          )}
          {block && (
            <div
              className={cn(
                "space-y-2 rounded-md border p-3 text-xs",
                block.red && "border-destructive/40 bg-destructive/5",
              )}
            >
              <p className="text-sm font-medium">Private Network</p>
              {block.red ? (
                <p className="text-destructive">{block.red}</p>
              ) : (
                <>
                  {block.lines.map((line) => (
                    <p key={line}>{line}</p>
                  ))}
                  {block.changes.map((change) => {
                    const key = `${change.nodeId}:${change.project}`;
                    return (
                      <label key={key} className="flex items-start gap-2">
                        <input
                          type="checkbox"
                          className="mt-0.5 size-4 shrink-0 accent-primary"
                          checked={!skipped.includes(key)}
                          onChange={() => skip(key)}
                        />
                        <span className="min-w-0 break-words">
                          {change.text}
                        </span>
                      </label>
                    );
                  })}
                  {block.note && (
                    <p className="text-muted-foreground">{block.note}</p>
                  )}
                  {tooMany && <p className="text-destructive">{tooMany}</p>}
                </>
              )}
            </div>
          )}
          {(bridging.lines.length > 0 || bridging.refusal) && (
            <div
              className={cn(
                "space-y-2 rounded-md border p-3 text-xs",
                bridging.refusal && "border-destructive/40 bg-destructive/5",
              )}
            >
              <p className="text-sm font-medium">Docker Networks</p>
              {bridging.refusal ? (
                <p className="text-destructive">{bridging.refusal}</p>
              ) : (
                bridging.lines.map((line) => (
                  <p
                    key={line}
                    className={line.startsWith("+") ? "" : "text-warning"}
                  >
                    {line}
                  </p>
                ))
              )}
            </div>
          )}
          <div className="space-y-1.5">
            <Label>More Secrets</Label>
            <SecretsEditor rows={secrets} onChange={setSecrets} />
            {secretsWrong && (
              <p className="text-xs text-destructive">{secretsWrong}</p>
            )}
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
            {original === "now" && (
              <div className="space-y-1.5">
                <Label htmlFor="move-confirm">
                  Type {source.project} to delete the original for good
                </Label>
                <Input
                  id="move-confirm"
                  value={typed}
                  autoComplete="off"
                  onChange={(event) => setTyped(event.target.value)}
                />
              </div>
            )}
            {blocked && <p className="text-sm text-destructive">{blocked}</p>}
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
            blocked !== null ||
            !moveConfirmed(original, typed, source.project) ||
            sealing ||
            operate.isPending
          }
          onClick={() => void move()}
        >
          <KeyRound aria-hidden="true" />
          {operate.isPending ? <Waiting /> : "Move"}
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
            {run.isPending ? <Waiting /> : "Move into Krynodes"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
