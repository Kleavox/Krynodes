import { Fingerprint } from "lucide-react";
import { useState } from "react";

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
import { useAction, useServices } from "@/lib/api";
import { orchestrationReady } from "@/lib/devices";
import { errorMessage } from "@/lib/http";
import { toast } from "sonner";
import { isPending } from "@/lib/services";
import { newStackBlocker, stackNameProblem } from "@/lib/stacks";
import type { NodeRecord } from "@/types";

import {
  AccessChoice,
  FullAccessSummary,
  SecretsEditor,
  sealSecrets,
  secretsProblem,
  type Access,
  type SecretRow,
} from "./stack-fields";
import { useSignedAction } from "./use-signed-action";

const LIMIT = 32 * 1024;

const SHEET =
  "max-h-[92dvh] overflow-y-auto max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none sm:max-w-xl";

export function NewStackDialog({
  open,
  onOpenChange,
  nodes,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  nodes: NodeRecord[];
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <NewStackForm nodes={nodes} onClose={() => onOpenChange(false)} />
      )}
    </Dialog>
  );
}

function NewStackForm({
  nodes,
  onClose,
}: {
  nodes: NodeRecord[];
  onClose: () => void;
}) {
  const services = useServices();
  const run = useSignedAction(false);
  const entries = new Map(
    (services.data?.nodes ?? []).map((entry) => [entry.id, entry]),
  );
  const choices = nodes.map((node) => ({
    node,
    blocker: newStackBlocker(node, entries.get(node.id)),
  }));
  const [nodeId, setNodeId] = useState(
    () => choices.find((choice) => choice.blocker === null)?.node.id ?? "",
  );
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const [touched, setTouched] = useState(false);
  const [access, setAccess] = useState<Access>("contained");
  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [sealing, setSealing] = useState(false);
  const [actionId, setActionId] = useState<string | null>(null);
  const action = useAction(actionId).data?.action;

  const chosen = choices.find((choice) => choice.node.id === nodeId);
  const sealKey = entries.get(nodeId)?.sealKey ?? null;
  const modern = chosen !== undefined && orchestrationReady(chosen.node);
  const taken = (entries.get(nodeId)?.stacks ?? []).map(
    (stack) => stack.project,
  );
  const waiting = (entries.get(nodeId)?.removed ?? []).map(
    (stack) => stack.project,
  );
  const nameProblem = stackNameProblem(name.trim(), taken, waiting);
  const size = new TextEncoder().encode(text).length;
  const textProblem = !text.trim()
    ? "Paste the compose file."
    : size > LIMIT
      ? "The compose file is larger than 32 KB."
      : null;
  const ready =
    chosen !== undefined &&
    chosen.blocker === null &&
    nameProblem === null &&
    textProblem === null &&
    (!modern || secretsProblem(secrets) === null);

  const create = async () => {
    setTouched(true);
    if (!ready) return;
    setSealing(true);
    let sealed: string | undefined;
    try {
      sealed =
        modern && sealKey ? await sealSecrets(sealKey, secrets) : undefined;
    } catch (error) {
      toast.error(errorMessage(error));
      return;
    } finally {
      setSealing(false);
    }
    run.mutate(
      {
        action: "create",
        targets: [
          {
            nodeId,
            kind: "compose",
            name: name.trim(),
            compose: text,
            ...(modern ? { access } : {}),
            ...(sealed ? { secrets: sealed } : {}),
          },
        ],
      },
      { onSuccess: (batch) => setActionId(batch.actions[0]?.id ?? null) },
    );
  };

  if (actionId) {
    const server = chosen?.node.name ?? "the server";
    const waiting = !action || isPending(action);
    const failed =
      action && (action.status === "failed" || action.status === "expired");
    return (
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>
            {failed
              ? `${name.trim()} was not created`
              : waiting
                ? `Creating ${name.trim()} on ${server}`
                : `${name.trim()} runs on ${server}`}
          </DialogTitle>
          <DialogDescription>
            {waiting
              ? action?.status === "sent"
                ? "Pulling images and starting the containers. This can take a few minutes."
                : `Waiting for ${server} to pick it up.`
              : failed
                ? "The server explained why:"
                : "It shows under Stacks within a minute, with Deploy, Logs and Remove."}
          </DialogDescription>
        </DialogHeader>
        {failed && (
          <pre className="max-h-48 overflow-auto rounded-md border bg-background p-3 font-mono text-xs whitespace-pre-wrap text-destructive">
            {action.output || "No reason given."}
          </pre>
        )}
        <DialogFooter>
          <Button variant={failed ? "outline" : "default"} onClick={onClose}>
            {waiting || failed ? "Close" : "Done"}
          </Button>
          {failed && (
            <Button onClick={() => setActionId(null)}>
              Edit and try again
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    );
  }

  return (
    <DialogContent className={SHEET}>
      <DialogHeader>
        <DialogTitle>New stack</DialogTitle>
        <DialogDescription>
          Paste a Docker Compose file. The server checks it, pulls its images
          and starts it.
        </DialogDescription>
      </DialogHeader>
      <div className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="stack-name">Name</Label>
          <Input
            id="stack-name"
            value={name}
            placeholder="uptime-kuma"
            autoComplete="off"
            aria-invalid={touched && nameProblem !== null}
            aria-describedby={
              touched && nameProblem ? "stack-name-problem" : undefined
            }
            onChange={(event) => setName(event.target.value)}
          />
          {touched && nameProblem && (
            <p id="stack-name-problem" className="text-xs text-destructive">
              {nameProblem}
            </p>
          )}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="stack-server">Server</Label>
          <Select value={nodeId} onValueChange={setNodeId}>
            <SelectTrigger id="stack-server" className="w-full">
              <SelectValue placeholder="Choose a server" />
            </SelectTrigger>
            <SelectContent>
              {choices.map(({ node, blocker }) => (
                <SelectItem
                  key={node.id}
                  value={node.id}
                  disabled={blocker !== null}
                >
                  {node.name}
                  {blocker && (
                    <span className="text-muted-foreground"> · {blocker}</span>
                  )}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="stack-file">compose.yml</Label>
          <textarea
            id="stack-file"
            value={text}
            rows={12}
            spellCheck={false}
            placeholder={
              'services:\n  web:\n    image: louislam/uptime-kuma:1\n    ports:\n      - "3001:3001"'
            }
            aria-invalid={touched && textProblem !== null}
            aria-describedby="stack-file-notes"
            onChange={(event) => setText(event.target.value)}
            className="w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 aria-invalid:border-destructive"
          />
          {touched && textProblem && (
            <p className="text-xs text-destructive">{textProblem}</p>
          )}
          {access === "contained" || !modern ? (
            <ul
              id="stack-file-notes"
              className="list-disc space-y-1 pl-4 text-xs text-muted-foreground"
            >
              <li>
                Ready images only; a file that builds from source is refused.
              </li>
              <li>
                Refused too: privileged mode, the server&rsquo;s network or
                processes, devices, extra capabilities, and mounts outside the
                stack&rsquo;s own folder.
              </li>
              <li>
                Ports open on the server itself (127.0.0.1). Open one to your
                browser with Web address in the stack&rsquo;s menu.
              </li>
              <li>
                The file is kept with the action in History for 90 days; put
                passwords under Secrets.
              </li>
            </ul>
          ) : (
            <div id="stack-file-notes">
              <FullAccessSummary text={text} />
            </div>
          )}
        </div>
        {modern && (
          <>
            <div className="space-y-1.5">
              <Label>Access</Label>
              <AccessChoice value={access} onChange={setAccess} />
            </div>
            <div className="space-y-1.5">
              <Label>Secrets</Label>
              <SecretsEditor rows={secrets} onChange={setSecrets} />
              {touched && secretsProblem(secrets) && (
                <p className="text-xs text-destructive">
                  {secretsProblem(secrets)}
                </p>
              )}
            </div>
          </>
        )}
      </div>
      {run.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(run.error)}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          disabled={sealing || run.isPending || (touched && !ready)}
          onClick={() => void create()}
        >
          {!run.isPending && <Fingerprint aria-hidden="true" />}
          {run.isPending ? "Waiting for the fingerprint…" : "Create"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
