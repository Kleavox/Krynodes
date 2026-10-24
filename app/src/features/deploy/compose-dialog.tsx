import { Fingerprint } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { StatusDot } from "@/components/status";
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
import { errorMessage } from "@/lib/http";
import { seal } from "@/lib/seal";
import { parseHostPorts } from "@/lib/stacks";

import {
  AccessChoice,
  FullAccessSummary,
  HeldSecrets,
  ReachField,
  SecretsEditor,
  heldProblem,
  sealSecrets,
  secretChange,
  type Access,
  type HeldSecret,
  type SecretRow,
} from "./stack-fields";
import { useComposeRead } from "./use-compose-read";
import { useSignedAction } from "./use-signed-action";

export const SHEET =
  "max-h-[92dvh] overflow-y-auto max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none sm:max-w-2xl";

export interface StackTarget {
  nodeId: string;
  nodeName: string;
  project: string;
  sealKey: string | null;
  reach: boolean;
}

const AREA =
  "w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

export function Reading({
  server,
  failure,
  retry,
}: {
  server: string;
  failure: Error | null;
  retry: () => void;
}) {
  return failure ? (
    <div className="space-y-2">
      <p role="alert" className="text-sm text-destructive">
        {errorMessage(failure)}
      </p>
      <Button variant="outline" size="sm" onClick={retry}>
        Try Again
      </Button>
    </div>
  ) : (
    <p className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
      <StatusDot tone="warn" pulse />
      Reading the compose file from {server}…
    </p>
  );
}

export function ComposeDialog({
  target,
  editable,
  open,
  onOpenChange,
}: {
  target: StackTarget;
  editable: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <ComposeForm
          target={target}
          editable={editable}
          onClose={() => onOpenChange(false)}
        />
      )}
    </Dialog>
  );
}

function ComposeForm({
  target,
  editable,
  onClose,
}: {
  target: StackTarget;
  editable: boolean;
  onClose: () => void;
}) {
  const { read, failure, retry } = useComposeRead({
    nodeId: target.nodeId,
    name: target.project,
  });
  const run = useSignedAction(false);
  const [text, setText] = useState<string | null>(null);
  const [access, setAccess] = useState<Access | null>(null);
  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [kept, setKept] = useState<HeldSecret[] | null>(null);
  const [reach, setReach] = useState<string | null>(null);
  const [sealing, setSealing] = useState(false);
  const current = text ?? read?.compose ?? "";
  const chosen: Access =
    access ?? (read?.access === "full" ? "full" : "contained");
  const reaching = target.reach && chosen === "contained";
  const hostPorts = parseHostPorts(
    reaching ? (reach ?? (read?.hostPorts ?? []).join(", ")) : "",
  );
  const before = read?.secrets;
  const held = kept ?? (before ?? []).map((name) => ({ name, value: null }));
  const secretsWrong = heldProblem(held, secrets);
  const problem = secretsWrong ?? hostPorts.problem;

  const sealed = async (sealKey: string) => {
    if (!before) return sealSecrets(sealKey, secrets);
    const change = secretChange(held, secrets, before);
    return change ? seal(sealKey, JSON.stringify(change)) : undefined;
  };

  const save = async () => {
    if (!read || problem) return;
    setSealing(true);
    let locked: string | undefined;
    try {
      locked = target.sealKey ? await sealed(target.sealKey) : undefined;
    } catch (error) {
      toast.error(errorMessage(error));
      return;
    } finally {
      setSealing(false);
    }
    run.mutate(
      {
        action: "edit",
        targets: [
          {
            nodeId: target.nodeId,
            kind: "compose",
            name: target.project,
            compose: current,
            access: chosen,
            ...(locked ? { secrets: locked } : {}),
            ...(reaching
              ? { args: { hostPorts: hostPorts.ports.join(",") } }
              : {}),
          },
        ],
      },
      {
        onSuccess: () => {
          toast.success(`Updating ${target.project} on ${target.nodeName}.`);
          onClose();
        },
      },
    );
  };

  return (
    <DialogContent className={SHEET}>
      <DialogHeader>
        <DialogTitle>
          {editable ? "Edit Compose" : "Compose File"} · {target.project} on{" "}
          {target.nodeName}
        </DialogTitle>
        <DialogDescription>
          {editable
            ? "Saving checks the file again and restarts the stack. If it fails, the previous file starts again."
            : "This stack was started outside Krynodes. Move it into Krynodes to edit it here."}
        </DialogDescription>
      </DialogHeader>
      {!read ? (
        <Reading server={target.nodeName} failure={failure} retry={retry} />
      ) : (
        <div className="space-y-4">
          <textarea
            aria-label="Compose File"
            value={current}
            rows={16}
            readOnly={!editable}
            spellCheck={false}
            onChange={(event) => setText(event.target.value)}
            className={AREA}
          />
          {editable && (
            <>
              <div className="space-y-1.5">
                <Label>Access</Label>
                <AccessChoice value={chosen} onChange={setAccess} />
              </div>
              {chosen === "full" && <FullAccessSummary text={current} />}
              {reaching && (
                <ReachField
                  value={reach ?? (read.hostPorts ?? []).join(", ")}
                  onChange={setReach}
                  problem={hostPorts.problem}
                />
              )}
              <div className="space-y-1.5">
                <Label>Secrets</Label>
                {before && <HeldSecrets rows={held} onChange={setKept} />}
                <SecretsEditor rows={secrets} onChange={setSecrets} />
                <p className="text-xs text-muted-foreground">
                  {before
                    ? "A secret stays as it is unless you replace or remove it. Its value never leaves the server."
                    : "Leave this empty to keep the secrets the stack has now."}
                </p>
                {secretsWrong && (
                  <p className="text-xs text-destructive">{secretsWrong}</p>
                )}
              </div>
            </>
          )}
        </div>
      )}
      {run.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(run.error)}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          {editable ? "Cancel" : "Close"}
        </Button>
        {editable && (
          <Button
            disabled={!read || sealing || run.isPending || problem !== null}
            onClick={() => void save()}
          >
            {!run.isPending && <Fingerprint aria-hidden="true" />}
            {run.isPending ? "Waiting for the Fingerprint…" : "Save"}
          </Button>
        )}
      </DialogFooter>
    </DialogContent>
  );
}
