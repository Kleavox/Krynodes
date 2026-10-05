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
import { useSignedAction } from "./use-signed-action";

export const SHEET =
  "max-h-[92dvh] overflow-y-auto max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none sm:max-w-2xl";

export interface StackTarget {
  nodeId: string;
  nodeName: string;
  project: string;
  sealKey: string | null;
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
        Try again
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
  const [sealing, setSealing] = useState(false);
  const current = text ?? read?.compose ?? "";
  const chosen: Access =
    access ?? (read?.access === "full" ? "full" : "contained");
  const problem = secretsProblem(secrets);

  const save = async () => {
    if (!read || problem) return;
    setSealing(true);
    let sealed: string | undefined;
    try {
      sealed = target.sealKey
        ? await sealSecrets(target.sealKey, secrets)
        : undefined;
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
            ...(sealed ? { secrets: sealed } : {}),
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
          {editable ? "Edit compose" : "Compose file"} · {target.project} on{" "}
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
            aria-label="Compose file"
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
              <div className="space-y-1.5">
                <Label>Secrets</Label>
                <SecretsEditor rows={secrets} onChange={setSecrets} />
                <p className="text-xs text-muted-foreground">
                  Leave this empty to keep the secrets the stack has now.
                </p>
                {problem && (
                  <p className="text-xs text-destructive">{problem}</p>
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
            {run.isPending ? "Waiting for the fingerprint…" : "Save"}
          </Button>
        )}
      </DialogFooter>
    </DialogContent>
  );
}
