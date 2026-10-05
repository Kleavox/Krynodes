import { toast } from "sonner";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useManualRestart, useServices } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { autoRestartBlocker, isPending } from "@/lib/services";
import type { CheckRecord, NodeRecord } from "@/types";

export function AutoRestartDialog({
  check,
  node,
  open,
  onOpenChange,
}: {
  check: CheckRecord;
  node: NodeRecord | undefined;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const services = useServices();
  const run = useSignedAction(false);
  const manual = useManualRestart();
  const unit = check.target.endsWith(".service")
    ? check.target
    : `${check.target}.service`;
  const latest = (services.data?.actions ?? [])
    .filter(
      (action) =>
        action.nodeId === check.node_id &&
        action.kind === "systemd" &&
        action.name === unit &&
        (action.action === "autorestart" || action.action === "manual"),
    )
    .at(-1);
  const waiting = latest && isPending(latest) ? latest : null;
  const on = waiting
    ? waiting.action === "autorestart"
    : latest?.status === "done"
      ? latest.action === "autorestart"
      : check.auto_restart === 1;
  const blocker = autoRestartBlocker(check, node, services.data);
  const working = run.isPending || manual.isPending || waiting !== null;
  const server = node?.name ?? "its server";

  const toggle = (next: boolean) => {
    const target = { nodeId: check.node_id, name: unit };
    if (next) {
      run.mutate(
        { action: "autorestart", targets: [{ ...target, kind: "systemd" }] },
        { onError: (error) => toast.error(errorMessage(error)) },
      );
    } else {
      manual.mutate(target, {
        onError: (error) => toast.error(errorMessage(error)),
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <DialogHeader>
          <DialogTitle>Restart automatically</DialogTitle>
          <DialogDescription>
            {unit} on {server}
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-start gap-3 rounded-md border p-3">
          <Switch
            id="auto-restart"
            checked={on}
            disabled={working || (blocker !== null && !on)}
            onCheckedChange={toggle}
            aria-describedby="auto-restart-state"
          />
          <div className="min-w-0 space-y-0.5">
            <Label htmlFor="auto-restart">
              Restart {unit.replace(/\.service$/u, "")} when this check turns
              red
            </Label>
            <p
              id="auto-restart-state"
              className="text-xs text-muted-foreground"
            >
              {waiting
                ? `${waiting.action === "autorestart" ? "Turning on" : "Turning off"}… waiting for ${server}.`
                : blocker && !on
                  ? blocker
                  : on
                    ? "On."
                    : "Off."}
            </p>
          </div>
        </div>
        <ul className="list-disc space-y-1 pl-4 text-sm text-muted-foreground">
          <li>
            Only when the check is red: two failed reports in a row. Yellow is
            left alone, and so is planned work on the server.
          </li>
          <li>
            Once per incident, at most 3 times an hour, and never after you
            stopped it from Krynodes.
          </li>
          <li>
            Turning it on needs your fingerprint; turning it off does not.
          </li>
        </ul>
      </DialogContent>
    </Dialog>
  );
}
