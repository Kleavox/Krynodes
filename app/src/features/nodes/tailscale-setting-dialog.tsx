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
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { errorMessage } from "@/lib/http";
import { dnsText, exitNodeText } from "@/lib/tailscale";
import type { NodeRecord } from "@/types";

export function TailscaleSettingDialog({
  node,
  setting,
  on,
  approves,
  onClose,
}: {
  node: NodeRecord;
  setting: "exitnode" | "dns";
  on: boolean;
  approves: boolean;
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const [ticked, setTicked] = useState(on);
  const [reviewing, setReviewing] = useState(false);
  const title = setting === "dns" ? "Tailscale DNS" : "Exit Node";
  const text = (next: boolean) =>
    setting === "dns"
      ? dnsText(node.name, next)
      : exitNodeText(node.name, next, approves);
  const submit = () =>
    run.mutate(
      {
        action: setting,
        targets: [
          {
            nodeId: node.id,
            kind: "host",
            name: "tailscale",
            args: { on: ticked ? "1" : "0" },
          },
        ],
      },
      {
        onSuccess: () => {
          toast.success(`Sent to ${node.name}.`);
          onClose();
        },
      },
    );
  return (
    <AlertDialog open onOpenChange={(open) => !open && onClose()}>
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <AlertDialogHeader>
          <AlertDialogTitle>
            {reviewing
              ? `Turn ${ticked ? "on" : "off"} ${title} on ${node.name}?`
              : `${title} on ${node.name}`}
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              {(reviewing ? text(ticked) : text(true).slice(0, 1)).map(
                (line) => (
                  <p key={line}>{line}</p>
                ),
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {!reviewing && (
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={ticked}
              onChange={() => setTicked(!ticked)}
            />
            {setting === "dns" ? "Use Tailscale DNS" : "Offer as Exit Node"}
          </label>
        )}
        {run.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(run.error)}
          </p>
        )}
        <AlertDialogFooter>
          {reviewing ? (
            <>
              <Button
                variant="outline"
                disabled={run.isPending}
                onClick={() => {
                  run.reset();
                  setReviewing(false);
                }}
              >
                Back
              </Button>
              <Button
                variant={ticked ? "default" : "destructive"}
                disabled={run.isPending}
                onClick={submit}
              >
                <KeyRound aria-hidden="true" />
                {run.isPending ? <Waiting /> : ticked ? "Turn On" : "Turn Off"}
              </Button>
            </>
          ) : (
            <>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <Button
                disabled={ticked === on}
                onClick={() => setReviewing(true)}
              >
                Review
              </Button>
            </>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
