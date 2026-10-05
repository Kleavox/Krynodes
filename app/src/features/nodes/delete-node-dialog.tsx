import { Fingerprint } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router";

import { GuardIcon } from "@/components/confirm-dialog";
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
import { useSignedOperation } from "@/features/deploy/use-signed-action";
import {
  useAction,
  useCloudflare,
  useDeleteNode,
  useOverview,
  useServices,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { planRemoval, reshareSteps, vaultNodes } from "@/lib/vault";
import type { NodeRecord } from "@/types";

const ENDED = ["failed", "expired", "cancelled", "skipped"];

export function DeleteNodeDialog({
  node,
  open,
  onOpenChange,
  onDeleted,
}: {
  node: NodeRecord;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDeleted?: () => void;
}) {
  const remove = useDeleteNode();
  const operate = useSignedOperation(false);
  const services = useServices();
  const overview = useOverview();
  const settings = useCloudflare();
  const [last, setLast] = useState<string | null>(null);
  const tracked = useAction(last);
  const seen = overview.dataUpdatedAt;
  const setId = settings.data?.setId ?? null;
  const zone = settings.data?.zone ?? "";
  const nodesFor = (fingerprint: string | null) =>
    services.data && overview.data
      ? vaultNodes(services.data, overview.data.nodes, fingerprint, seen)
      : [];
  const plan = planRemoval(nodesFor(null), node.id, setId);
  const status = tracked.data?.action.status;
  const spreadFailed = status !== undefined && ENDED.includes(status);

  const close = (next: boolean) => {
    if (!next) {
      remove.reset();
      operate.reset();
      setLast(null);
    }
    onOpenChange(next);
  };
  const deleteNow = () =>
    remove.mutate(node.id, {
      onSuccess: () => {
        close(false);
        onDeleted?.();
      },
    });

  useEffect(() => {
    if (remove.isIdle && status === "done") {
      deleteNow();
    }
  });

  const spread = () =>
    operate.mutate(
      {
        kind: "reshare",
        reach: [],
        build: (fingerprint) => {
          const all = nodesFor(fingerprint);
          const chosen = planRemoval(all, node.id, setId);
          if (!chosen.ok) throw new Error(chosen.reason);
          if (!chosen.needed) throw new Error("Nothing to spread.");
          return reshareSteps({
            releaser: chosen.releaser,
            assembler: chosen.assembler,
            holders: chosen.holders,
            keyOf: Object.fromEntries(
              all.map((item) => [item.id, item.sealKey ?? ""]),
            ),
            set: crypto.randomUUID(),
            cleanup: node.id,
            zone,
            forgets: chosen.forgets,
          });
        },
      },
      { onSuccess: (batch) => setLast(batch.actions.at(-1)?.id ?? null) },
    );

  const spreading = last !== null && !spreadFailed;
  const holds = !plan.ok || plan.needed;
  const error = remove.error ?? operate.error;

  return (
    <AlertDialog open={open} onOpenChange={close}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete {node.name}?</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              <p>
                Its metrics, checks, check results and incidents are deleted
                with it, and the agent on the server stops being accepted. Then
                run{" "}
                <code className="font-mono text-xs">
                  sudo kry uninstall-service
                </code>{" "}
                on the server to take Krynodes off it.
              </p>
              {holds && plan.ok && (
                <p>
                  {node.name} holds a piece of the Cloudflare token. Krynodes
                  first spreads the token across the other servers and removes
                  the tunnel of {node.name} from Cloudflare, then deletes it.
                </p>
              )}
              {!plan.ok && (
                <p>
                  {node.name} holds a piece of the Cloudflare token, and it
                  cannot move now: {plan.reason}
                </p>
              )}
              {(!plan.ok || spreadFailed) && (
                <p>
                  If {node.name} may be in the wrong hands, replace the token
                  under{" "}
                  <Link
                    to="/settings/cloudflare"
                    className="underline underline-offset-4"
                  >
                    Settings, Cloudflare
                  </Link>{" "}
                  after deleting it.
                </p>
              )}
              {spreading && (
                <p className="text-warning">
                  Spreading the token. {node.name} is deleted once that
                  finishes; keep this open.
                </p>
              )}
              {spreadFailed && (
                <p className="text-destructive">
                  Spreading the token did not finish, so {node.name} is still
                  here.
                </p>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          {holds && plan.ok && !spreadFailed ? (
            <Button
              variant="destructive"
              disabled={operate.isPending || spreading || remove.isPending}
              onClick={spread}
            >
              {!operate.isPending && !spreading && (
                <Fingerprint aria-hidden="true" />
              )}
              {operate.isPending
                ? "Waiting for the fingerprint…"
                : spreading
                  ? "Spreading…"
                  : "Spread and delete"}
            </Button>
          ) : (
            <Button
              variant="destructive"
              disabled={remove.isPending}
              onClick={deleteNow}
            >
              {!remove.isPending && <GuardIcon />}
              {remove.isPending
                ? "Working…"
                : holds
                  ? "Delete anyway"
                  : "Delete node"}
            </Button>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
