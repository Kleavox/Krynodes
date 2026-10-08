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
import {
  useSignedAction,
  useSignedOperation,
} from "@/features/deploy/use-signed-action";
import { removalReady } from "@/lib/agent";
import {
  useAction,
  useCloudflare,
  useDeleteNode,
  useDevices,
  useOverview,
  useServices,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { pieceOf, planRemoval, reshareSteps, vaultNodes } from "@/lib/vault";
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
  const run = useSignedAction(false);
  const devices = useDevices();
  const services = useServices();
  const overview = useOverview();
  const settings = useCloudflare();
  const [last, setLast] = useState<string | null>(null);
  const [stage, setStage] = useState<"spread" | "remove" | null>(null);
  const [keepAgent, setKeepAgent] = useState(false);
  const tracked = useAction(last);
  const seen = overview.dataUpdatedAt;
  const setId = settings.data?.setId ?? null;
  const zone = settings.data?.zone ?? "";
  const nodesFor = (fingerprint: string | null) =>
    services.data && overview.data
      ? vaultNodes(services.data, overview.data.nodes, fingerprint, seen)
      : [];
  const addresses =
    (services.data?.nodes.find((entry) => entry.id === node.id)?.webAddresses
      ?.length ?? 0) > 0;
  const piece =
    pieceOf(
      nodesFor(null).find((item) => item.id === node.id),
      setId,
    ) !== null;
  const plan = planRemoval(nodesFor(null), node.id, setId, addresses);
  const action = tracked.data?.action.id === last ? tracked.data?.action : null;
  const status = action?.status;
  const ended = status !== undefined && ENDED.includes(status);
  const spreadFailed = ended && stage === "spread";
  const removalFailed = ended && stage === "remove";
  const holds = !plan.ok || plan.needed;
  const trust =
    services.data?.nodes.find((entry) => entry.id === node.id)?.trust ?? null;
  const offer =
    plan.ok &&
    removalReady(node, trust, devices.data?.devices ?? [], Date.now());
  const leaving = offer && !keepAgent;
  const spreadDone = stage === "spread" && status === "done";

  const close = (next: boolean) => {
    if (!next) {
      remove.reset();
      operate.reset();
      run.reset();
      setLast(null);
      setStage(null);
      setKeepAgent(false);
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

  const removeAgent = () =>
    run.mutate(
      {
        action: "uninstall",
        targets: [{ nodeId: node.id, kind: "host", name: "server" }],
      },
      {
        onSuccess: (batch) => {
          setStage("remove");
          setLast(batch.actions[0]?.id ?? null);
        },
      },
    );

  useEffect(() => {
    if (!remove.isIdle || status !== "done") return;
    if (stage === "spread" && leaving) {
      if (run.isIdle) removeAgent();
      return;
    }
    deleteNow();
  });

  const spread = () =>
    operate.mutate(
      {
        kind: "reshare",
        reach: [],
        build: (fingerprint) => {
          const all = nodesFor(fingerprint);
          const chosen = planRemoval(all, node.id, setId, addresses);
          if (!chosen.ok) throw new Error(chosen.reason);
          if (!chosen.needed || !setId) throw new Error("Nothing to spread.");
          return reshareSteps({
            releaser: chosen.releaser,
            assembler: chosen.assembler,
            holders: chosen.holders,
            keyOf: Object.fromEntries(
              all.map((item) => [item.id, item.sealKey ?? ""]),
            ),
            set: crypto.randomUUID(),
            source: setId,
            cleanup: node.id,
            zone,
            forgets: chosen.forgets,
          });
        },
      },
      {
        onSuccess: (batch) => {
          setStage("spread");
          setLast(batch.actions.at(-1)?.id ?? null);
        },
      },
    );

  const spreading = stage === "spread" && !ended && !spreadDone;
  const removing = run.isPending || (stage === "remove" && !ended);
  const busy = operate.isPending || spreading || removing || remove.isPending;
  const error = remove.error ?? operate.error ?? run.error;

  return (
    <AlertDialog open={open} onOpenChange={close}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete {node.name}?</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              <p>
                Its metrics, checks, check results and incidents are deleted
                with it, and the agent on the server stops being accepted.{" "}
                {leaving ? (
                  "Krynodes also leaves the server: its protections are turned off and its apps keep running."
                ) : (
                  <>
                    Then run{" "}
                    <code className="font-mono text-xs">
                      sudo kry uninstall-service
                    </code>{" "}
                    on the server to take Krynodes off it.
                  </>
                )}
              </p>
              {holds && plan.ok && stage !== "remove" && (
                <p>
                  {piece
                    ? `${node.name} holds a piece of the Cloudflare token. Krynodes first spreads the token across the other servers and removes the tunnel of ${node.name} from Cloudflare, then deletes it.`
                    : `${node.name} has web addresses. Krynodes first removes its tunnel, DNS records and logins from Cloudflare, then deletes it.`}
                </p>
              )}
              {!plan.ok && (
                <p>
                  {piece
                    ? `${node.name} holds a piece of the Cloudflare token, and it cannot move now: ${plan.reason}`
                    : `${node.name} has web addresses, and Krynodes cannot reach Cloudflare now: ${plan.reason} Deleting anyway leaves them in Cloudflare.`}
                </p>
              )}
              {piece && (!plan.ok || spreadFailed) && (
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
              {stage === "remove" && !ended && (
                <p className="text-warning">
                  Removing Krynodes from {node.name}. It is deleted once that
                  finishes; keep this open.
                </p>
              )}
              {removalFailed && (
                <p className="text-destructive">
                  Krynodes could not be removed from {node.name}
                  {action?.output ? `: ${action.output}` : "."} Delete anyway
                  leaves it there; run{" "}
                  <code className="font-mono text-xs">
                    sudo kry uninstall-service
                  </code>{" "}
                  on the server to take it off.
                </p>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {offer && !removalFailed && (
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={!keepAgent}
              disabled={busy}
              onChange={() => setKeepAgent(!keepAgent)}
            />
            Remove Krynodes from the server
          </label>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          {holds &&
          plan.ok &&
          stage !== "remove" &&
          !spreadFailed &&
          !spreadDone ? (
            <Button variant="destructive" disabled={busy} onClick={spread}>
              {!operate.isPending && !spreading && (
                <Fingerprint aria-hidden="true" />
              )}
              {operate.isPending
                ? "Waiting for the fingerprint…"
                : spreading
                  ? "Spreading…"
                  : piece
                    ? "Spread and delete"
                    : "Clean up and delete"}
            </Button>
          ) : leaving && !removalFailed && !spreadFailed ? (
            <Button variant="destructive" disabled={busy} onClick={removeAgent}>
              {!busy && <Fingerprint aria-hidden="true" />}
              {run.isPending
                ? "Waiting for the fingerprint…"
                : removing
                  ? "Removing Krynodes…"
                  : remove.isPending
                    ? "Working…"
                    : "Remove and delete"}
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
                : holds || removalFailed
                  ? "Delete anyway"
                  : "Delete node"}
            </Button>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
