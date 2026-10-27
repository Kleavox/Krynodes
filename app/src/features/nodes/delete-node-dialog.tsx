import { Fingerprint } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

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
import {
  useNetworkKeys,
  useSignChange,
} from "@/features/network/use-network-sign";
import { removalReady } from "@/lib/agent";
import {
  useCloudflare,
  useDeleteNode,
  useDevices,
  useNetwork,
  useOverview,
  useQuarantine,
  useServices,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { leaveParagraph, networkText } from "@/lib/network";
import { planWithout, tailnetBlock } from "@/lib/quarantine";
import {
  pieceOf,
  planRemoval,
  reshareSteps,
  vaultNodes,
  type OperationTarget,
} from "@/lib/vault";
import type { NodeRecord } from "@/types";

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
  const network = useNetwork().data;
  const member = network?.members.find(
    (entry) => entry.nodeId === node.id && entry.state === "in",
  );
  const leave = useSignChange();
  const keys = useNetworkKeys(network?.members ?? []);
  const operate = useSignedOperation(false);
  const run = useSignedAction(false);
  const unblock = useSignedAction(false);
  const quarantined = !!node.quarantine;
  const record = useQuarantine(node.id, quarantined).data?.quarantine;
  const block = quarantined ? tailnetBlock(record, node.name) : null;
  const planFor = quarantined ? planWithout : planRemoval;
  const devices = useDevices();
  const services = useServices();
  const overview = useOverview();
  const settings = useCloudflare();
  const [keepAgent, setKeepAgent] = useState(false);
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
  const plan = planFor(nodesFor(null), node.id, setId, addresses);
  const holds = !plan.ok || plan.needed;
  const trust =
    services.data?.nodes.find((entry) => entry.id === node.id)?.trust ?? null;
  const offer =
    !quarantined &&
    plan.ok &&
    removalReady(node, trust, devices.data?.devices ?? [], Date.now());
  const leaving = offer && !keepAgent;
  const stopped = node.deleting === "stopped";
  const running = node.deleting === "running";
  const background = !running && ((holds && plan.ok) || leaving);

  const close = (next: boolean) => {
    if (!next) {
      remove.reset();
      leave.reset();
      operate.reset();
      run.reset();
      unblock.reset();
      setKeepAgent(false);
    }
    onOpenChange(next);
  };
  const started = () => {
    toast.success(
      `Deleting ${node.name}. It disappears once Krynodes is done.`,
    );
    close(false);
  };
  const leaveThen = (then: () => void) =>
    member
      ? leave.mutate(
          {
            change: { kind: "remove", nodeId: node.id },
            text: networkText.remove(node.name),
            signers: keys.signers,
          },
          { onSuccess: then },
        )
      : then();
  const first = (then: () => void) =>
    block
      ? unblock.mutate(
          {
            action: "unblock",
            targets: block.nodeIds.map((nodeId) => ({
              nodeId,
              kind: "host" as const,
              name: "tailscale",
              args: { addresses: block.addresses },
            })),
          },
          { onSuccess: () => leaveThen(then) },
        )
      : leaveThen(then);
  const deleteNow = () =>
    remove.mutate(node.id, {
      onSuccess: () => {
        close(false);
        onDeleted?.();
      },
    });

  const removeAndDelete = () =>
    run.mutate(
      {
        action: "uninstall",
        targets: [{ nodeId: node.id, kind: "host", name: "server" }],
        then: "delete",
      },
      { onSuccess: started },
    );

  const spread = () =>
    operate.mutate(
      {
        kind: "reshare",
        reach: [],
        deleteNode: node.id,
        build: (fingerprint) => {
          const all = nodesFor(fingerprint);
          const chosen = planFor(all, node.id, setId, addresses);
          if (!chosen.ok) throw new Error(chosen.reason);
          if (!chosen.needed || !setId) throw new Error("Nothing to spread.");
          const gone = all.find((item) => item.id === node.id);
          const uninstall: OperationTarget[] =
            leaving && gone?.reachable && gone.online
              ? [
                  {
                    nodeId: node.id,
                    kind: "host",
                    name: "server",
                    action: "uninstall",
                  },
                ]
              : [];
          return [
            ...reshareSteps({
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
            }),
            ...uninstall,
          ];
        },
      },
      { onSuccess: started },
    );

  const busy =
    leave.isPending ||
    operate.isPending ||
    run.isPending ||
    unblock.isPending ||
    remove.isPending;
  const error =
    unblock.error ?? leave.error ?? remove.error ?? operate.error ?? run.error;

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
              {member && network && (
                <p>{leaveParagraph(member, network, !leaving)}</p>
              )}
              {block && (
                <p>
                  {block.text}{" "}
                  <a
                    href={block.console}
                    target="_blank"
                    rel="noreferrer"
                    className="underline underline-offset-4"
                  >
                    Admin Console ↗
                  </a>
                </p>
              )}
              {holds && plan.ok && (
                <p>
                  {piece
                    ? `${node.name} holds a piece of the Cloudflare token. Krynodes first spreads the token across the other servers and removes the tunnel of ${node.name} from Cloudflare, then deletes it.`
                    : `${node.name} has web addresses. Krynodes first removes its tunnel, DNS records and logins from Cloudflare, then deletes it.`}
                </p>
              )}
              {background && (
                <p>
                  It runs on its own after your fingerprint, so you can close
                  this. {node.name} shows as deleting until it is gone.
                </p>
              )}
              {!plan.ok && (
                <p>
                  {piece
                    ? `${node.name} holds a piece of the Cloudflare token, and it cannot move now: ${plan.reason}`
                    : `${node.name} has web addresses, and Krynodes cannot reach Cloudflare now: ${plan.reason} Deleting anyway leaves them in Cloudflare.`}
                </p>
              )}
              {running && (
                <p className="text-warning">
                  Krynodes is already deleting {node.name}; it disappears once
                  that is done. Delete anyway takes it off the dashboard now.
                </p>
              )}
              {stopped && (
                <p className="text-destructive">
                  The last try to delete {node.name} stopped before it was done.{" "}
                  {background
                    ? "Try again, or delete it anyway."
                    : "Delete it anyway to take it off the dashboard."}
                </p>
              )}
              {piece && (!plan.ok || stopped) && (
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
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {offer && !running && (
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
          {stopped && background && (
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() => first(deleteNow)}
            >
              Delete Anyway
            </Button>
          )}
          {running ? (
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => first(deleteNow)}
            >
              {!remove.isPending && <GuardIcon />}
              {remove.isPending ? "Working…" : "Delete Anyway"}
            </Button>
          ) : holds && plan.ok ? (
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => first(spread)}
            >
              {!operate.isPending && <Fingerprint aria-hidden="true" />}
              {operate.isPending
                ? "Waiting for the Fingerprint…"
                : piece
                  ? "Spread and Delete"
                  : "Clean Up and Delete"}
            </Button>
          ) : leaving ? (
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => first(removeAndDelete)}
            >
              {!run.isPending && <Fingerprint aria-hidden="true" />}
              {run.isPending
                ? "Waiting for the Fingerprint…"
                : "Remove and Delete"}
            </Button>
          ) : (
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => first(deleteNow)}
            >
              {!remove.isPending && <GuardIcon />}
              {remove.isPending
                ? "Working…"
                : holds || stopped
                  ? "Delete Anyway"
                  : "Delete Node"}
            </Button>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
