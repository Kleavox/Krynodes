import { KeyRound } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

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
import { useDevices } from "@/lib/api";
import { signersFor } from "@/lib/devices";
import { nodeState } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import { deployBlocker, deployTargets, type StackMember } from "@/lib/stacks";
import type { BatchMode } from "@/types";

import { useDeploySession } from "./use-deploy-session";
import { useSignedAction } from "./use-signed-action";

const MODES: { value: BatchMode; label: string; detail: string }[] = [
  {
    value: "rolling",
    label: "One at a time (recommended)",
    detail:
      "The next server goes after the previous one succeeds; the rest stop at the first failure.",
  },
  {
    value: "parallel",
    label: "All at Once",
    detail: "Every server runs it at its next report.",
  },
];

export interface DeployRequest {
  action: "deploy" | "rollback";
  project: string;
  members: StackMember[];
}

export function DeployDialog({
  request,
  seen,
  onClose,
}: {
  request: DeployRequest | null;
  seen: number;
  onClose: () => void;
}) {
  return (
    <AlertDialog
      open={request !== null}
      onOpenChange={(open) => !open && onClose()}
    >
      {request && request.members.length > 0 && (
        <DeployForm request={request} seen={seen} onClose={onClose} />
      )}
    </AlertDialog>
  );
}

function DeployForm({
  request,
  seen,
  onClose,
}: {
  request: DeployRequest;
  seen: number;
  onClose: () => void;
}) {
  const devices = useDevices();
  const run = useSignedAction(false);
  const { state } = useDeploySession();
  const [mode, setMode] = useState<BatchMode>("rolling");
  const working = run.isPending;
  const rollback = request.action === "rollback";
  const targets = deployTargets(request.members, seen).filter(
    (member) => !rollback || member.stack.rollback,
  );
  const blocked = request.members.filter((member) => !targets.includes(member));
  const several = targets.length > 1;
  const word = rollback ? "Roll Back" : "Deploy";
  const [first] = targets;
  const title = several
    ? `${word} ${request.project} on ${targets.length} servers?`
    : `${word} ${request.project} on ${first?.node.name ?? request.members[0]?.node.name ?? ""}?`;
  const list = devices.data?.devices;
  const ids = list?.map((device) => device.id) ?? [];
  const signers = signersFor(
    list ?? [],
    targets.map((member) => member.trust),
  );
  const offline = (member: StackMember) =>
    nodeState(member.node, seen) === "offline";

  const submit = () =>
    run.mutate(
      {
        action: request.action,
        mode,
        targets: targets.map((member) => ({
          nodeId: member.node.id,
          kind: "compose" as const,
          name: request.project,
        })),
      },
      { onSuccess: onClose },
    );

  return (
    <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
      <AlertDialogHeader>
        <AlertDialogTitle>{title}</AlertDialogTitle>
        <AlertDialogDescription>
          {rollback
            ? "Starts the images that ran before the last deploy. Changes to the compose file stay."
            : "Pulls new images and restarts the stack. It can take a few minutes."}
        </AlertDialogDescription>
      </AlertDialogHeader>
      {list && (ids.length === 0 || signers.length === 0) ? (
        <p className="text-sm">
          {ids.length === 0
            ? "Deploys need a trusted passkey. "
            : "None of your passkeys has access to every server here. "}
          <Link
            to="/devices"
            className="underline underline-offset-4"
            onClick={onClose}
          >
            {ids.length === 0 ? "Set Up Passkeys" : "Change Access"}
          </Link>
          .
        </p>
      ) : (
        <>
          {(several || blocked.length > 0) && (
            <ul className="max-h-32 overflow-y-auto rounded-md border px-3 py-2 font-mono text-xs">
              {targets.map((member) => (
                <li key={member.node.id}>
                  {member.node.name}
                  {offline(member) && (
                    <span className="text-muted-foreground"> · Offline</span>
                  )}
                </li>
              ))}
              {blocked.map((member) => (
                <li key={member.node.id} className="text-muted-foreground">
                  {member.node.name} · Skipped:{" "}
                  {deployBlocker(member) ?? "nothing to roll back to"}
                </li>
              ))}
            </ul>
          )}
          {several && (
            <fieldset className="space-y-2">
              <legend className="mb-1 text-sm font-medium">Order</legend>
              {MODES.map((option) => (
                <label
                  key={option.value}
                  className="flex cursor-pointer items-start gap-2 text-sm"
                >
                  <input
                    type="radio"
                    name="deploy-order"
                    value={option.value}
                    checked={mode === option.value}
                    onChange={() => setMode(option.value)}
                    className="mt-1"
                  />
                  <span>
                    <span className="font-medium">{option.label}</span>
                    <span className="block text-muted-foreground">
                      {option.detail}
                    </span>
                  </span>
                </label>
              ))}
            </fieldset>
          )}
        </>
      )}
      {run.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(run.error)}
        </p>
      )}
      <AlertDialogFooter>
        <AlertDialogCancel>Cancel</AlertDialogCancel>
        <Button
          variant={rollback ? "destructive" : "default"}
          disabled={working || signers.length === 0 || targets.length === 0}
          onClick={submit}
        >
          {!working && <KeyRound aria-hidden="true" />}
          {working ? (state ? "Sending…" : "Waiting for the Passkey…") : word}
        </Button>
      </AlertDialogFooter>
    </AlertDialogContent>
  );
}
