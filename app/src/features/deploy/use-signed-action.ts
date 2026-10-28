import {
  ACTION_QUERIES,
  postActions,
  postOperation,
  useApiMutation,
  useDevices,
  useServices,
  type OperationStep,
} from "@/lib/api";
import { failure } from "@/lib/proof";
import { signersFor, usable } from "@/lib/devices";
import {
  actionCommand,
  signCommand,
  signTargets,
  type CommandTarget,
  type Session,
} from "@/lib/passkeys";
import { queryKeys } from "@/lib/query-client";
import type { OperationTarget } from "@/lib/vault";
import type { ActionVerb, BatchMode } from "@/types";

import { useDeploySession } from "./use-deploy-session";

export const NO_SIGNER =
  "None of your passkeys has access to every server here. Change access in Passkeys.";

export function useSignedAction(toastErrors = true) {
  const devices = useDevices();
  const services = useServices();
  const { open } = useDeploySession();
  return useApiMutation(
    async ({
      action,
      mode = "rolling",
      targets,
      then,
    }: {
      action: Exclude<ActionVerb, "trust" | "heal" | "manual">;
      mode?: BatchMode;
      targets: CommandTarget[];
      then?: "delete";
    }) => {
      const trust = new Map(
        (services.data?.nodes ?? []).map((node) => [node.id, node.trust]),
      );
      const reports = targets.map((target) => trust.get(target.nodeId) ?? null);
      const signers = signersFor(devices.data?.devices ?? [], reports);
      if (signers.length === 0) throw new Error(NO_SIGNER);
      try {
        const session = await open(signers);
        return await postActions({
          action,
          mode,
          targets: await signTargets(session, action, targets),
          ...(then ? { then } : {}),
        });
      } catch (error) {
        throw error instanceof DOMException && error.name === "NotAllowedError"
          ? new Error(failure(error))
          : error;
      }
    },
    ACTION_QUERIES,
    toastErrors,
  );
}

export type OperationKind =
  | "move"
  | "expose"
  | "unexpose"
  | "split"
  | "reshare"
  | "tailnet"
  | "disconnect";

export interface OperationInput {
  kind: OperationKind;
  zone?: string;
  tailscale?: { tailnet: string; clientId: string; webhookSecret?: string };
  deleteNode?: string;
}

export async function sendOperation(
  session: Session,
  input: OperationInput,
  steps: OperationTarget[],
) {
  const signed: OperationStep[] = await Promise.all(
    steps.map(async ({ attachFrom, attachKey, ...target }) => {
      const id = crypto.randomUUID();
      return {
        id,
        nodeId: target.nodeId,
        kind: target.kind as OperationStep["kind"],
        name: target.name,
        action: target.action,
        signed: await signCommand(
          session,
          actionCommand({ ...target, id }, session),
        ),
        ...(attachFrom === undefined ? {} : { attachFrom }),
        ...(attachKey === undefined ? {} : { attachKey }),
      };
    }),
  );
  return postOperation({
    kind: input.kind,
    steps: signed,
    ...(input.zone ? { zone: input.zone } : {}),
    ...(input.tailscale ? { tailscale: input.tailscale } : {}),
    ...(input.deleteNode ? { deleteNode: input.deleteNode } : {}),
  });
}

export function useSignedOperation(toastErrors = true) {
  const devices = useDevices();
  const services = useServices();
  const { open } = useDeploySession();
  return useApiMutation(
    async ({
      kind,
      zone,
      reach,
      build,
      deleteNode,
    }: {
      kind: OperationKind;
      zone?: string;
      reach: string[];
      deleteNode?: string;
      build: (
        fingerprint: string,
      ) => OperationTarget[] | Promise<OperationTarget[]>;
    }) => {
      const all = devices.data?.devices ?? [];
      const trust = new Map(
        (services.data?.nodes ?? []).map((node) => [node.id, node.trust]),
      );
      const signers =
        reach.length === 0
          ? all.filter(usable).map((device) => device.id)
          : signersFor(
              all,
              reach.map((id) => trust.get(id) ?? null),
            );
      if (signers.length === 0) throw new Error(NO_SIGNER);
      try {
        const session = await open(signers);
        const device = all.find(
          (item) => item.id === session.grant.credentialId,
        );
        return await sendOperation(
          session,
          { kind, zone, deleteNode },
          await build(device?.fingerprint ?? ""),
        );
      } catch (error) {
        throw error instanceof DOMException && error.name === "NotAllowedError"
          ? new Error(failure(error))
          : error;
      }
    },
    [...ACTION_QUERIES, ["cloudflare"], queryKeys.tailscale],
    toastErrors,
  );
}
