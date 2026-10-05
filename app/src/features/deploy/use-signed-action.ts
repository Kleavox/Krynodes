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
import { signersFor } from "@/lib/devices";
import {
  actionCommand,
  signCommand,
  signTargets,
  type CommandTarget,
} from "@/lib/passkeys";
import type { OperationTarget } from "@/lib/vault";
import type { ActionVerb, BatchMode } from "@/types";

import { useDeploySession } from "./use-deploy-session";

const NO_SIGNER =
  "None of your devices has access to every server here. Change access in Trusted devices.";

export function useSignedAction(toastErrors = true) {
  const devices = useDevices();
  const services = useServices();
  const { open } = useDeploySession();
  return useApiMutation(
    async ({
      action,
      mode = "rolling",
      targets,
    }: {
      action: Exclude<ActionVerb, "trust" | "heal" | "manual">;
      mode?: BatchMode;
      targets: CommandTarget[];
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

type OperationKind = "move" | "expose" | "unexpose" | "split" | "reshare";

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
    }: {
      kind: OperationKind;
      zone?: string;
      reach: string[];
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
          ? all.map((device) => device.id)
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
        const steps = await build(device?.fingerprint ?? "");
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
        return await postOperation({
          kind,
          steps: signed,
          ...(zone ? { zone } : {}),
        });
      } catch (error) {
        throw error instanceof DOMException && error.name === "NotAllowedError"
          ? new Error(failure(error))
          : error;
      }
    },
    [...ACTION_QUERIES, ["cloudflare"]],
    toastErrors,
  );
}
