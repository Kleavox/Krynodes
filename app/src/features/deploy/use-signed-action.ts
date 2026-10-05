import {
  ACTION_QUERIES,
  postActions,
  useApiMutation,
  useDevices,
  useServices,
} from "@/lib/api";
import { failure } from "@/lib/proof";
import { signersFor } from "@/lib/devices";
import { signTargets, type CommandTarget } from "@/lib/passkeys";
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
