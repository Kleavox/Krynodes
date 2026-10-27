import { useSignedOperation } from "@/features/deploy/use-signed-action";
import {
  ACTION_QUERIES,
  postItWasMe,
  postNetworkDocument,
  postRelease,
  useApiMutation,
  useCloudflare,
  useDevices,
  useOverview,
  useServices,
} from "@/lib/api";
import { openSession } from "@/lib/deploy-session";
import { signersFor } from "@/lib/devices";
import { apiFetch, errorMessage } from "@/lib/http";
import { baseOf, buildDocument } from "@/lib/network";
import { signCommand, signTargets, type CommandTarget } from "@/lib/passkeys";
import { failure } from "@/lib/proof";
import { acceptsWarning, planWithout, releaseInputs } from "@/lib/quarantine";
import { queryKeys } from "@/lib/query-client";
import { reshareSteps, vaultNodes } from "@/lib/vault";
import type {
  ActionVerb,
  NetworkView,
  NodeRecord,
  NodeWarning,
  QuarantineView,
} from "@/types";

const NO_SIGNER =
  "None of your devices has access to every server here. Change access in Trusted devices.";

const said = (error: unknown) =>
  new Error(
    error instanceof DOMException ? failure(error) : errorMessage(error),
  );

function useSigners() {
  const devices = useDevices().data?.devices ?? [];
  const reports = useServices().data?.nodes ?? [];
  return (nodeIds: string[]) => {
    const signers = signersFor(
      devices,
      nodeIds.map(
        (id) => reports.find((entry) => entry.id === id)?.trust ?? null,
      ),
    );
    if (signers.length === 0) throw new Error(NO_SIGNER);
    return signers;
  };
}

async function signed(
  signers: string[],
  steps: (CommandTarget & { action: ActionVerb })[],
) {
  const session = await openSession(signers);
  const out = await Promise.all(
    steps.map(async ({ action, ...target }) => {
      const [one] = await signTargets(session, action, [target]);
      return { ...one!, action };
    }),
  );
  return { session, steps: out };
}

export function useItWasMe(node: NodeRecord) {
  const signers = useSigners();
  return useApiMutation(
    async (warning: NodeWarning) => {
      try {
        if (!acceptsWarning(warning.kind)) {
          return await postItWasMe(node.id, warning.id);
        }
        const { steps } = await signed(signers([node.id]), [
          {
            nodeId: node.id,
            kind: "host",
            name: "server",
            action: "accept",
            args: { kind: warning.kind, item: warning.detail.item ?? "" },
          },
        ]);
        return await postItWasMe(node.id, warning.id, steps[0]);
      } catch (error) {
        throw said(error);
      }
    },
    [queryKeys.overview, ...ACTION_QUERIES],
  );
}

export function useRelease(node: NodeRecord) {
  const signers = useSigners();
  const reports = useServices().data?.nodes ?? [];
  return useApiMutation(
    async ({
      view,
      code,
      locked,
    }: {
      view: QuarantineView;
      code: string;
      locked: boolean;
    }) => {
      const release = view.release;
      const record = view.quarantine;
      if (!release || !record) {
        throw new Error(`Run sudo kry release-code on ${node.name} first.`);
      }
      try {
        const inputs = releaseInputs(record, release, node.id, node.name, {
          locked,
          sealKeys: Object.fromEntries(
            reports.flatMap((entry) =>
              entry.sealKey ? [[entry.id, entry.sealKey]] : [],
            ),
          ),
        });
        const blocked = inputs.blocked;
        const network = await apiFetch<NetworkView>("/api/network");
        const member = network.members.some(
          (entry) => entry.nodeId === node.id && entry.state === "in",
        );
        const everyone = [
          node.id,
          ...blocked,
          ...(member
            ? network.members
                .filter((entry) => entry.state === "in")
                .map((entry) => entry.nodeId)
            : []),
        ];
        const { session, steps } = await signed(
          signers([...new Set(everyone)]),
          [
            {
              nodeId: node.id,
              kind: "host",
              name: "server",
              action: "release",
              args: {
                key: release.key,
                signer: release.signer,
                seal: release.seal,
                token: release.token,
                code,
              },
            },
            ...(inputs.unlock
              ? [
                  {
                    nodeId: node.id,
                    kind: "host" as const,
                    name: "server",
                    action: "unlock" as const,
                  },
                ]
              : []),
            ...blocked.map((nodeId) => ({
              nodeId,
              kind: "host" as const,
              name: "tailscale",
              action: "unblock" as const,
              args: { addresses: inputs.addresses },
            })),
          ],
        );
        await postRelease(node.id, { code, steps });
        if (!member) return;
        const base = await baseOf(await apiFetch<NetworkView>("/api/network"));
        const document = await buildDocument(
          base?.document ?? null,
          {
            kind: "release",
            nodeId: node.id,
            key: release.key,
            signer: release.signer,
          },
          inputs.sealKeys,
          base?.parent,
        );
        const sealed = await signCommand(session, document);
        await postNetworkDocument({
          signed: {
            grant: sealed.grant,
            document: sealed.command,
            signature: sealed.signature,
          },
          change: `Send the new keys of ${node.name} to the private network`,
          detail: null,
        });
      } catch (error) {
        throw said(error);
      }
    },
    [
      queryKeys.overview,
      queryKeys.network,
      queryKeys.quarantine(node.id),
      ...ACTION_QUERIES,
    ],
  );
}

export function useReshareWithout(node: NodeRecord) {
  const operate = useSignedOperation(false);
  const services = useServices();
  const overview = useOverview();
  const settings = useCloudflare();
  const setId = settings.data?.setId ?? null;
  const zone = settings.data?.zone ?? "";
  const nodesFor = (fingerprint: string | null) =>
    services.data && overview.data
      ? vaultNodes(
          services.data,
          overview.data.nodes,
          fingerprint,
          overview.dataUpdatedAt,
        )
      : [];
  const plan = (addresses: boolean) =>
    planWithout(nodesFor(null), node.id, setId, addresses);
  const run = (addresses: boolean) =>
    operate.mutate({
      kind: "reshare",
      reach: [],
      build: (fingerprint) => {
        const all = nodesFor(fingerprint);
        const chosen = planWithout(all, node.id, setId, addresses);
        if (!chosen.ok) throw new Error(chosen.reason);
        if (!chosen.needed || !setId) throw new Error("Nothing to reshare.");
        return reshareSteps({
          releaser: chosen.releaser,
          assembler: chosen.assembler,
          holders: chosen.holders,
          keyOf: Object.fromEntries(
            all.map((item) => [item.id, item.sealKey ?? ""]),
          ),
          set: crypto.randomUUID(),
          source: setId,
          ...(addresses ? { cleanup: node.id } : {}),
          zone,
          forgets: chosen.forgets,
        });
      },
    });
  return { plan, run, operate };
}
