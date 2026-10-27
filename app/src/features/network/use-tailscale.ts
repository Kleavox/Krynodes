import {
  TAILSCALE,
  type TailnetRule,
  type TailscaleReport,
} from "@krynodes/protocol";

import { NO_SIGNER, sendOperation } from "@/features/deploy/use-signed-action";
import {
  ACTION_QUERIES,
  postActions,
  useApiMutation,
  useDevices,
  useOverview,
  useServices,
  useTailscale,
} from "@/lib/api";
import { openSession } from "@/lib/deploy-session";
import { usable } from "@/lib/devices";
import { apiFetch, errorMessage } from "@/lib/http";
import type { Session } from "@/lib/passkeys";
import { failure } from "@/lib/proof";
import { TAILSCALE_CONSOLE } from "@/lib/quarantine";
import { queryKeys } from "@/lib/query-client";
import { isPending } from "@/lib/services";
import {
  connectSteps,
  disconnectSteps,
  joinSteps,
  readSteps,
  removeSteps,
  saveSteps,
} from "@/lib/tailscale";
import { planUse, splitHolders, vaultNodes, type VaultNode } from "@/lib/vault";
import type {
  ActionRecord,
  DeviceRecord as Device,
  TailnetConnected,
  TailnetServer,
  TailscaleResponse,
} from "@/types";

export const CONSOLE = {
  policy: "https://login.tailscale.com/admin/acls/file",
  credentials: "https://login.tailscale.com/admin/settings/trust-credentials",
  webhooks: "https://login.tailscale.com/admin/settings/webhooks",
  machines: TAILSCALE_CONSOLE,
};

const POLL_MS = 3_000;
const WAIT_MS = 120_000;

interface PolicyRead {
  at: string;
  kry: boolean;
  open: string | null;
  block: string[] | null;
  hash: string;
}

export interface Started {
  read: PolicyRead;
  inUse: Record<string, { from: string; port: string }[]>;
}

export type Saved =
  { saved: true } | { saved: false; block: string; now: string[] };

interface Context {
  devices: Device[];
  data: TailscaleResponse | undefined;
  nodesFor: (fingerprint: string | null) => VaultNode[];
}

const wait = (milliseconds: number) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

const outputOf = <T>(action: ActionRecord): T | null => {
  try {
    return action.output ? (JSON.parse(action.output) as T) : null;
  } catch {
    return null;
  }
};

const failed = (action: ActionRecord | undefined, otherwise: string) =>
  action?.status === "done" ? null : action?.output || otherwise;

async function finished(ids: string[]): Promise<ActionRecord[]> {
  const started = Date.now();
  for (;;) {
    try {
      const actions = await Promise.all(
        ids.map((id) =>
          apiFetch<{ action: ActionRecord }>(
            `/api/actions/${encodeURIComponent(id)}`,
          ).then((reply) => reply.action),
        ),
      );
      if (actions.every((action) => !isPending(action))) return actions;
    } catch {
      if (Date.now() - started > WAIT_MS) throw new Error(NO_ANSWER);
    }
    if (Date.now() - started > WAIT_MS) throw new Error(NO_ANSWER);
    await wait(POLL_MS);
  }
}

const NO_ANSWER = "Your servers did not answer within two minutes.";

async function holding(nodeIds: string[], set: string) {
  const started = Date.now();
  while (Date.now() - started < WAIT_MS) {
    const view = await apiFetch<TailscaleResponse>("/api/tailscale").catch(
      () => null,
    );
    if (
      nodeIds.every(
        (id) =>
          view?.servers.find((server) => server.nodeId === id)?.vault?.set ===
          set,
      )
    ) {
      return;
    }
    await wait(POLL_MS);
  }
  throw new Error(
    "Your servers took the credential but have not reported it yet. Open Network again in a minute.",
  );
}

async function begin(devices: Device[]) {
  const signers = devices.filter(usable).map((device) => device.id);
  if (signers.length === 0) throw new Error(NO_SIGNER);
  const session = await openSession(signers);
  const fingerprint =
    devices.find((device) => device.id === session.grant.credentialId)
      ?.fingerprint ?? "";
  return { session, fingerprint };
}

const keysOf = (nodes: VaultNode[]) =>
  Object.fromEntries(nodes.map((node) => [node.id, node.sealKey ?? ""]));

const connectedOf = (context: Context) => {
  const connected = context.data?.connected;
  if (!connected) throw new Error("Connect Tailscale first.");
  return connected;
};

function useOf(
  nodes: VaultNode[],
  connected: TailnetConnected,
  without?: string,
) {
  const use = planUse(nodes, connected.setId, without);
  if (!use.ok) throw new Error(use.reason);
  return use;
}

const running = (servers: TailnetServer[]) =>
  servers.filter((server) => server.report?.state === "running");

async function read(
  session: Session,
  use: { assembler: string; releaser: string },
  keyOf: Record<string, string>,
  connected: Pick<TailnetConnected, "clientId" | "setId">,
  servers: TailnetServer[],
): Promise<Started> {
  const asking = running(servers);
  const [sent, asked] = await Promise.all([
    sendOperation(
      session,
      { kind: "tailnet" },
      readSteps(use, keyOf, connected as TailnetConnected),
    ),
    asking.length > 0
      ? postActions({
          action: "inspect",
          mode: "parallel",
          targets: asking.map((server) => ({
            nodeId: server.nodeId,
            kind: "host" as const,
            name: "tailscale",
          })),
        })
      : Promise.resolve({ actions: [] as { id: string }[] }),
  ]);
  const [reading, inspected] = await Promise.all([
    finished(sent.actions.map((action) => action.id)),
    finished(asked.actions.map((action) => action.id)),
  ]);
  const policy = reading.at(-1);
  const problem = failed(policy, "The policy file could not be read.");
  if (problem) throw new Error(problem);
  const answer = outputOf<PolicyRead>(policy!);
  if (!answer) throw new Error("The policy file could not be read.");
  return {
    read: answer,
    inUse: Object.fromEntries(
      inspected.map((action) => [
        action.nodeId,
        action.status === "done"
          ? (outputOf<{ inUse?: { from: string; port: string }[] }>(action)
              ?.inUse ?? [])
          : [],
      ]),
    ),
  };
}

async function save(
  context: Context,
  session: Session,
  nodes: VaultNode[],
  input: {
    rules: TailnetRule[];
    expected: string;
    tag: boolean;
    label: string;
    servers?: TailnetServer[];
  },
): Promise<Saved> {
  const connected = connectedOf(context);
  const steps = saveSteps({
    use: useOf(nodes, connected),
    keyOf: keysOf(nodes),
    connected,
    rules: input.rules,
    servers: input.servers ?? context.data?.servers ?? [],
    expected: input.expected,
    tag: input.tag,
    label: input.label,
  });
  const sent = await sendOperation(session, { kind: "tailnet" }, steps);
  const job = (await finished(sent.actions.map((action) => action.id))).at(-1);
  const problem = failed(job, "Tailscale did not take the rules.");
  if (problem) throw new Error(problem);
  const answer = outputOf<{
    saved?: boolean;
    block?: string;
    changed?: { now?: string[] };
  }>(job!);
  return answer?.saved === false
    ? {
        saved: false,
        block: answer.block ?? "",
        now: answer.changed?.now ?? [],
      }
    : { saved: true };
}

function useFlow<I, O>(work: (input: I, context: Context) => Promise<O>) {
  const devices = useDevices().data?.devices ?? [];
  const tailnet = useTailnet();
  return useApiMutation(
    async (input: I) => {
      try {
        return await work(input, {
          devices,
          data: tailnet.data,
          nodesFor: tailnet.nodesFor,
        });
      } catch (error) {
        throw new Error(
          error instanceof DOMException ? failure(error) : errorMessage(error),
        );
      }
    },
    [...ACTION_QUERIES, queryKeys.tailscale, queryKeys.overview],
    false,
  );
}

export function useTailnet() {
  const tailscale = useTailscale();
  const services = useServices();
  const overview = useOverview();
  const nodesFor = (fingerprint: string | null) =>
    services.data && overview.data
      ? vaultNodes(
          services.data,
          overview.data.nodes,
          fingerprint,
          overview.dataUpdatedAt,
          "tailscale",
        )
      : [];
  const listeners = Object.fromEntries(
    (tailscale.data?.servers ?? []).map((server) => [
      server.nodeId,
      server.listeners ?? [],
    ]),
  );
  return {
    data: tailscale.data,
    error: tailscale.error,
    nodesFor,
    listeners,
  };
}

export const useConnect = () =>
  useFlow(
    async (
      input: {
        secret: string;
        clientId: string;
        webhookSecret: string;
        tailnet: string;
        change: boolean;
      },
      context,
    ): Promise<Started | null> => {
      const { session, fingerprint } = await begin(context.devices);
      const nodes = context.nodesFor(fingerprint);
      const set = crypto.randomUUID();
      const plan = await connectSteps({
        secret: input.secret.trim(),
        set,
        tailnet: input.tailnet,
        clientId: input.clientId.trim(),
        webhookSecret: input.webhookSecret.trim(),
        holders: splitHolders(nodes, "tailscale"),
      });
      if (!plan.ok) throw new Error(plan.reason);
      const sent = await sendOperation(
        session,
        {
          kind: "split",
          tailscale: {
            tailnet: plan.tailscale.tailnet,
            clientId: plan.tailscale.clientId,
            ...(plan.tailscale.webhookSecret
              ? { webhookSecret: plan.tailscale.webhookSecret }
              : {}),
          },
        },
        plan.steps,
      );
      const stores = await finished(sent.actions.map((action) => action.id));
      const kept = stores
        .filter((action) => action.status === "done")
        .map((action) => action.nodeId);
      if (kept.length < 2) {
        throw new Error(
          failed(
            stores.find((action) => action.status !== "done"),
            "Fewer than two servers took a piece of the credential.",
          ) ?? "Fewer than two servers took a piece of the credential.",
        );
      }
      if (input.change) return null;
      await holding(kept.slice(0, 2), set);
      return read(
        session,
        { assembler: kept[0]!, releaser: kept[1]! },
        keysOf(nodes),
        { clientId: input.clientId.trim(), setId: set },
        context.data?.servers ?? [],
      );
    },
  );

export const useReadPolicy = () =>
  useFlow(async (_input: null, context): Promise<Started> => {
    const connected = connectedOf(context);
    const { session, fingerprint } = await begin(context.devices);
    const nodes = context.nodesFor(fingerprint);
    return read(
      session,
      useOf(nodes, connected),
      keysOf(nodes),
      connected,
      context.data?.servers ?? [],
    );
  });

export const useSaveRules = () =>
  useFlow(
    async (
      input: {
        rules: TailnetRule[];
        expected: string;
        tag: boolean;
        label: string;
      },
      context,
    ) => {
      const { session, fingerprint } = await begin(context.devices);
      return save(context, session, context.nodesFor(fingerprint), input);
    },
  );

export const useJoinTailnet = () =>
  useFlow(async (nodeId: string, context) => {
    const connected = connectedOf(context);
    const { session, fingerprint } = await begin(context.devices);
    const nodes = context.nodesFor(fingerprint);
    const keyOf = keysOf(nodes);
    if (!keyOf[nodeId]) {
      throw new Error("This server has no sealing key yet. Update its agent.");
    }
    const sent = await sendOperation(
      session,
      { kind: "tailnet" },
      joinSteps(useOf(nodes, connected), keyOf, connected, nodeId),
    );
    const joined = (await finished(sent.actions.map((action) => action.id))).at(
      -1,
    );
    const problem = failed(joined, "The server did not join your tailnet.");
    if (problem) throw new Error(problem);
    const answer = outputOf<{
      id: string | null;
      addresses: string[];
      name: string | null;
    }>(joined!);
    const report: TailscaleReport = {
      state: "running",
      addresses: answer?.addresses ?? [],
      name: answer?.name ?? null,
      keyExpiry: null,
      id: answer?.id ?? null,
      tags: [TAILSCALE.tag],
    };
    const servers = (context.data?.servers ?? []).map((server) =>
      server.nodeId === nodeId ? { ...server, report } : server,
    );
    const saved = await save(context, session, nodes, {
      rules: connected.rules,
      expected: connected.block ?? "",
      tag: false,
      label: "Sign In",
      servers,
    });
    return { report, servers, saved };
  });

export const useRemoveFromTailnet = () =>
  useFlow(async (nodeId: string, context) => {
    const connected = connectedOf(context);
    const device = context.data?.servers.find(
      (server) => server.nodeId === nodeId,
    )?.report?.id;
    if (!device) {
      throw new Error("Krynodes does not know this server's Tailscale ID.");
    }
    const { session, fingerprint } = await begin(context.devices);
    const nodes = context.nodesFor(fingerprint);
    const sent = await sendOperation(
      session,
      { kind: "tailnet" },
      removeSteps(
        useOf(nodes, connected, nodeId),
        keysOf(nodes),
        connected,
        device,
        nodeId,
      ),
    );
    const job = (await finished(sent.actions.map((action) => action.id))).at(
      -1,
    );
    const problem = failed(job, "Tailscale did not remove the server.");
    if (problem) throw new Error(problem);
  });

export const useDisconnect = () =>
  useFlow(async (_input: null, context) => {
    const steps = disconnectSteps(context.data?.servers ?? []);
    if (steps.length === 0) {
      throw new Error("No server holds a piece of the credential.");
    }
    const { session } = await begin(context.devices);
    await sendOperation(session, { kind: "disconnect" }, steps);
  });
