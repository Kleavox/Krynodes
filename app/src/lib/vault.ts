import { MIN_AGENT_VERSION } from "@krynodes/protocol/versions";
import type {
  ActionRecord,
  ActionVerb,
  NodeRecord,
  ServicesResponse,
} from "../types";

import { nodeState } from "./format";

import type { CommandTarget } from "./passkeys";
import { seal } from "./seal";
import { split } from "./shamir";

export interface Holder {
  nodeId: string;
  sealKey: string;
}

export interface OperationTarget extends CommandTarget {
  action: ActionVerb;
  attachFrom?: number;
  attachKey?: string;
}

const encoder = new TextEncoder();

const vault = (nodeId: string) =>
  ({ nodeId, kind: "vault", name: "cloudflare" }) as const;

export function pieceJson(set: string, piece: Uint8Array): string {
  return JSON.stringify({ set, piece: btoa(String.fromCharCode(...piece)) });
}

export async function splitSteps(
  token: string,
  holders: Holder[],
  set: string,
  source: string | null,
): Promise<OperationTarget[]> {
  const pieces = split(encoder.encode(token.trim()), holders.length);
  return Promise.all(
    holders.map(async (holder, index) => ({
      ...vault(holder.nodeId),
      action: "store" as const,
      piece: await seal(holder.sealKey, pieceJson(set, pieces[index]!)),
      args: {
        set,
        holders: String(holders.length),
        ...(source ? { source } : {}),
      },
    })),
  );
}

const release = (
  releaser: string,
  to: string,
  key: string,
  set: string,
): OperationTarget => ({
  ...vault(releaser),
  action: "release",
  args: { to, key, set },
});

export function reshareSteps(input: {
  releaser: string | null;
  assembler: string;
  holders: Holder[];
  keyOf: Record<string, string>;
  set: string;
  source: string;
  cleanup?: string;
  zone: string;
  forgets: string[];
}): OperationTarget[] {
  const steps: OperationTarget[] = input.releaser
    ? [
        release(
          input.releaser,
          input.assembler,
          input.keyOf[input.assembler] ?? "",
          input.source,
        ),
      ]
    : [];
  const index = steps.length;
  steps.push({
    ...vault(input.assembler),
    action: "reshare",
    args: {
      holders: input.holders
        .map((holder) => `${holder.nodeId}:${holder.sealKey}`)
        .join(","),
      set: input.set,
      source: input.source,
      ...(input.cleanup ? { cleanup: input.cleanup } : {}),
      zone: input.zone,
    },
    ...(input.releaser ? { attachFrom: 0 } : {}),
  });
  for (const holder of input.holders) {
    steps.push({
      ...vault(holder.nodeId),
      action: "store",
      args: {
        set: input.set,
        holders: String(input.holders.length),
        source: input.source,
      },
      attachFrom: index,
      attachKey: holder.nodeId,
    });
  }
  for (const nodeId of input.forgets) {
    steps.push({ ...vault(nodeId), action: "forget" });
  }
  return steps;
}

const slug = (text: string) =>
  text
    .toLowerCase()
    .replace(/[^a-z0-9-]+/gu, "-")
    .replace(/^-+|-+$/gu, "");

export function hostnameFor(project: string, server: string, zone: string) {
  return `${slug(slug(`${slug(project)}-${slug(server)}`).slice(0, 63))}.${zone}`;
}

export function addressProblem(label: string, port: string): string | null {
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)) {
    return "Use 1 to 63 lowercase letters, digits and -, not starting or ending with -.";
  }
  const number = Number(port);
  return /^\d+$/u.test(port) && number >= 1 && number <= 65535
    ? null
    : "The port must be 1 to 65535.";
}

export function exposeSteps(input: {
  target: string;
  targetKey: string;
  project: string;
  service: string;
  port: number;
  hostname: string;
  mode: "allow" | "path" | "everyone";
  path?: string;
  zone: string;
  aud: string;
  releaser: string | null;
  source: string;
}): OperationTarget[] {
  return [
    ...(input.releaser
      ? [release(input.releaser, input.target, input.targetKey, input.source)]
      : []),
    {
      nodeId: input.target,
      kind: "compose",
      name: input.project,
      action: "expose",
      args: {
        service: input.service,
        port: String(input.port),
        hostname: input.hostname,
        mode: input.mode,
        ...(input.mode === "path" ? { path: input.path ?? "/" } : {}),
        zone: input.zone,
        aud: input.aud,
        source: input.source,
      },
      ...(input.releaser ? { attachFrom: 0 } : {}),
    },
  ];
}

export function unexposeSteps(input: {
  target: string;
  targetKey: string;
  project: string;
  hostname: string;
  zone: string;
  releaser: string | null;
  disposal?: "remove" | "purge";
  source: string;
}): OperationTarget[] {
  return [
    ...(input.releaser
      ? [release(input.releaser, input.target, input.targetKey, input.source)]
      : []),
    {
      nodeId: input.target,
      kind: "compose",
      name: input.project,
      action: "unexpose",
      args: {
        hostname: input.hostname,
        zone: input.zone,
        source: input.source,
      },
      ...(input.releaser ? { attachFrom: 0 } : {}),
    },
    ...(input.disposal
      ? [
          {
            nodeId: input.target,
            kind: "compose" as const,
            name: input.project,
            action: input.disposal,
          },
        ]
      : []),
  ];
}

export function moveSteps(input: {
  source: string;
  target: string;
  targetKey: string;
  project: string;
  compose: string;
  access: "contained" | "full";
  secrets?: string;
  original: "now" | "later" | "keep";
}): OperationTarget[] {
  return [
    {
      nodeId: input.source,
      kind: "compose",
      name: input.project,
      action: "export",
      args: { to: input.target, key: input.targetKey },
    },
    {
      nodeId: input.target,
      kind: "compose",
      name: input.project,
      action: "create",
      compose: input.compose,
      access: input.access,
      ...(input.secrets ? { secrets: input.secrets } : {}),
      attachFrom: 0,
    },
    ...(input.original === "keep"
      ? []
      : [
          {
            nodeId: input.source,
            kind: "compose" as const,
            name: input.project,
            action:
              input.original === "now"
                ? ("purge" as const)
                : ("remove" as const),
          },
        ]),
  ];
}

export interface VaultNode {
  id: string;
  name: string;
  sealKey: string | null;
  vault: {
    set: string;
    holders: number;
    previous?: { set: string; holders: number };
  } | null;
  reachable: boolean;
  online: boolean;
}

type Plan<T> = ({ ok: true } & T) | { ok: false; reason: string };

export function pieceOf(
  node: VaultNode | undefined,
  setId: string | null,
): { set: string; holders: number } | null {
  if (!node?.vault || setId === null) return null;
  if (node.vault.set === setId) return node.vault;
  return node.vault.previous?.set === setId ? node.vault.previous : null;
}

export const splitHolders = (nodes: VaultNode[]): Holder[] =>
  nodes
    .filter((node) => node.reachable && node.online && node.sealKey)
    .map((node) => ({ nodeId: node.id, sealKey: node.sealKey! }));

export function planSpread(
  nodes: VaultNode[],
  setId: string | null,
): Plan<{
  assembler: string;
  releaser: string | null;
  holders: Holder[];
  forgets: string[];
}> {
  const holders = splitHolders(nodes);
  const current = nodes.filter((node) => pieceOf(node, setId) !== null);
  if (current.length === 0) {
    return {
      ok: false,
      reason: "No server holds a piece any more. Paste the token again.",
    };
  }
  if (holders.length === 0) {
    return {
      ok: false,
      reason: `This device reaches no online server with agent ${MIN_AGENT_VERSION}.`,
    };
  }
  const usable = current.filter((node) => node.reachable && node.online);
  const whole =
    current.length === 1 && pieceOf(current[0], setId)!.holders === 1;
  if (whole ? usable.length < 1 : usable.length < 2) {
    return {
      ok: false,
      reason: whole
        ? `${current[0]!.name} holds the token and must be online.`
        : `Two servers holding a piece must be online; ${usable.length} is.`,
    };
  }
  const kept = holders.map((holder) => holder.nodeId);
  return {
    ok: true,
    assembler: usable[0]!.id,
    releaser: whole ? null : usable[1]!.id,
    holders,
    forgets: usable
      .filter((node) => !kept.includes(node.id))
      .map((node) => node.id),
  };
}

export function planRemoval(
  nodes: VaultNode[],
  removed: string,
  setId: string | null,
  addresses = false,
): Plan<
  | { needed: false }
  | {
      needed: true;
      assembler: string;
      releaser: string | null;
      holders: Holder[];
      forgets: string[];
    }
> {
  const gone = nodes.find((node) => node.id === removed);
  if (!gone || setId === null || (!pieceOf(gone, setId) && !addresses)) {
    return { ok: true, needed: false };
  }
  const plan = planSpread(
    [...nodes.filter((node) => node.id !== removed), gone],
    setId,
  );
  if (!plan.ok) return plan;
  const holders = plan.holders.filter((holder) => holder.nodeId !== removed);
  if (holders.length === 0) {
    return {
      ok: false,
      reason: `No other server with agent ${MIN_AGENT_VERSION} that this device reaches can take the token.`,
    };
  }
  return {
    ...plan,
    needed: true,
    holders,
    forgets: [
      ...plan.forgets,
      ...(gone.vault && gone.reachable && gone.online ? [removed] : []),
    ],
  };
}

export function planAddress(
  nodes: VaultNode[],
  target: string,
  setId: string | null,
): Plan<{ releaser: string | null }> {
  const node = nodes.find((item) => item.id === target);
  const piece = pieceOf(node, setId);
  if (!piece) {
    return {
      ok: false,
      reason: `${node?.name ?? "This server"} holds no piece of the Cloudflare token. Spread it again under Settings, Cloudflare.`,
    };
  }
  if (piece.holders === 1) return { ok: true, releaser: null };
  const other = nodes.find(
    (item) =>
      item.id !== target &&
      pieceOf(item, setId) !== null &&
      item.reachable &&
      item.online,
  );
  return other
    ? { ok: true, releaser: other.id }
    : {
        ok: false,
        reason: "Another server holding a piece of the token must be online.",
      };
}

export function vaultNodes(
  data: ServicesResponse,
  nodes: NodeRecord[],
  fingerprint: string | null,
  seen: number,
): VaultNode[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  return data.nodes.flatMap((entry) => {
    const node = byId.get(entry.id);
    if (!node) return [];
    return [
      {
        id: entry.id,
        name: node.name,
        sealKey: entry.sealKey ?? null,
        vault: entry.vault ?? null,
        reachable:
          fingerprint === null
            ? (entry.trust?.access.length ?? 0) > 0
            : (entry.trust?.access.includes(fingerprint) ?? false),
        online: nodeState(node, seen) !== "offline",
      },
    ];
  });
}

const TOKEN_STEPS = ["store", "reshare", "forget"];

export const pendingTokenSteps = (
  actions: Pick<ActionRecord, "kind" | "action" | "status">[],
) =>
  actions.filter(
    (action) =>
      action.kind === "vault" &&
      TOKEN_STEPS.includes(action.action) &&
      (action.status === "queued" || action.status === "sent"),
  ).length;
