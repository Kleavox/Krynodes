import { QueryObserver, type QueryClient } from "@tanstack/react-query";

import { NETWORK } from "@krynodes/protocol";

import { apiFetch } from "@/lib/http";
import { onProgress } from "@/lib/live";
import { queryKeys } from "@/lib/query-client";
import { buildCommand, openSession, signCommand } from "@/lib/sign";
import type { ActionKind, ActionRow, FleetNode } from "@/types";

const POLL_MS = 30_000;

export interface ActionRequest {
  kind: ActionKind;
  action: string;
  title: string;
  name?: string;
  args?: Record<string, string>;
}

const commandName = (request: ActionRequest, node: FleetNode) =>
  request.name ?? (request.kind === "network" ? NETWORK.interface : node.name);

const carriesOutput = (request: ActionRequest) =>
  request.action === "logs" ||
  (request.kind === "stack" && request.action === "read");

const finished = (row: ActionRow | undefined): row is ActionRow =>
  row?.status === "done" || row?.status === "failed";

function settled(
  client: QueryClient,
  node: FleetNode,
  id: string,
  signal?: AbortSignal,
): Promise<ActionRow> {
  const nodeId = node.id;
  const observer = new QueryObserver(client, {
    queryKey: [...queryKeys.actions, nodeId],
    queryFn: () =>
      apiFetch<ActionRow[]>(
        `/api/actions?node=${encodeURIComponent(nodeId)}&limit=50`,
      ),
    staleTime: 0,
    refetchInterval: POLL_MS,
  });
  return new Promise((resolve, reject) => {
    let seen = false;
    let stop = () => undefined as void;
    const quit = () => {
      stop();
      reject(signal?.reason ?? new Error("Stopped waiting."));
    };
    stop = observer.subscribe(({ data }) => {
      if (!data) return;
      const row = data.find((entry) => entry.id === id);
      if (finished(row)) {
        stop();
        signal?.removeEventListener("abort", quit);
        resolve(row);
      } else if (row) {
        seen = true;
      } else if (seen && data.length === 0) {
        stop();
        signal?.removeEventListener("abort", quit);
        reject(new Error(`${node.name} was deleted.`));
      }
    });
    if (signal?.aborted) quit();
    else signal?.addEventListener("abort", quit, { once: true });
  });
}

export async function deliver(
  client: QueryClient,
  node: FleetNode,
  body: ActionRequest & { id: string; signed: string },
  onLine: (line: string) => void = () => undefined,
  signal?: AbortSignal,
): Promise<ActionRow> {
  const stop = onProgress((progress) => {
    if (progress.id === body.id) onLine(progress.line);
  });
  try {
    const row = await apiFetch<ActionRow>("/api/actions", {
      method: "POST",
      body: JSON.stringify({
        nodeId: node.id,
        id: body.id,
        kind: body.kind,
        name: commandName(body, node),
        action: body.action,
        title: body.title,
        signed: body.signed,
      }),
    });
    if (finished(row)) return row;
    const polled = await settled(client, node, body.id, signal);
    if (!carriesOutput(body)) return polled;
    return await apiFetch<ActionRow>(
      `/api/actions/${encodeURIComponent(body.id)}`,
      { signal },
    ).catch(() => polled);
  } finally {
    stop();
  }
}

export async function runAction(
  client: QueryClient,
  node: FleetNode,
  request: ActionRequest,
  onLine?: (line: string) => void,
  signal?: AbortSignal,
): Promise<ActionRow> {
  if (!node.online) throw new Error(`${node.name} is offline.`);
  if (!node.trust) {
    throw new Error(`${node.name} has not reported its trust yet.`);
  }
  const access = node.trust.access;
  if (access.length === 0) {
    throw new Error(`No passkey can act on ${node.name}.`);
  }
  const id = crypto.randomUUID();
  const session = await openSession(access);
  const signed = await signCommand(
    session,
    buildCommand(session, {
      id,
      nodeId: node.id,
      kind: request.kind,
      name: commandName(request, node),
      action: request.action,
      args: request.args,
    }),
  );
  return deliver(client, node, { ...request, id, signed }, onLine, signal);
}
