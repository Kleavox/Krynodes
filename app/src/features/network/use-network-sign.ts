import { useState, useSyncExternalStore } from "react";
import { useQueries } from "@tanstack/react-query";
import type { NetworkDocument, NetworkTest } from "@krynodes/protocol";

import {
  ACTION_QUERIES,
  postActions,
  postNetworkDocument,
  useApiMutation,
  useDevices,
  useServices,
} from "@/lib/api";
import { activeSession, openSession } from "@/lib/deploy-session";
import { signersFor } from "@/lib/devices";
import { apiFetch, errorMessage } from "@/lib/http";
import {
  baseOf,
  buildDocument,
  joinerOf,
  missingSeals,
  networkText,
  preparedOf,
  type DocumentChange,
  type Seat,
} from "@/lib/network";
import { signCommand, signTargets, type Session } from "@/lib/passkeys";
import { failure } from "@/lib/proof";
import { queryKeys } from "@/lib/query-client";
import { isPending } from "@/lib/services";
import type { ActionRecord, NetworkNext, NetworkView } from "@/types";

const POLL_MS = 3_000;

type Prepared = NonNullable<ReturnType<typeof preparedOf>>;

export interface JoinSeat extends Seat {
  port: number;
  tools: boolean;
  waitingFor: string | null;
  prepared?: Prepared;
}

export interface Job {
  kind: "create" | "add";
  range: string;
  port: number;
  mtu: number;
  seats: JoinSeat[];
  actions: Record<string, ActionRecord>;
  addresses: Record<string, string>;
  phase: "preparing" | "signing" | "sign" | "done" | "failed";
  error: string | null;
  postedAt: number | null;
  signers: string[];
  sealKeys: Record<string, string>;
}

let job: Job | null = null;
const listeners = new Set<() => void>();

function set(next: Job | null) {
  job = next;
  for (const listener of listeners) listener();
}

const update = (from: Job, change: Partial<Job>) => {
  if (job && job.seats === from.seats) set({ ...job, ...change });
};

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

const snapshot = () => job;

export const useJoin = () =>
  useSyncExternalStore(subscribe, snapshot, snapshot);

export const clearJoin = () => set(null);

const said = (error: unknown) =>
  error instanceof DOMException && error.name === "NotAllowedError"
    ? failure(error)
    : errorMessage(error);

async function signDocument(session: Session, document: NetworkDocument) {
  const signed = await signCommand(session, document);
  return {
    grant: signed.grant,
    document: signed.command,
    signature: signed.signature,
  };
}

const wait = (milliseconds: number) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

export async function startJoin(
  input: Omit<Job, "actions" | "addresses" | "phase" | "error" | "postedAt">,
) {
  const session = await openSession(input.signers);
  const fresh = input.seats.filter((seat) => !seat.prepared);
  const targets =
    fresh.length > 0
      ? await signTargets(
          session,
          "prepare",
          fresh.map((seat) => ({
            nodeId: seat.nodeId,
            kind: "network" as const,
            name: "kry0",
            args: { range: input.range, port: String(seat.port) },
          })),
        )
      : [];
  if (targets.length > 0) {
    await postActions({ action: "prepare", mode: "parallel", targets });
  }
  const started: Job = {
    ...input,
    actions: {},
    addresses: {},
    phase: "preparing",
    error: null,
    postedAt: null,
  };
  set(started);
  void follow(
    started,
    Object.fromEntries(targets.map((target) => [target.nodeId, target.id])),
  );
}

async function follow(started: Job, ids: Record<string, string>) {
  for (;;) {
    if (job?.seats !== started.seats) return;
    const actions = job.actions;
    const open = Object.entries(ids).filter(
      ([nodeId]) => !actions[nodeId] || isPending(actions[nodeId]),
    );
    if (open.length === 0) break;
    await wait(POLL_MS);
    try {
      const replies = await Promise.all(
        open.map(async ([nodeId, id]) => {
          const reply = await apiFetch<{ action: ActionRecord }>(
            `/api/actions/${encodeURIComponent(id)}`,
          );
          return [nodeId, reply.action] as const;
        }),
      );
      update(started, {
        actions: { ...job.actions, ...Object.fromEntries(replies) },
      });
    } catch {
      continue;
    }
  }
  await finishJoin();
}

export async function finishJoin() {
  const current = job;
  if (!current) return;
  const ready = current.seats.flatMap((seat) => {
    const prepared =
      seat.prepared ??
      (current.actions[seat.nodeId]
        ? preparedOf(current.actions[seat.nodeId]!)
        : null);
    return prepared ? [{ seat, prepared }] : [];
  });
  if (ready.length === 0) {
    update(current, {
      phase: "failed",
      error: "No server got ready, so nothing was changed.",
    });
    return;
  }
  update(current, { phase: "signing", error: null });
  try {
    const ids = ready.map(({ seat }) => seat.nodeId);
    const query = new URLSearchParams({
      nodes: ids.join(","),
      ...(current.kind === "create" ? { range: current.range } : {}),
    });
    const [next, view] = await Promise.all([
      apiFetch<NetworkNext>(`/api/network/next?${query}`),
      apiFetch<NetworkView>("/api/network"),
    ]);
    const addresses = Object.fromEntries(
      next.addresses.map((entry) => [entry.nodeId, entry.address]),
    );
    const join = ready.map(({ seat, prepared }) =>
      joinerOf(seat, prepared, addresses[seat.nodeId]!),
    );
    const change: DocumentChange =
      current.kind === "create"
        ? {
            kind: "create",
            range: current.range,
            port: current.port,
            mtu: current.mtu,
            join,
          }
        : { kind: "add", join };
    const base = await baseOf(view);
    const document = await buildDocument(
      base?.document ?? null,
      change,
      current.sealKeys,
      base?.parent,
    );
    const session = activeSession() ?? (await openSession(current.signers));
    const names = ready.map(({ seat }) => seat.name);
    await postNetworkDocument({
      signed: await signDocument(session, document),
      change:
        current.kind === "create"
          ? networkText.create(names)
          : networkText.add(names),
      detail: null,
    });
    update(current, { phase: "done", postedAt: Date.now(), addresses });
  } catch (error) {
    update(current, { phase: "sign", error: said(error) });
  }
}

async function settle(ids: Record<string, string>) {
  const ended: Record<string, ActionRecord> = {};
  for (;;) {
    const open = Object.entries(ids).filter(([nodeId]) => !ended[nodeId]);
    if (open.length === 0) return ended;
    await wait(POLL_MS);
    try {
      for (const [nodeId, id] of open) {
        const reply = await apiFetch<{ action: ActionRecord }>(
          `/api/actions/${encodeURIComponent(id)}`,
        );
        if (!isPending(reply.action)) ended[nodeId] = reply.action;
      }
    } catch {
      continue;
    }
  }
}

export interface Change {
  change: DocumentChange;
  text: string;
  detail?: string | null;
  signers: string[];
  sealKeys?: Record<string, string>;
}

async function signChange(input: Change) {
  if (input.signers.length === 0) {
    throw new Error(
      "None of your passkeys has access to every server in the network. Change access in Passkeys.",
    );
  }
  const session = await openSession(input.signers);
  const base = await baseOf(await apiFetch<NetworkView>("/api/network"));
  const document = await buildDocument(
    base?.document ?? null,
    input.change,
    input.sealKeys ?? {},
    base?.parent,
  );
  await postNetworkDocument({
    signed: await signDocument(session, document),
    change: input.text,
    detail: input.detail ?? null,
  });
}

export const useSignChange = () =>
  useApiMutation(
    (input: Change) =>
      signChange(input).catch((error: unknown) => {
        throw new Error(said(error));
      }),
    [["network"], ...ACTION_QUERIES],
    false,
  );

async function makeNewKeys(input: {
  view: NetworkView;
  online: string[];
  signers: string[];
  sealKeys: Record<string, string>;
}) {
  const missing = missingSeals(input.view, input.sealKeys);
  if (missing) throw new Error(missing);
  const session = await openSession(input.signers);
  const targets = await signTargets(
    session,
    "rekey",
    input.online.map((nodeId) => ({
      nodeId,
      kind: "network" as const,
      name: "kry0",
    })),
  );
  await postActions({ action: "rekey", mode: "parallel", targets });
  const ended = await settle(
    Object.fromEntries(targets.map((target) => [target.nodeId, target.id])),
  );
  const keys = Object.fromEntries(
    Object.entries(ended).flatMap(([nodeId, action]) => {
      const key =
        action.status === "done"
          ? answerOf<{ key: string }>(action.output)?.key
          : undefined;
      return key ? [[nodeId, key]] : [];
    }),
  );
  await signChange({
    change: { kind: "rekey", keys },
    text: networkText.rekey,
    signers: input.signers,
    sealKeys: input.sealKeys,
  });
}

export const useMakeNewKeys = () =>
  useApiMutation(
    (input: Parameters<typeof makeNewKeys>[0]) =>
      makeNewKeys(input).catch((error: unknown) => {
        throw new Error(said(error));
      }),
    [["network"], ...ACTION_QUERIES],
    false,
  );

export async function testPair(
  ends: { nodeId: string; peer: string; address: string }[],
  mtu: number,
) {
  if (ends.length === 0) return {};
  const sent = await postActions({
    action: "test",
    mode: "parallel",
    targets: ends.map((end) => ({
      nodeId: end.nodeId,
      kind: "network" as const,
      name: "kry0",
      args: { peer: end.peer, address: end.address, mtu: String(mtu) },
    })),
  });
  const ended = await settle(
    Object.fromEntries(
      ends.map((end, index) => [end.nodeId, sent.actions[index]!.id]),
    ),
  );
  return Object.fromEntries(
    Object.entries(ended).map(([nodeId, action]) => [
      nodeId,
      action.status === "done" ? answerOf<NetworkTest>(action.output) : null,
    ]),
  );
}

interface Answer<T> {
  value: T | null;
  waiting: boolean;
  error: string | null;
}

function answerOf<T>(output: string | null): T | null {
  try {
    return output ? (JSON.parse(output) as T) : null;
  } catch {
    return null;
  }
}

export function useAsk<T>(action: "inspect" | "probe") {
  const [ids, setIds] = useState<Record<string, string>>({});
  const send = useApiMutation(
    (targets: { nodeId: string; args?: Record<string, string> }[]) =>
      postActions({
        action,
        mode: "parallel",
        targets: targets.map((target) => ({
          nodeId: target.nodeId,
          kind: "network" as const,
          name: "kry0",
          ...(target.args ? { args: target.args } : {}),
        })),
      }),
    [],
  );
  const entries = Object.entries(ids);
  const replies = useQueries({
    queries: entries.map(([, id]) => ({
      queryKey: queryKeys.action(id),
      queryFn: () =>
        apiFetch<{ action: ActionRecord }>(
          `/api/actions/${encodeURIComponent(id)}`,
        ),
      refetchInterval: (query: {
        state: { data?: { action: ActionRecord } };
      }) =>
        !query.state.data || isPending(query.state.data.action)
          ? POLL_MS
          : false,
    })),
  });
  const answers: Record<string, Answer<T>> = {};
  entries.forEach(([nodeId], index) => {
    const action = replies[index]?.data?.action;
    const ended = action !== undefined && !isPending(action);
    answers[nodeId] = {
      value: action?.status === "done" ? answerOf<T>(action.output) : null,
      waiting: !ended,
      error:
        ended && action.status !== "done"
          ? action.output || "No answer came back."
          : null,
    };
  });
  const ask = (
    targets: { nodeId: string; args?: Record<string, string> }[],
  ) => {
    if (targets.length === 0) return;
    setIds((current) =>
      Object.fromEntries(
        Object.entries(current).filter(
          ([nodeId]) => !targets.some((target) => target.nodeId === nodeId),
        ),
      ),
    );
    send.mutate(targets, {
      onSuccess: (sent) =>
        setIds((current) => ({
          ...current,
          ...Object.fromEntries(
            targets.map((target, index) => [
              target.nodeId,
              sent.actions[index]!.id,
            ]),
          ),
        })),
    });
  };
  return {
    ask,
    answers,
    sending: send.isPending,
    error: send.error ? errorMessage(send.error) : null,
  };
}

export function useNetworkKeys(
  members: Pick<NetworkView["members"][number], "nodeId" | "state">[],
) {
  const devices = useDevices().data?.devices ?? [];
  const reports = useServices().data?.nodes ?? [];
  const trust = new Map(reports.map((entry) => [entry.id, entry.trust]));
  return {
    signers: signersFor(
      devices,
      members
        .filter((member) => member.state === "in")
        .map((member) => trust.get(member.nodeId) ?? null),
    ),
    sealKeys: Object.fromEntries(
      reports.flatMap((entry) =>
        entry.sealKey ? [[entry.id, entry.sealKey]] : [],
      ),
    ),
  };
}

export const useStartJoin = () =>
  useApiMutation(
    (input: Parameters<typeof startJoin>[0]) =>
      startJoin(input).catch((error: unknown) => {
        throw new Error(said(error));
      }),
    [...ACTION_QUERIES, ["network"]],
    false,
  );
