import {
  documentHash,
  networkDocumentSchema,
  type NetworkDocument,
} from "@krynodes/protocol";
import { useQuery } from "@tanstack/react-query";

import type {
  ActionKind,
  ActionRow,
  Device,
  FleetNode,
  LaptopCode,
  NetworkApplied,
  NetworkChange,
  NetworkNext,
  NetworkView,
  SessionResponse,
} from "../types";
import { ApiError, apiFetch } from "./http";
import { fromB64url } from "./passkeys";
import { queryKeys } from "./query-client";

export function useSession() {
  return useQuery({
    queryKey: queryKeys.session,
    queryFn: () => apiFetch<SessionResponse>("/api/session"),
    retry: 1,
    refetchOnWindowFocus: false,
  });
}

export function useDevices() {
  return useQuery({
    queryKey: queryKeys.devices,
    queryFn: () => apiFetch<Device[]>("/api/devices"),
  });
}

export interface ActionBody {
  nodeId: string;
  id: string;
  kind: ActionKind;
  name: string;
  action: string;
  title: string;
  signed: string;
}

const post = <T>(path: string, body?: object) =>
  apiFetch<T>(path, {
    method: "POST",
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

const flip = (node: string, verb: "reject" | "again") =>
  post<{ state: "rejected" | "requested" }>(
    `/api/network/requests/${encodeURIComponent(node)}/${verb}`,
  );

export async function currentDocument(): Promise<{
  document: NetworkDocument;
  hash: string;
} | null> {
  let current: { version: number; hash: string; document: string };
  try {
    current = await apiFetch("/api/network/current");
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
  const unreadable = () =>
    new Error("The network document cannot be read. Nothing was changed.");
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = fromB64url(current.document);
  } catch {
    throw unreadable();
  }
  if ((await documentHash(bytes)) !== current.hash) {
    throw new Error(
      "The network document does not match its hash. Nothing was changed.",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    parsed = null;
  }
  const read = networkDocumentSchema.safeParse(parsed);
  if (!read.success) throw unreadable();
  return { document: read.data, hash: current.hash };
}

export const networkApi = {
  current: currentDocument,
  nodes: () => apiFetch<FleetNode[]>("/api/nodes"),
  network: () => apiFetch<NetworkView>("/api/network"),
  applied: () => apiFetch<NetworkApplied>("/api/network/applied"),
  next: (ids: string[], range?: string) =>
    apiFetch<NetworkNext>(
      `/api/network/next?${new URLSearchParams({
        for: ids.join(","),
        ...(range ? { range } : {}),
      })}`,
    ),
  postDocument: (body: {
    signed: string;
    change: string;
    detail: string | null;
  }) => post<{ version: number }>("/api/network/document", body),
  changes: () => apiFetch<NetworkChange[]>("/api/network/changes"),
  reject: (node: string) => flip(node, "reject"),
  askAgain: (node: string) => flip(node, "again"),
  addLaptop: (body: { name: string; trust: string[] }) =>
    post<LaptopCode>("/api/laptops", body),
  sendAction: (body: ActionBody) => post<ActionRow>("/api/actions", body),
  actions: (nodeId: string) =>
    apiFetch<ActionRow[]>(
      `/api/actions?node=${encodeURIComponent(nodeId)}&limit=50`,
    ),
};
