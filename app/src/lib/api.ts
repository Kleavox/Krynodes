import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryKey,
} from "@tanstack/react-query";
import type { QuarantineSettings } from "@krynodes/protocol";
import { toast } from "sonner";

import type {
  AddressOwner,
  ActionRecord,
  AttentionItem,
  ActionVerb,
  BatchMode,
  ChangeHistory,
  CheckKind,
  CheckResults,
  CloudflareSettings,
  DevicesResponse,
  Enrollment,
  EnrollmentStatus,
  HistoryPage,
  HistoryShow,
  IncidentBoard,
  IncidentDetail,
  IncidentUpdate,
  IncidentUpdateStatus,
  MetricRange,
  NetworkNext,
  NetworkView,
  NodeMetrics,
  Overview,
  PackagesResponse,
  ProposalRecord,
  QuarantineView,
  TailscaleResponse,
  RecentMetrics,
  ServicesResponse,
  SessionResponse,
  UsageResponse,
  UsageShare,
} from "../types";
import type { EnrollSetup } from "./enroll";
import { pollEnrollment } from "./enrollment";
import { historyPath } from "./history";
import { apiFetch, errorMessage } from "./http";
import { guardedFetch } from "./proof";
import { keepWhileSameNode, queryKeys } from "./query-client";
import { untilWindowSettles } from "./series";
import type { Approval, DeviceInput, SignedTarget } from "./passkeys";
import { isPending, pollServices } from "./services";

const MINUTE = 60_000;

const RANGE_REFRESH: Record<MetricRange, number> = {
  "6h": 5 * MINUTE,
  "24h": 15 * MINUTE,
  "7d": 60 * MINUTE,
};

export function useSession() {
  return useQuery({
    queryKey: queryKeys.session,
    queryFn: () => apiFetch<SessionResponse>("/api/session"),
    retry: 1,
    refetchOnWindowFocus: false,
  });
}

export function useOverview() {
  return useQuery({
    queryKey: queryKeys.overview,
    queryFn: () => apiFetch<Overview>("/api/overview"),
    refetchInterval: () => untilWindowSettles(Date.now()),
  });
}

export function useRecentMetrics() {
  return useQuery({
    queryKey: queryKeys.recentMetrics,
    queryFn: () => apiFetch<RecentMetrics>("/api/metrics/recent"),
    refetchInterval: () => untilWindowSettles(Date.now()),
  });
}

export function useNodeMetrics(id: string, range: MetricRange) {
  return useQuery({
    queryKey: queryKeys.nodeMetrics(id, range),
    queryFn: () =>
      apiFetch<NodeMetrics>(
        `/api/nodes/${encodeURIComponent(id)}/metrics?range=${range}`,
      ),
    refetchInterval: RANGE_REFRESH[range],
    placeholderData: keepWhileSameNode(id),
  });
}

export function useIncident(id: string) {
  return useQuery({
    queryKey: queryKeys.incident(id),
    queryFn: () =>
      apiFetch<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`),
    refetchInterval: (query) =>
      query.state.data?.incident.status === "OPEN"
        ? untilWindowSettles(Date.now())
        : false,
    retry: false,
  });
}

export const usePostIncidentUpdate = (id: string) =>
  useApiMutation(
    (update: { status: IncidentUpdateStatus; message: string }) =>
      apiFetch<IncidentUpdate>(
        `/api/incidents/${encodeURIComponent(id)}/updates`,
        send("POST", update),
      ),
    [queryKeys.incident(id), queryKeys.overview, queryKeys.incidentBoard],
  );

export const useDeleteIncidentUpdate = (id: string) =>
  useApiMutation(
    (updateId: string) =>
      apiFetch(
        `/api/incidents/${encodeURIComponent(id)}/updates/${encodeURIComponent(updateId)}`,
        send("DELETE"),
      ),
    [queryKeys.incident(id), queryKeys.overview, queryKeys.incidentBoard],
    true,
  );

export function useCheckResults() {
  return useQuery({
    queryKey: queryKeys.checkResults,
    queryFn: () => apiFetch<CheckResults>("/api/checks/results"),
    refetchInterval: () => untilWindowSettles(Date.now()),
  });
}

export interface CheckDismissal {
  nodeId: string;
  project: string;
  reaches: string[];
}

export function useCheckDismissals() {
  return useQuery({
    queryKey: queryKeys.checkDismissals,
    queryFn: () =>
      apiFetch<{ dismissals: CheckDismissal[] }>("/api/checks/dismissals"),
  });
}

export const useDismissCheck = () =>
  useApiMutation(
    (dismissal: CheckDismissal) =>
      apiFetch("/api/checks/dismissals", send("PUT", dismissal)),
    [queryKeys.checkDismissals],
    true,
  );

export function useApiMutation<TVariables, TData = unknown>(
  request: (variables: TVariables) => Promise<TData>,
  invalidate: readonly QueryKey[],
  toastErrors = false,
) {
  const client = useQueryClient();
  return useMutation<TData, Error, TVariables>({
    mutationFn: request,
    onSuccess: () =>
      Promise.all(
        invalidate.map((queryKey) => client.invalidateQueries({ queryKey })),
      ).then(() => undefined),
    onError: toastErrors
      ? (error) => {
          toast.error(errorMessage(error));
        }
      : undefined,
  });
}

function send(method: string, body?: unknown): RequestInit {
  return body === undefined
    ? { method }
    : { method, body: JSON.stringify(body) };
}

interface NewCheck {
  nodeId: string;
  name: string;
  kind: CheckKind;
  target: string;
  timeoutSeconds: number;
}

export const useCreateEnrollment = () =>
  useApiMutation(
    (setup: EnrollSetup) =>
      guardedFetch<Enrollment>("/api/enrollments", send("POST", setup)),
    [],
  );

export const useUpdateEnrollment = () =>
  useApiMutation(
    ({ id, setup }: { id: string; setup: EnrollSetup }) =>
      apiFetch(
        `/api/enrollments/${encodeURIComponent(id)}`,
        send("PATCH", setup),
      ),
    [],
  );

export function useEnrollmentStatus(id: string | undefined) {
  return useQuery({
    queryKey: queryKeys.enrollment(id ?? ""),
    queryFn: () =>
      apiFetch<EnrollmentStatus>(`/api/enrollments/${encodeURIComponent(id!)}`),
    enabled: id !== undefined,
    refetchInterval: (query) => pollEnrollment(query.state.data),
  });
}

export function usePrivateRanges(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.privateRanges,
    queryFn: () =>
      apiFetch<{ ranges: string[]; network: string | null }>(
        "/api/settings/private-ranges",
      ),
    enabled,
  });
}

export interface EnrollDefaults {
  recommended: boolean;
  docker: boolean;
  hour: number;
  network: boolean;
}

export function useEnrollDefaults(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.enrollDefaults,
    queryFn: () => apiFetch<EnrollDefaults>("/api/settings/enroll-defaults"),
    enabled,
  });
}

export const useSaveEnrollDefaults = () =>
  useApiMutation(
    (defaults: EnrollDefaults) =>
      apiFetch<EnrollDefaults>(
        "/api/settings/enroll-defaults",
        send("PUT", defaults),
      ),
    [queryKeys.enrollDefaults],
  );

export function useQuarantineSettings() {
  return useQuery({
    queryKey: queryKeys.quarantineSettings,
    queryFn: () =>
      apiFetch<{ settings: QuarantineSettings }>("/api/settings/quarantine"),
  });
}

export const useSaveQuarantineSettings = () =>
  useApiMutation(
    (settings: QuarantineSettings) =>
      guardedFetch<{ settings: QuarantineSettings }>(
        "/api/settings/quarantine",
        send("PUT", settings),
      ),
    [queryKeys.quarantineSettings],
  );

export function useQuarantine(id: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.quarantine(id),
    queryFn: () =>
      apiFetch<QuarantineView>(
        `/api/nodes/${encodeURIComponent(id)}/quarantine`,
      ),
    enabled,
    refetchInterval: () => untilWindowSettles(Date.now()),
  });
}

export const useCutOff = () =>
  useApiMutation(
    ({ nodeId, id }: { nodeId: string; id: string }) =>
      apiFetch(
        `/api/nodes/${encodeURIComponent(nodeId)}/warnings/${encodeURIComponent(id)}/cut`,
        send("POST"),
      ),
    [queryKeys.overview, ["quarantine"], queryKeys.network],
  );

export const postItWasMe = (
  nodeId: string,
  id: string,
  target?: SignedTarget & { action: ActionVerb },
) =>
  guardedFetch(
    `/api/nodes/${encodeURIComponent(nodeId)}/warnings/${encodeURIComponent(id)}/me`,
    send("POST", target ? { target } : {}),
  );

export const postRelease = (
  nodeId: string,
  body: { code: string; steps: (SignedTarget & { action: ActionVerb })[] },
) =>
  apiFetch<{ batchId: string; actions: { id: string }[] }>(
    `/api/nodes/${encodeURIComponent(nodeId)}/release`,
    send("POST", body),
  );

export const useSavePrivateRanges = () =>
  useApiMutation(
    (ranges: string[]) =>
      apiFetch<{ ranges: string[] }>(
        "/api/settings/private-ranges",
        send("PUT", { ranges }),
      ),
    [queryKeys.privateRanges, queryKeys.services],
  );

export const useUpdateNode = () =>
  useApiMutation(
    ({
      id,
      ...change
    }: {
      id: string;
      name?: string;
      autoUpdate?: boolean;
      addressOwner?: { family: 4 | 6; owner: AddressOwner | null };
    }) => apiFetch(`/api/nodes/${id}`, send("PATCH", change)),
    [queryKeys.overview, queryKeys.recentMetrics],
  );

export const useRequestAgentUpdate = () =>
  useApiMutation(
    (nodeId: string) =>
      apiFetch<{ version: string }>(
        `/api/nodes/${nodeId}/update`,
        send("POST"),
      ),
    [queryKeys.overview],
    true,
  );

export const useCheckAgentRelease = () =>
  useApiMutation(
    () =>
      apiFetch<{ version: string | null; requested: number }>(
        "/api/agent-release/check",
        send("POST"),
      ),
    [queryKeys.overview],
    true,
  );

export const useDeleteNode = () =>
  useApiMutation(
    (nodeId: string) => guardedFetch(`/api/nodes/${nodeId}`, send("DELETE")),
    [queryKeys.overview, queryKeys.recentMetrics, queryKeys.checkResults],
  );

export const useCreateCheck = () =>
  useApiMutation(
    (check: NewCheck) => apiFetch("/api/checks", send("POST", check)),
    [queryKeys.overview, queryKeys.checkResults],
  );

export const useUpdateCheck = () =>
  useApiMutation(
    ({
      id,
      ...change
    }: {
      id: string;
      name?: string;
      nodeId?: string;
      kind?: CheckKind;
      target?: string;
      timeoutSeconds?: number;
      enabled?: boolean;
      public?: boolean;
      publicNote?: string;
    }) => guardedFetch(`/api/checks/${id}`, send("PATCH", change)),
    [queryKeys.overview, queryKeys.checkResults],
  );

export const useDeleteCheck = () =>
  useApiMutation(
    (checkId: string) => guardedFetch(`/api/checks/${checkId}`, send("DELETE")),
    [queryKeys.overview, queryKeys.checkResults],
    true,
  );

export function useServices() {
  return useQuery({
    queryKey: queryKeys.services,
    queryFn: () => apiFetch<ServicesResponse>("/api/services"),
    refetchInterval: (query) => pollServices(query.state.data, Date.now()),
  });
}

export function useNodeActions(id: string) {
  return useQuery({
    queryKey: queryKeys.nodeActions(id),
    queryFn: () =>
      apiFetch<{ actions: ActionRecord[] }>(
        `/api/nodes/${encodeURIComponent(id)}/actions`,
      ),
    refetchInterval: (query) =>
      query.state.data?.actions.some(
        (action) => action.status === "queued" || action.status === "sent",
      )
        ? 5_000
        : untilWindowSettles(Date.now()),
  });
}

export const ACTION_QUERIES = [
  queryKeys.services,
  ["actions"],
  queryKeys.devices,
] as const;

export const postActions = (body: {
  action: Exclude<ActionVerb, "trust" | "heal">;
  mode: BatchMode;
  targets: (
    | SignedTarget
    | {
        nodeId: string;
        kind: "systemd" | "host" | "apt" | "network";
        name: string;
        args?: Record<string, string>;
      }
  )[];
  then?: "delete";
}) =>
  apiFetch<{ batchId: string; actions: { id: string }[] }>(
    "/api/actions",
    send("POST", body),
  );

export interface OperationStep {
  id: string;
  nodeId: string;
  kind: "compose" | "vault" | "host";
  name: string;
  action: ActionVerb;
  signed: unknown;
  attachFrom?: number;
  attachKey?: string;
}

export const postOperation = (body: {
  kind:
    | "move"
    | "expose"
    | "unexpose"
    | "split"
    | "reshare"
    | "tailnet"
    | "disconnect";
  steps: OperationStep[];
  zone?: string;
  tailscale?: { tailnet: string; clientId: string; webhookSecret?: string };
  deleteNode?: string;
}) =>
  apiFetch<{ batchId: string; actions: { id: string }[] }>(
    "/api/operations",
    send("POST", body),
  );

export function useTailscale(refetchInterval: number | false = false) {
  return useQuery({
    queryKey: queryKeys.tailscale,
    queryFn: () => apiFetch<TailscaleResponse>("/api/tailscale"),
    refetchInterval,
  });
}

export function useNetwork(refetchInterval: number | false = false) {
  return useQuery({
    queryKey: queryKeys.network,
    queryFn: () => apiFetch<NetworkView>("/api/network"),
    refetchInterval,
  });
}

export function useNetworkNext(nodes: string[], range?: string) {
  return useQuery({
    queryKey: queryKeys.networkNext(nodes, range),
    queryFn: () =>
      apiFetch<NetworkNext>(
        `/api/network/next?${new URLSearchParams({
          nodes: nodes.join(","),
          ...(range ? { range } : {}),
        })}`,
      ),
    enabled: nodes.length > 0,
  });
}

export const postNetworkDocument = (body: {
  signed: unknown;
  change: string;
  detail: string | null;
}) =>
  apiFetch<{ version: number }>("/api/network/document", send("POST", body));

export const postNetworkTest = (body: {
  change: string;
  detail: string | null;
  nodes: string[];
}) => apiFetch("/api/network/tests", send("POST", body));

export function useCloudflare() {
  return useQuery({
    queryKey: ["cloudflare"],
    queryFn: () => apiFetch<CloudflareSettings>("/api/cloudflare"),
  });
}

export const useScan = () =>
  useApiMutation(
    (nodeId: string) =>
      postActions({
        action: "scan",
        mode: "parallel",
        targets: [{ nodeId, kind: "host", name: "server" }],
      }),
    [...ACTION_QUERIES, queryKeys.overview],
    true,
  );

export function usePackages(id: string) {
  return useQuery({
    queryKey: queryKeys.packages(id),
    queryFn: () =>
      apiFetch<PackagesResponse>(
        `/api/nodes/${encodeURIComponent(id)}/packages`,
      ),
    refetchInterval: () => untilWindowSettles(Date.now()),
  });
}

export function usePackageNames(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.packageNames,
    queryFn: () =>
      apiFetch<{ servers: { nodeId: string; names: string[] }[] }>(
        "/api/packages",
      ),
    enabled,
  });
}

export const useAskApt = () =>
  useApiMutation(
    (ask: {
      nodeId: string;
      action: "refresh" | "find" | "preview";
      name: string;
      args?: Record<string, string>;
    }) =>
      postActions({
        action: ask.action,
        mode: "parallel",
        targets: [
          {
            nodeId: ask.nodeId,
            kind: "apt",
            name: ask.name,
            ...(ask.args ? { args: ask.args } : {}),
          },
        ],
      }),
    ACTION_QUERIES,
  );

export function useManualRestart() {
  return useApiMutation(
    (target: { nodeId: string; name: string }) =>
      postActions({
        action: "manual",
        mode: "parallel",
        targets: [
          { nodeId: target.nodeId, kind: "systemd", name: target.name },
        ],
      }),
    [...ACTION_QUERIES, queryKeys.overview],
  );
}

export function useAction(id: string | null) {
  return useQuery({
    queryKey: queryKeys.action(id),
    queryFn: () =>
      apiFetch<{ action: ActionRecord }>(
        `/api/actions/${encodeURIComponent(id!)}`,
      ),
    enabled: id !== null,
    refetchInterval: (query) =>
      isPending(query.state.data?.action) ? 5_000 : false,
  });
}

export const useCancelActions = () =>
  useApiMutation(
    (batchId: string) =>
      apiFetch(
        `/api/actions/${encodeURIComponent(batchId)}/cancel`,
        send("POST"),
      ),
    [queryKeys.services, ["actions"]],
    true,
  );

export const useRefreshServices = () =>
  useApiMutation(
    (nodeIds: string[] | undefined) =>
      apiFetch(
        "/api/services/refresh",
        send("POST", nodeIds ? { nodeIds } : {}),
      ),
    [queryKeys.services],
    true,
  );

export function useDevices(poll = false) {
  return useQuery({
    queryKey: queryKeys.devices,
    queryFn: () => apiFetch<DevicesResponse>("/api/devices"),
    refetchInterval: poll ? 5_000 : false,
  });
}

const DEVICE_QUERIES = [
  queryKeys.devices,
  queryKeys.services,
  queryKeys.proposals,
  ["actions"],
] as const;

export const useRegisterDevice = () =>
  useApiMutation(
    (device: DeviceInput) => apiFetch("/api/devices", send("POST", device)),
    [queryKeys.devices],
  );

export const useRenameDevice = () =>
  useApiMutation(
    ({ id, name }: { id: string; name: string }) =>
      apiFetch(
        `/api/devices/${encodeURIComponent(id)}`,
        send("PATCH", { name }),
      ),
    [queryKeys.devices],
    true,
  );

export const useForgetDevice = () =>
  useApiMutation(
    (id: string) =>
      apiFetch(`/api/devices/${encodeURIComponent(id)}`, send("DELETE")),
    [queryKeys.devices],
    true,
  );

export const useFirstTrust = () =>
  useApiMutation(
    (changes: string[]) =>
      apiFetch<{ queued: number }>("/api/trust", send("POST", { changes })),
    DEVICE_QUERIES,
  );

const page = (path: string, before: string) =>
  before
    ? `${path}${path.includes("?") ? "&" : "?"}before=${encodeURIComponent(before)}`
    : path;

export function useHistory(params: {
  node?: string;
  show: HistoryShow;
  q: string;
}) {
  const path = historyPath(params);
  return useInfiniteQuery({
    queryKey: queryKeys.history(path),
    queryFn: ({ pageParam }) => apiFetch<HistoryPage>(page(path, pageParam)),
    initialPageParam: "",
    getNextPageParam: (last) => last.next ?? undefined,
  });
}

export function useHistoryAttention() {
  return useQuery({
    queryKey: queryKeys.attention,
    queryFn: () =>
      apiFetch<{ items: AttentionItem[] }>("/api/history/attention"),
    refetchInterval: () => untilWindowSettles(Date.now()),
  });
}

export const useHideAction = () =>
  useApiMutation(
    (id: string) =>
      apiFetch(`/api/history/${encodeURIComponent(id)}/hide`, send("POST")),
    [["actions"]],
    true,
  );

export function useIncidentBoard() {
  return useQuery({
    queryKey: queryKeys.incidentBoard,
    queryFn: () => apiFetch<IncidentBoard>("/api/incidents/board"),
    refetchInterval: () => untilWindowSettles(Date.now()),
  });
}

export function useChangeHistory() {
  return useInfiniteQuery({
    queryKey: queryKeys.changeHistory,
    queryFn: ({ pageParam }) =>
      apiFetch<ChangeHistory>(page("/api/proposals/history", pageParam)),
    initialPageParam: "",
    getNextPageParam: (last) => last.next ?? undefined,
  });
}

export function useProposals() {
  return useQuery({
    queryKey: queryKeys.proposals,
    queryFn: () => apiFetch<{ proposals: ProposalRecord[] }>("/api/proposals"),
    refetchInterval: (query) =>
      query.state.data?.proposals.some((proposal) => proposal.status === "open")
        ? 10_000
        : 5 * MINUTE,
  });
}

export interface ProposalReply {
  id: string;
  status: "open" | "applied";
  missing?: string;
}

export const useOpenProposal = () =>
  useApiMutation(
    (body: { change: string; approval: Approval }) =>
      apiFetch<ProposalReply>("/api/proposals", send("POST", body)),
    DEVICE_QUERIES,
  );

export const useApproveProposal = () =>
  useApiMutation(
    ({ id, approval }: { id: string; approval: Approval }) =>
      apiFetch<ProposalReply>(
        `/api/proposals/${encodeURIComponent(id)}/approvals`,
        send("POST", { approval }),
      ),
    DEVICE_QUERIES,
  );

export const useCancelProposal = () =>
  useApiMutation(
    (id: string) =>
      apiFetch(`/api/proposals/${encodeURIComponent(id)}/cancel`, send("POST")),
    [queryKeys.proposals],
    true,
  );

export function useUsage() {
  return useQuery({
    queryKey: queryKeys.usage,
    queryFn: () => apiFetch<UsageResponse>("/api/usage"),
    refetchInterval: 15 * MINUTE,
    refetchOnWindowFocus: false,
  });
}

export const useSaveBudget = () =>
  useApiMutation(
    (budget: UsageShare) => apiFetch("/api/usage/budget", send("PUT", budget)),
    [queryKeys.usage],
  );
