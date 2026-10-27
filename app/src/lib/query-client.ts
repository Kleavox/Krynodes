import { QueryCache, QueryClient } from "@tanstack/react-query";

import type { MetricRange } from "../types";
import { isSessionLost } from "./errors";

export const queryKeys = {
  session: ["session"],
  overview: ["overview"],
  recentMetrics: ["metrics", "recent"],
  nodeMetrics: (id: string, range: MetricRange) => [
    "metrics",
    "node",
    id,
    range,
  ],
  checkResults: ["checks", "results"],
  checkDismissals: ["checks", "dismissals"],
  services: ["services"],
  privateRanges: ["settings", "private-ranges"],
  enrollDefaults: ["settings", "enroll-defaults"],
  quarantineSettings: ["settings", "quarantine"],
  quarantine: (id: string) => ["quarantine", id],
  nodeActions: (id: string) => ["actions", "node", id],
  action: (id: string | null) => ["actions", "one", id],
  history: (path: string) => ["actions", "history", path],
  attention: ["actions", "attention"],
  incident: (id: string) => ["incidents", id],
  incidentBoard: ["incidents", "board"],
  enrollment: (id: string) => ["enrollments", id],
  devices: ["devices"],
  proposals: ["proposals"],
  changeHistory: ["proposals", "history"],
  usage: ["usage"],
  packages: (id: string) => ["packages", "node", id],
  packageNames: ["packages", "names"],
  network: ["network"],
  networkNext: (nodes: string[], range?: string) => [
    "network",
    "next",
    nodes.join(","),
    range ?? null,
  ],
} as const;

export function createQueryClient(): QueryClient {
  const client: QueryClient = new QueryClient({
    defaultOptions: { queries: { staleTime: 10_000 } },
    queryCache: new QueryCache({
      onError: (error, query) => {
        if (query.queryKey[0] !== "session" && isSessionLost(error)) {
          void client.invalidateQueries({ queryKey: queryKeys.session });
        }
      },
    }),
  });
  return client;
}

export function keepWhileSameNode<T>(id: string) {
  return (
    previous: T | undefined,
    query: { queryKey: readonly unknown[] } | undefined,
  ) => (query?.queryKey[2] === id ? previous : undefined);
}
