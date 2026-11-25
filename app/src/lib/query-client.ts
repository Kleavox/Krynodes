import { QueryCache, QueryClient } from "@tanstack/react-query";

import { isSessionLost } from "./errors";

export const queryKeys = {
  session: ["session"],
  fleet: ["fleet"],
  devices: ["devices"],
  actions: ["actions"],
  network: ["network"],
  stacks: ["stacks"],
  checks: ["checks"],
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
