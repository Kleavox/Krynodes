import { useQuery, useQueryClient } from "@tanstack/react-query";

import { networkApi } from "@/lib/api";
import { queryKeys } from "@/lib/query-client";

export function useNetworkView() {
  return useQuery({
    queryKey: queryKeys.network,
    queryFn: networkApi.network,
  });
}

export function useCurrentDocument(enabled = true) {
  return useQuery({
    queryKey: [...queryKeys.network, "current"],
    queryFn: networkApi.current,
    enabled,
  });
}

export function useNetworkChanges() {
  return useQuery({
    queryKey: [...queryKeys.network, "changes"],
    queryFn: networkApi.changes,
  });
}

export function useRefreshNetwork() {
  const client = useQueryClient();
  return () => {
    void client.invalidateQueries({ queryKey: queryKeys.network });
    void client.invalidateQueries({ queryKey: queryKeys.fleet });
  };
}
