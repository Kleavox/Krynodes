import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/lib/http";
import { queryKeys } from "@/lib/query-client";
import type { Enrollment, FleetNode } from "@/types";

export function useFleet() {
  return useQuery({
    queryKey: queryKeys.fleet,
    queryFn: () => apiFetch<FleetNode[]>("/api/nodes"),
  });
}

export function useDeleteNode(
  id: string,
  onDone: () => void,
  path = `/api/nodes/${id}`,
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => apiFetch(path, { method: "DELETE" }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.fleet });
      onDone();
    },
  });
}

export function useCreateEnrollment() {
  return useMutation({
    mutationFn: (body: { name: string; trust: string[] }) =>
      apiFetch<Enrollment>("/api/enrollments", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  });
}

export function useEnrollment(id: string | undefined) {
  return useQuery({
    queryKey: [...queryKeys.fleet, "enrollment", id],
    queryFn: () =>
      apiFetch<{ nodeId: string | null }>(`/api/enrollments/${id}`),
    enabled: id !== undefined,
  });
}
