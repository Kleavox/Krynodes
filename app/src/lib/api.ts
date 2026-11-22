import { useQuery } from "@tanstack/react-query";

import type { Device, SessionResponse } from "../types";
import { apiFetch } from "./http";
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
