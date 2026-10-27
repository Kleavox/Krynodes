import { useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useEffect } from "react";

import { queryKeys } from "./query-client";

const PING_MS = 25_000;
const SETTLE_MS = 300;

const TOPICS: Record<string, QueryKey[]> = {
  actions: [queryKeys.services, ["actions"], queryKeys.network],
  services: [queryKeys.services, ["packages"], queryKeys.overview],
  checks: [queryKeys.overview, queryKeys.checkResults],
  nodes: [queryKeys.overview, queryKeys.recentMetrics, queryKeys.network],
};

export function keysFor(topics: string[]): QueryKey[] | null {
  if (topics.includes("all")) return null;
  const seen = new Set<string>();
  const keys: QueryKey[] = [];
  for (const topic of topics) {
    for (const key of TOPICS[topic] ?? []) {
      const id = JSON.stringify(key);
      if (seen.has(id)) continue;
      seen.add(id);
      keys.push(key);
    }
  }
  return keys;
}

export function retryDelay(attempt: number, random: number): number {
  return Math.round(Math.min(30_000, 1_000 * 2 ** attempt) * (0.5 + random));
}

export function liveUrl(location: { protocol: string; host: string }): string {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/live`;
}

export function useLiveUpdates(): void {
  const client = useQueryClient();
  useEffect(() => {
    let socket: WebSocket | null = null;
    let stopped = false;
    let attempt = 0;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let flush: ReturnType<typeof setTimeout> | undefined;
    let ping: ReturnType<typeof setInterval> | undefined;
    const pending = new Set<string>();

    const invalidate = (topics: string[]) => {
      for (const topic of topics) pending.add(topic);
      clearTimeout(flush);
      flush = setTimeout(() => {
        const keys = keysFor([...pending]);
        pending.clear();
        if (keys === null) {
          void client.invalidateQueries();
          return;
        }
        for (const queryKey of keys) {
          void client.invalidateQueries({ queryKey });
        }
      }, SETTLE_MS);
    };

    const open = () => {
      const current = new WebSocket(liveUrl(window.location));
      socket = current;
      current.onopen = () => {
        if (attempt > 0) invalidate(["all"]);
        attempt = 0;
        ping = setInterval(() => current.send("ping"), PING_MS);
      };
      current.onmessage = (event: MessageEvent) => {
        if (typeof event.data !== "string" || event.data === "pong") return;
        try {
          const message = JSON.parse(event.data) as {
            type?: unknown;
            topics?: unknown;
          };
          if (message.type === "changed" && Array.isArray(message.topics)) {
            invalidate(
              message.topics.filter(
                (topic): topic is string => typeof topic === "string",
              ),
            );
          }
        } catch {
          return;
        }
      };
      current.onclose = () => {
        clearInterval(ping);
        if (stopped) return;
        retry = setTimeout(open, retryDelay(attempt, Math.random()));
        attempt += 1;
      };
    };

    open();
    return () => {
      stopped = true;
      clearTimeout(retry);
      clearTimeout(flush);
      clearInterval(ping);
      socket?.close();
    };
  }, [client]);
}
