import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect } from "react";

import { queryKeys } from "./query-client";

const PING_MS = 25_000;
const SETTLE_MS = 300;
const OWN_QUERY = new Set(["stacks", "checks"]);

export interface Progress {
  id: string;
  line: string;
}

const listeners = new Set<(progress: Progress) => void>();

export function onProgress(listener: (progress: Progress) => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

const networkListeners = new Set<() => void>();

export function onNetworkChange(listener: () => void) {
  networkListeners.add(listener);
  return () => {
    networkListeners.delete(listener);
  };
}

export function retryDelay(attempt: number, random: number): number {
  return Math.round(Math.min(30_000, 1_000 * 2 ** attempt) * (0.5 + random));
}

export function liveUrl(location: { protocol: string; host: string }): string {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/live`;
}

export function watch(client: QueryClient, url: string): () => void {
  let socket: WebSocket | undefined;
  let stopped = false;
  let attempt = 0;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let flush: ReturnType<typeof setTimeout> | undefined;
  let ping: ReturnType<typeof setInterval> | undefined;

  const heard = new Set<string>();
  const refresh = (topics: unknown) => {
    const named = Array.isArray(topics)
      ? topics.filter((topic) => typeof topic === "string")
      : [];
    if (named.length === 0 || named.some((topic) => !OWN_QUERY.has(topic))) {
      heard.add("fleet");
    }
    for (const topic of named) heard.add(topic);
    clearTimeout(flush);
    flush = setTimeout(() => {
      const fleet = heard.has("fleet");
      if (fleet) {
        void client.invalidateQueries({ queryKey: queryKeys.fleet });
        void client.invalidateQueries({ queryKey: queryKeys.actions });
        void client.invalidateQueries({ queryKey: queryKeys.network });
      }
      if (fleet || heard.has("stacks")) {
        void client.invalidateQueries({ queryKey: queryKeys.stacks });
      }
      if (fleet || heard.has("checks")) {
        void client.invalidateQueries({ queryKey: queryKeys.checks });
      }
      heard.clear();
    }, SETTLE_MS);
  };

  const open = () => {
    const current = new WebSocket(url);
    socket = current;
    current.onopen = () => {
      if (attempt > 0) refresh(["fleet"]);
      attempt = 0;
      ping = setInterval(() => current.send("ping"), PING_MS);
    };
    current.onmessage = (event: MessageEvent) => {
      if (typeof event.data !== "string") return;
      let message:
        (Partial<Progress> & { type?: unknown; topics?: unknown }) | null;
      try {
        message = JSON.parse(event.data) as typeof message;
      } catch {
        return;
      }
      if (message?.type === "changed") {
        refresh(message.topics);
        if (
          Array.isArray(message.topics) &&
          message.topics.includes("network")
        ) {
          for (const listener of networkListeners) listener();
        }
      } else if (
        message?.type === "progress" &&
        typeof message.id === "string" &&
        typeof message.line === "string"
      ) {
        for (const listener of listeners) {
          listener({ id: message.id, line: message.line });
        }
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
}

export function useLiveUpdates(): void {
  const client = useQueryClient();
  useEffect(() => watch(client, liveUrl(window.location)), [client]);
}
