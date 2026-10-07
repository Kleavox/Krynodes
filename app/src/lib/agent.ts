import { agentUpdatable, compareVersions } from "@krynodes/protocol/versions";

import type { NodeRecord } from "../types";

const ATTEMPT_MS = 15 * 60_000;
const SILENT_MS = 20 * 60_000;
export const UPDATE_ATTEMPTS = 3;
const VERSION = /^\d+\.\d+\.\d+$/u;

export type AgentState =
  "unknown" | "current" | "available" | "updating" | "failed" | "unsupported";

export function agentState(
  node: Pick<
    NodeRecord,
    | "agent_version"
    | "update_requested_version"
    | "update_requested_at"
    | "update_attempts"
  >,
  latest: string | null,
  now: number,
): AgentState {
  const version = node.agent_version;
  if (version && VERSION.test(version) && !agentUpdatable(version)) {
    return "unsupported";
  }
  const requested = node.update_requested_version;
  const passed =
    requested !== null &&
    version !== null &&
    VERSION.test(version) &&
    compareVersions(version, requested) >= 0;
  if (requested && !passed) {
    const elapsed = now - Date.parse(node.update_requested_at ?? "");
    const last = (node.update_attempts ?? 1) >= UPDATE_ATTEMPTS;
    return elapsed >= SILENT_MS || (last && elapsed >= ATTEMPT_MS)
      ? "failed"
      : "updating";
  }
  if (!latest || !version || !VERSION.test(version)) return "unknown";
  return compareVersions(version, latest) >= 0 ? "current" : "available";
}
