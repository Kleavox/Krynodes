import type { Setup } from "@krynodes/protocol";

import type { NodeRecord } from "../types";
import { nodeState, parseTimestamp } from "./format";

const LABELS: Record<Setup["phase"], string> = {
  admin: "Adding Admin User",
  upgrade: "Updating Packages",
  protections: "Turning On Protections",
  selinux: "Turning On SELinux",
  apparmor: "Turning On AppArmor",
  docker: "Installing Docker",
  network: "Preparing Private Network",
  restart: "Restarting",
};

export interface SetupView {
  label: string;
  stopped: boolean;
  failed: boolean;
  step: string | null;
}

type SetupNode = Pick<
  NodeRecord,
  | "setup"
  | "enrolled_at"
  | "last_seen_at"
  | "warnings"
  | "disabled_at"
  | "interval_seconds"
>;

const SETTING_UP_MS = 60 * 60_000;

export function setupView(node: SetupNode, now: number): SetupView | null {
  const step = node.setup ? LABELS[node.setup.phase] : null;
  if (node.setup?.stopped) {
    return {
      label: LABELS[node.setup.phase],
      stopped: true,
      failed: false,
      step,
    };
  }
  if (node.setup && !node.setup.failed) {
    if (node.last_seen_at && nodeState(node, now) === "offline") return null;
    return { label: "Setting Up", stopped: false, failed: false, step };
  }
  if (node.setup || (node.enrolled_at && !node.last_seen_at)) {
    const failed =
      !!node.setup || now - parseTimestamp(node.enrolled_at!) >= SETTING_UP_MS;
    return {
      label: failed ? "Setup Failed" : "Setting Up",
      stopped: false,
      failed,
      step,
    };
  }
  return null;
}

export function opensServer(node: SetupNode, now: number): boolean {
  const view = setupView(node, now);
  return !view || view.stopped || (node.warnings?.length ?? 0) > 0;
}
