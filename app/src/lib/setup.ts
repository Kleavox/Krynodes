import type { Setup } from "@krynodes/protocol";

import type { NodeRecord } from "../types";
import { parseTimestamp, SETTING_UP_MS } from "./format";

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
}

type SetupNode = Pick<
  NodeRecord,
  "setup" | "enrolled_at" | "last_seen_at" | "warnings"
>;

export function setupView(node: SetupNode, now: number): SetupView | null {
  if (node.setup?.stopped) {
    return { label: LABELS[node.setup.phase], stopped: true };
  }
  if (
    node.setup ||
    (node.enrolled_at &&
      !node.last_seen_at &&
      now - parseTimestamp(node.enrolled_at) < SETTING_UP_MS)
  ) {
    return { label: "Setting Up", stopped: false };
  }
  return null;
}

export function opensServer(node: SetupNode, now: number): boolean {
  const view = setupView(node, now);
  return !view || view.stopped || (node.warnings?.length ?? 0) > 0;
}
