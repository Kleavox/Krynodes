import { ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";

import { useServices } from "@/lib/api";
import { worst } from "@/lib/security";
import { cn } from "@/lib/utils";

const LOOK = {
  serious: {
    Icon: ShieldX,
    label: "Security: serious findings",
    tone: "text-destructive",
  },
  warning: {
    Icon: ShieldAlert,
    label: "Security: warnings",
    tone: "text-warning",
  },
  ok: {
    Icon: ShieldCheck,
    label: "Security: no warnings",
    tone: "text-success",
  },
};

export function SecurityMark({ nodeId }: { nodeId: string }) {
  const services = useServices();
  const report = services.data?.nodes.find(
    (node) => node.id === nodeId,
  )?.security;
  const level = worst(report);
  if (level === null) return null;
  const { Icon, label, tone } = LOOK[level];
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={cn("relative z-10 inline-flex shrink-0", tone)}
    >
      <Icon aria-hidden="true" className="size-3.5" />
    </span>
  );
}
