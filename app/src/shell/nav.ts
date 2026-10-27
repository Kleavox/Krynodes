import {
  Activity,
  Boxes,
  History,
  Network,
  Server,
  type LucideIcon,
} from "lucide-react";

import { isPending } from "@/lib/services";
import type { Overview, ServicesResponse } from "@/types";

interface Section {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

export const SECTIONS: readonly Section[] = [
  { to: "/", label: "Fleet", icon: Server, end: true },
  { to: "/services", label: "Services", icon: Boxes },
  { to: "/network", label: "Network", icon: Network },
  { to: "/checks", label: "Checks", icon: Activity },
];

export const PAGES: readonly Section[] = [
  ...SECTIONS,
  { to: "/history", label: "History", icon: History },
];

export const alsoActive = (to: string, pathname: string) =>
  to === "/checks" && pathname.startsWith("/incidents/");

export function navCounts(
  overview: Overview | undefined,
  services: ServicesResponse | undefined,
  networkProblems = 0,
  tailnetAlarms = 0,
): Record<string, number> {
  return {
    "/checks":
      overview?.incidents.filter((incident) => incident.status === "OPEN")
        .length ?? 0,
    "/services": services?.actions.filter(isPending).length ?? 0,
    "/network": tailnetAlarms > 0 ? tailnetAlarms : networkProblems,
  };
}

export const networkWarns = (tailnetAlarms = 0) => tailnetAlarms === 0;
