import {
  History,
  KeyRound,
  Network,
  Server,
  type LucideIcon,
} from "lucide-react";

interface Section {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

export const SECTIONS: readonly Section[] = [
  { to: "/", label: "Fleet", icon: Server, end: true },
  { to: "/network", label: "Network", icon: Network },
  { to: "/passkeys", label: "Passkeys", icon: KeyRound },
  { to: "/history", label: "History", icon: History },
];
