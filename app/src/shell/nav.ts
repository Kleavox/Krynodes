import { History, KeyRound, Server, type LucideIcon } from "lucide-react";

interface Section {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

export const SECTIONS: readonly Section[] = [
  { to: "/", label: "Fleet", icon: Server, end: true },
  { to: "/passkeys", label: "Passkeys", icon: KeyRound },
  { to: "/history", label: "History", icon: History },
];
