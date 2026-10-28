import { KeyRound } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { Line } from "@/lib/packages";
import { cn } from "@/lib/utils";

export const SHEET =
  "max-h-[90dvh] overflow-y-auto max-sm:top-auto max-sm:bottom-0 max-sm:max-w-full max-sm:translate-y-0 max-sm:rounded-b-none";

export function SignButton({
  label,
  pending,
  disabled = false,
  destructive = false,
  onClick,
}: {
  label: string;
  pending: boolean;
  disabled?: boolean;
  destructive?: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      variant={destructive ? "destructive" : "default"}
      disabled={disabled || pending}
      onClick={onClick}
    >
      {!pending && <KeyRound aria-hidden="true" />}
      {pending ? "Waiting for the Passkey…" : label}
    </Button>
  );
}

export function Said({ text }: { text: string | null }) {
  return text ? (
    <p role="alert" className="text-sm text-destructive">
      {text}
    </p>
  ) : null;
}

export type PackagesDialog =
  | { kind: "install"; name?: string }
  | { kind: "repo" }
  | { kind: "upgrade" }
  | { kind: "remove"; name: string }
  | { kind: "hold"; name: string; held: boolean }
  | { kind: "droprepo"; name: string; label: string }
  | { kind: "job"; id: string };

const TONE: Record<Line["mark"], string> = {
  "+": "text-success",
  "!": "text-warning",
  "✓": "text-success",
  "−": "text-destructive",
  "↑": "text-primary",
  "·": "text-muted-foreground",
  "✕": "text-destructive",
};

export function Lines({
  lines,
  className,
}: {
  lines: Line[];
  className?: string;
}) {
  return (
    <ul className={cn("space-y-2 text-sm", className)}>
      {lines.map((line, index) => (
        <li key={`${index}:${line.title}`} className="flex gap-2.5">
          <span
            aria-hidden="true"
            className={cn(
              "w-3 shrink-0 text-center font-mono",
              TONE[line.mark],
            )}
          >
            {line.mark}
          </span>
          <span className="min-w-0">
            <span className="block break-words">{line.title}</span>
            {line.detail.map((detail) => (
              <span
                key={detail}
                className="block text-xs break-words text-muted-foreground"
              >
                {detail}
              </span>
            ))}
          </span>
        </li>
      ))}
    </ul>
  );
}
