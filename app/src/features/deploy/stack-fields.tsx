import { Plus, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { summarize } from "@/lib/compose";
import { seal } from "@/lib/seal";
import { cn } from "@/lib/utils";

export type Access = "contained" | "full";

export interface SecretRow {
  name: string;
  value: string;
}

const ACCESS: { value: Access; label: string; detail: string }[] = [
  {
    value: "contained",
    label: "Contained",
    detail:
      "For projects you are trying out. Ready images only, ports on the server itself, at most 1 CPU, 1 GB and 512 processes per service.",
  },
  {
    value: "full",
    label: "Full access",
    detail:
      "For your own projects. Ports on the internet, the server's network and folders, devices and builds. It can do anything root can.",
  },
];

export function AccessChoice({
  value,
  onChange,
}: {
  value: Access;
  onChange: (value: Access) => void;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="Access"
      className="grid gap-2 sm:grid-cols-2"
    >
      {ACCESS.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={value === option.value}
          onClick={() => onChange(option.value)}
          className={cn(
            "rounded-md border px-3 py-2 text-left transition-colors",
            value === option.value
              ? "border-primary bg-primary/10"
              : "hover:bg-muted/50",
          )}
        >
          <span className="block text-sm font-medium">{option.label}</span>
          <span className="block text-xs text-muted-foreground">
            {option.detail}
          </span>
        </button>
      ))}
    </div>
  );
}

export function SecretsEditor({
  rows,
  onChange,
}: {
  rows: SecretRow[];
  onChange: (rows: SecretRow[]) => void;
}) {
  const update = (index: number, change: Partial<SecretRow>) =>
    onChange(
      rows.map((row, at) => (at === index ? { ...row, ...change } : row)),
    );
  return (
    <div className="space-y-2">
      {rows.map((row, index) => (
        <div key={index} className="flex gap-2">
          <Input
            aria-label={`Secret ${index + 1} name`}
            placeholder="SMTP_PASSWORD"
            value={row.name}
            autoComplete="off"
            className="font-mono text-xs"
            onChange={(event) => update(index, { name: event.target.value })}
          />
          <Input
            aria-label={`Secret ${index + 1} value`}
            type="password"
            value={row.value}
            autoComplete="off"
            className="font-mono text-xs"
            onChange={(event) => update(index, { value: event.target.value })}
          />
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Remove secret ${index + 1}`}
            onClick={() => onChange(rows.filter((_, at) => at !== index))}
          >
            <X aria-hidden="true" />
          </Button>
        </div>
      ))}
      <Button
        variant="outline"
        size="sm"
        onClick={() => onChange([...rows, { name: "", value: "" }])}
      >
        <Plus aria-hidden="true" />
        Add secret
      </Button>
      <p className="text-xs text-muted-foreground">
        Refer to them as ${"{NAME}"} in the compose file. They are locked to the
        server before they leave this page and never kept in History.
      </p>
    </div>
  );
}

const SECRET_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;

export function secretsProblem(rows: SecretRow[]): string | null {
  const named = rows.filter((row) => row.name.trim() || row.value);
  const seen = new Set<string>();
  for (const row of named) {
    const name = row.name.trim();
    if (!SECRET_NAME.test(name)) {
      return "Secret names hold letters, digits and _, not starting with a digit.";
    }
    if (seen.has(name)) return `The secret ${name} is listed twice.`;
    if (/['\n\r]/u.test(row.value)) {
      return `The secret ${name} cannot contain ' or a line break.`;
    }
    seen.add(name);
  }
  return null;
}

export async function sealSecrets(
  sealKey: string,
  rows: SecretRow[],
): Promise<string | undefined> {
  const named = rows.filter((row) => row.name.trim());
  if (named.length === 0) return undefined;
  return seal(
    sealKey,
    JSON.stringify(
      Object.fromEntries(named.map((row) => [row.name.trim(), row.value])),
    ),
  );
}

export function FullAccessSummary({ text }: { text: string }) {
  const summary = summarize(text);
  if (summary.error) return null;
  const lines = [
    summary.internet.length > 0 &&
      `Opens to the internet: ${summary.internet.join(", ")}`,
    summary.folders.length > 0 &&
      `Uses server folders: ${summary.folders.join(", ")}`,
    summary.hostNetwork.length > 0 &&
      `Uses the server's network: ${summary.hostNetwork.join(", ")}`,
    summary.devices.length > 0 && `Uses devices: ${summary.devices.join(", ")}`,
    summary.privileged.length > 0 &&
      `Runs privileged: ${summary.privileged.join(", ")}`,
    summary.builds.length > 0 &&
      `Builds on the server: ${summary.builds.join(", ")}`,
  ].filter(Boolean) as string[];
  const dns = summary.internet.some((port) => port.startsWith("53/"));
  return (
    <div className="space-y-2 rounded-md border border-warning/40 bg-warning/5 p-3 text-xs">
      <p className="font-medium">What this stack opens</p>
      {lines.length === 0 ? (
        <p className="text-muted-foreground">
          Nothing beyond its own containers.
        </p>
      ) : (
        <ul className="list-disc space-y-1 pl-4 font-mono">
          {lines.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
      {summary.internet.length > 0 && (
        <p className="text-muted-foreground">
          Docker opens these ports past ufw, so a firewall does not close them.
        </p>
      )}
      {dns && (
        <p className="text-muted-foreground">
          Port 53 open to everyone makes an open resolver that others can abuse.
          Limit it with AdGuard&rsquo;s Allowed clients, or use DNS-over-TLS.
        </p>
      )}
    </div>
  );
}
