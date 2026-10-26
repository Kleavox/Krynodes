import { Plus, X } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useNetwork } from "@/lib/api";
import { publishedPorts, usePrivateAddress } from "@/lib/compose";
import {
  inside,
  opensBox,
  parsePlaces,
  placeText,
  readServes,
  servesArg,
  servesProblem,
  type Serve,
  type ServeChoice,
  type ServeRow,
} from "@/lib/network";
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
    label: "Full Access",
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
        Add Secret
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

export interface HeldSecret {
  name: string;
  value: string | null;
}

export function heldProblem(
  held: HeldSecret[],
  added: SecretRow[],
): string | null {
  return secretsProblem([
    ...held.map((row) => ({ name: row.name, value: row.value ?? "" })),
    ...added,
  ]);
}

export function secretChange(
  held: HeldSecret[],
  added: SecretRow[],
  before: string[],
): { keep: string[]; set: Record<string, string> } | undefined {
  const named = added.filter((row) => row.name.trim());
  if (
    named.length === 0 &&
    held.length === before.length &&
    held.every((row) => row.value === null)
  ) {
    return undefined;
  }
  return {
    keep: held.filter((row) => row.value === null).map((row) => row.name),
    set: Object.fromEntries([
      ...held.flatMap((row) =>
        row.value === null ? [] : [[row.name, row.value]],
      ),
      ...named.map((row) => [row.name.trim(), row.value]),
    ]),
  };
}

export function HeldSecrets({
  rows,
  onChange,
}: {
  rows: HeldSecret[];
  onChange: (rows: HeldSecret[]) => void;
}) {
  const update = (index: number, value: string | null) =>
    onChange(rows.map((row, at) => (at === index ? { ...row, value } : row)));
  return (
    <ul className="space-y-2">
      {rows.map((row, index) => (
        <li key={row.name} className="flex items-center gap-2">
          <span className="w-2/5 truncate font-mono text-xs">{row.name}</span>
          {row.value === null ? (
            <span
              aria-label={`${row.name} is kept`}
              className="flex-1 font-mono text-xs text-muted-foreground"
            >
              ••••••
            </span>
          ) : (
            <Input
              aria-label={`New value for ${row.name}`}
              type="password"
              value={row.value}
              autoFocus
              autoComplete="off"
              className="flex-1 font-mono text-xs"
              onChange={(event) => update(index, event.target.value)}
            />
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => update(index, row.value === null ? "" : null)}
          >
            {row.value === null ? "Replace" : "Keep"}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Remove ${row.name}`}
            onClick={() => onChange(rows.filter((_, at) => at !== index))}
          >
            <X aria-hidden="true" />
          </Button>
        </li>
      ))}
    </ul>
  );
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

export function ReachField({
  value,
  onChange,
  problem,
}: {
  value: string;
  onChange: (value: string) => void;
  problem: string | null;
}) {
  return (
    <div className="space-y-1.5">
      <label htmlFor="stack-reach" className="text-sm font-medium">
        Reach This Server On
      </label>
      <Input
        id="stack-reach"
        value={value}
        placeholder="3000/tcp"
        autoComplete="off"
        spellCheck={false}
        className="font-mono"
        aria-invalid={problem !== null}
        aria-describedby="stack-reach-hint"
        onChange={(event) => onChange(event.target.value)}
      />
      <p
        id="stack-reach-hint"
        className={cn(
          "text-xs",
          problem ? "text-destructive" : "text-muted-foreground",
        )}
      >
        {problem ??
          "Ports on this server the stack may open, such as 3000/tcp, separated by commas. Leave it empty to keep the server closed to it."}
      </p>
    </div>
  );
}

export function FullAccessSummary({
  text,
  member,
  onText,
}: {
  text: string;
  member: Member | null;
  onText: (text: string) => void;
}) {
  const box = opensBox(text, member);
  if (!box) return null;
  return (
    <div
      className={cn(
        "space-y-2 rounded-md border p-3 text-xs",
        box.warn && "border-warning/40 bg-warning/5",
      )}
    >
      <p className="font-medium">What This Stack Opens</p>
      {box.lines.length === 0 ? (
        <p className="text-muted-foreground">
          Nothing beyond its own containers.
        </p>
      ) : (
        <ul className="list-disc space-y-1 pl-4 font-mono">
          {box.lines.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
      {box.notes.map((note) => (
        <p key={note} className="text-muted-foreground">
          {note}
        </p>
      ))}
      {box.offer && (
        <div className="flex flex-wrap items-center gap-2">
          <p className="min-w-0 flex-1">{box.offer}</p>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onText(usePrivateAddress(text))}
          >
            Use Private Address
          </Button>
        </div>
      )}
    </div>
  );
}

type Member = { nodeId: string; name: string; address: string | null };

const CHOICES: { value: ServeChoice; label: string }[] = [
  { value: "self", label: "This Server Only" },
  { value: "all", label: "All Servers" },
  { value: "chosen", label: "Chosen Servers" },
];

export function useStackNetwork(
  nodeId: string,
  text: string,
  start?: { serves?: Serve[]; reaches?: string[] },
) {
  const view = useNetwork().data;
  const members = view ? inside(view) : [];
  const member = members.find((entry) => entry.nodeId === nodeId) ?? null;
  const [serving, setServing] = useState<ServeRow[] | null>(null);
  const [typed, setTyped] = useState<string | null>(null);
  const ports = publishedPorts(text);
  const rows = ports.map(
    ({ port }) =>
      serving?.find((row) => row.port === port) ??
      readServes(start?.serves, [port])[0]!,
  );
  const places =
    typed ??
    (start?.reaches ?? [])
      .map((place) => (view ? placeText(view, place) : place))
      .join(", ");
  const parsed =
    view && member
      ? parsePlaces(places, view, nodeId)
      : { places: [], problem: null };
  return {
    member,
    others: members.filter((entry) => entry.nodeId !== nodeId),
    ports,
    rows,
    onRows: setServing,
    places,
    onPlaces: setTyped,
    placesProblem: parsed.problem,
    servesProblem: servesProblem(rows),
    args: { serves: servesArg(rows), reaches: parsed.places.join(",") },
  };
}

export function NetworkSection({
  network,
}: {
  network: ReturnType<typeof useStackNetwork>;
}) {
  const { member, others, ports, rows, onRows, places, onPlaces } = network;
  if (!member) return null;
  const update = (index: number, change: Partial<ServeRow>) =>
    onRows(rows.map((row, at) => (at === index ? { ...row, ...change } : row)));
  const problem = network.placesProblem;
  return (
    <div className="space-y-3 rounded-md border p-3">
      <div className="space-y-0.5">
        <p className="text-sm font-medium">Private Network</p>
        <p className="text-xs text-muted-foreground">
          {member.name} is {member.address ?? "--"} on the private network.
        </p>
      </div>
      {rows.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No ports in the compose file
        </p>
      ) : (
        <ul className="space-y-3">
          {rows.map((row, index) => (
            <li key={row.port} className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs">{row.port}</span>
                <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
                  {ports[index]?.service}
                </span>
                <Select
                  value={row.choice}
                  onValueChange={(value) =>
                    update(index, { choice: value as ServeChoice })
                  }
                >
                  <SelectTrigger
                    aria-label={`Who may reach ${row.port}`}
                    className="w-44"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CHOICES.map((choice) => (
                      <SelectItem key={choice.value} value={choice.value}>
                        {choice.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {row.choice === "chosen" && (
                <fieldset className="space-y-1.5 rounded-md bg-muted/40 px-3 py-2">
                  <legend className="sr-only">Who may reach {row.port}</legend>
                  <p className="text-xs text-muted-foreground">
                    Who may reach it
                  </p>
                  {others.map((other) => (
                    <label
                      key={other.nodeId}
                      className="flex items-center gap-2 text-sm"
                    >
                      <input
                        type="checkbox"
                        className="size-4 accent-primary"
                        checked={row.to.includes(other.nodeId)}
                        onChange={() =>
                          update(index, {
                            to: row.to.includes(other.nodeId)
                              ? row.to.filter((id) => id !== other.nodeId)
                              : [...row.to, other.nodeId],
                          })
                        }
                      />
                      {other.name}
                    </label>
                  ))}
                </fieldset>
              )}
            </li>
          ))}
        </ul>
      )}
      {network.servesProblem && (
        <p className="text-xs text-destructive">{network.servesProblem}</p>
      )}
      <div className="space-y-1.5">
        <label htmlFor="stack-places" className="text-sm font-medium">
          Reach Other Servers On
        </label>
        <Input
          id="stack-places"
          value={places}
          placeholder={`${others[0]?.name ?? "vps-1"}:5432/tcp`}
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
          aria-invalid={problem !== null}
          aria-describedby="stack-places-hint"
          onChange={(event) => onPlaces(event.target.value)}
        />
        <p
          id="stack-places-hint"
          className={cn(
            "text-xs",
            problem ? "text-destructive" : "text-muted-foreground",
          )}
        >
          {problem ?? (
            <>
              <span className="max-sm:hidden">
                Places on other servers its containers may connect to, separated
                by commas.{" "}
              </span>
              Leave it empty and it reaches none.
              <span className="max-sm:hidden">
                {" "}
                Replies to connections that came in always pass.
              </span>
            </>
          )}
        </p>
      </div>
    </div>
  );
}
