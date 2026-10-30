import { Plus, X } from "lucide-react";
import { useState } from "react";

import { SmallLabel } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useBridges } from "@/features/nodes/use-bridges";
import { useNetwork, useServices } from "@/lib/api";
import {
  KIND_TAG,
  networkBoxes,
  stackNetworkArgs,
  type NetworkBox,
} from "@/lib/bridges";
import {
  publishedPorts,
  publishedRanges,
  usePrivateAddress,
} from "@/lib/compose";
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
      "For apps that stay isolated. Ready images only, ports on the server itself, at most 1 CPU, 1 GB and 512 processes per service.",
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
        placeholder="number/tcp"
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
          "Ports on this server the stack may open, written as number/tcp, separated by commas. Ports other stacks publish count too. Leave it empty to keep the server closed to it."}
      </p>
    </div>
  );
}

export function FullAccessSummary({
  nodeId,
  text,
  member,
  onText,
}: {
  nodeId: string;
  text: string;
  member: Member | null;
  onText: (text: string) => void;
}) {
  const security = useServices().data?.nodes.find(
    (node) => node.id === nodeId,
  )?.security;
  const wall = security?.firewall;
  const box = opensBox(
    text,
    member,
    wall?.closed ? wall.open : null,
    security?.confinement?.system === "selinux" &&
      security.confinement.docker === true,
  );
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
  const [serving, setServing] = useState<{
    nodeId: string;
    rows: ServeRow[];
  } | null>(null);
  const [typed, setTyped] = useState<{ nodeId: string; text: string } | null>(
    null,
  );
  const ports = publishedPorts(text);
  const rows = ports.map(
    ({ port }) =>
      (serving?.nodeId === nodeId
        ? serving.rows.find((row) => row.port === port)
        : undefined) ?? readServes(start?.serves, [port])[0]!,
  );
  const places =
    (typed?.nodeId === nodeId ? typed.text : null) ??
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
    ranges: publishedRanges(text),
    rows,
    onRows: (next: ServeRow[]) => setServing({ nodeId, rows: next }),
    places,
    onPlaces: (next: string) => setTyped({ nodeId, text: next }),
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
  const { member, others, ports, ranges, rows, onRows, places, onPlaces } =
    network;
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
      {ranges.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Port ranges stay on This Server Only:{" "}
          <span className="font-mono">
            {ranges.map((range) => range.port).join(", ")}
          </span>
        </p>
      )}
      {rows.length === 0 ? (
        ranges.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No ports in the compose file
          </p>
        )
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

export function useNetworkBoxes(
  node: { id: string; name: string },
  text: string,
  project: string,
  access: Access,
) {
  const { server } = useBridges(node);
  const [offers, setOffers] = useState<Record<string, string>>({});
  const [ticks, setTicks] = useState<Record<string, boolean>>({});
  const boxes = networkBoxes(text, server, project, access);
  const { args, problem } = stackNetworkArgs(boxes, offers, ticks);
  return {
    boxes,
    offers,
    onOffer: (key: string, value: string) =>
      setOffers({ ...offers, [key]: value }),
    ticks,
    onTick: (key: string, value: boolean) =>
      setTicks({ ...ticks, [key]: value }),
    args,
    problem,
  };
}

function Box({
  box,
  offers,
  onOffer,
  ticks,
  onTick,
}: {
  box: NetworkBox;
  offers: Record<string, string>;
  onOffer: (key: string, value: string) => void;
  ticks: Record<string, boolean>;
  onTick: (key: string, value: boolean) => void;
}) {
  if (box.refusal) {
    return (
      <p className="rounded-md border border-destructive/40 p-3 text-xs text-destructive">
        {box.refusal}
      </p>
    );
  }
  return (
    <div className="space-y-3 rounded-md border p-3 text-sm">
      <div>
        <p className="flex flex-wrap items-center gap-2 font-medium">
          <span className="font-mono">{box.name}</span>
          {box.kind && <SmallLabel>{KIND_TAG[box.kind]}</SmallLabel>}
          {box.guest && <SmallLabel>guest</SmallLabel>}
        </p>
        <p className="text-xs text-muted-foreground">{box.address}</p>
      </div>
      <div className="space-y-1.5">
        <p className="text-xs font-medium">Offers on This Network</p>
        {box.offers.map((offer) => {
          const key = `${box.name}/${offer.service}`;
          return (
            <div
              key={key}
              className="grid grid-cols-[minmax(64px,auto)_minmax(0,1fr)] items-center gap-2"
            >
              <label
                htmlFor={`offer-${key}`}
                className="truncate font-mono text-xs"
              >
                {offer.service}
              </label>
              <Input
                id={`offer-${key}`}
                className="font-mono"
                placeholder="number/tcp"
                autoComplete="off"
                spellCheck={false}
                value={offers[key] ?? offer.value}
                onChange={(event) => onOffer(key, event.target.value)}
              />
            </div>
          );
        })}
        <p className="text-xs text-muted-foreground">
          Ports other members may reach on it. Leave it empty to offer nothing.
        </p>
      </div>
      {!box.guest && (
        <fieldset className="space-y-1.5">
          <legend className="text-xs font-medium">Reach Stack On</legend>
          {box.reach.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No other stack offers a port on {box.name} yet.
            </p>
          ) : (
            box.reach.map((each) => {
              const key = `${box.name}/${each.entry}`;
              return (
                <label key={key} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    className="size-4 accent-primary"
                    checked={ticks[key] ?? each.ticked}
                    onChange={(event) => onTick(key, event.target.checked)}
                  />
                  <span className="min-w-0 truncate font-mono text-xs">
                    {each.entry}
                  </span>
                  {each.guest && <SmallLabel>guest</SmallLabel>}
                  {each.gone && (
                    <span className="text-xs text-muted-foreground">
                      Not offered now
                    </span>
                  )}
                </label>
              );
            })
          )}
          <p className="text-xs text-muted-foreground">
            Reach a ticked one by that name, such as{" "}
            {box.reach[0]?.entry.replace(/\/(tcp|udp)$/u, "") ?? "name:port"}.
            Everything else on {box.name} stays closed.
          </p>
        </fieldset>
      )}
    </div>
  );
}

export function NetworkBoxes({
  network,
}: {
  network: ReturnType<typeof useNetworkBoxes>;
}) {
  if (network.boxes.length === 0) return null;
  return (
    <div className="space-y-2">
      {network.boxes.map((box) => (
        <Box
          key={box.name}
          box={box}
          offers={network.offers}
          onOffer={network.onOffer}
          ticks={network.ticks}
          onTick={network.onTick}
        />
      ))}
      {network.problem && !network.boxes.some((box) => box.refusal) && (
        <p className="text-xs text-destructive">{network.problem}</p>
      )}
    </div>
  );
}
