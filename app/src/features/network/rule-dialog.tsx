import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Said, SignButton } from "@/features/packages/lines";
import { addRuleEffect, ruleForm } from "@/lib/tailscale";

import type { Changed } from "./changed-rule-dialog";
import { useSaveRules, useTailnet } from "./use-tailscale";

function Choose({
  id,
  label,
  value,
  choices,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  choices: { value: string; label: string }[];
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid grid-cols-[64px_minmax(0,1fr)] items-center gap-3">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value} onValueChange={onChange} disabled={disabled}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {choices.map((choice) => (
            <SelectItem key={choice.value} value={choice.value}>
              {choice.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export function RuleDialog({
  index,
  onChanged,
  onClose,
}: {
  index: number | null;
  onChanged: (changed: Changed) => void;
  onClose: () => void;
}) {
  const { data, listeners } = useTailnet();
  const save = useSaveRules();
  const connected = data?.connected;
  const editing = (() => {
    const rule = index === null ? undefined : connected?.rules[index];
    return rule && "ports" in rule ? rule : null;
  })();
  const on = (data?.servers ?? []).filter((server) => server.report);
  const [from, setFrom] = useState<string>(editing?.from ?? "devices");
  const [to, setTo] = useState<string>(
    editing?.to ?? on[0]?.nodeId ?? "servers",
  );
  const [ticked, setTicked] = useState<string[]>(editing?.ports ?? []);
  const [other, setOther] = useState("");
  if (!connected) return null;

  const { options, allowed, rule, problem, readable, ready } = ruleForm({
    connected,
    index,
    servers: data.servers,
    listeners,
    from,
    to,
    ticked,
    other,
  });
  const label = index === null ? "Add Rule" : "Edit Rule";
  const toggle = (port: string) =>
    setTicked(
      ticked.includes(port)
        ? ticked.filter((each) => each !== port)
        : [...ticked, port],
    );
  const places = on.map((server) => ({
    value: server.nodeId,
    label: server.name,
  }));

  return (
    <Dialog open onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-[512px]">
        <DialogHeader>
          <DialogTitle>{label}</DialogTitle>
          <DialogDescription>
            Who may open a connection to a server over Tailscale.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Choose
            id="rule-from"
            label="From"
            value={from}
            disabled={save.isPending}
            onChange={setFrom}
            choices={[
              { value: "devices", label: "Your Devices" },
              ...(on.length > 1
                ? [{ value: "servers", label: "All Servers" }]
                : []),
              ...places,
            ]}
          />
          <Choose
            id="rule-to"
            label="To"
            value={to}
            disabled={save.isPending}
            onChange={setTo}
            choices={[
              ...(on.length > 1
                ? [{ value: "servers", label: "All Servers" }]
                : []),
              ...places,
            ]}
          />
        </div>
        <fieldset className="space-y-2">
          <legend className="mb-2 text-sm font-medium">Ports</legend>
          <ul className="divide-y rounded-md border">
            {options.map((entry) => (
              <li key={entry.port}>
                <label className="flex items-center gap-3 px-3 py-2 text-sm">
                  <input
                    type="checkbox"
                    className="size-4 shrink-0 accent-primary"
                    checked={ticked.includes(entry.port)}
                    disabled={save.isPending}
                    onChange={() => toggle(entry.port)}
                  />
                  <span className="flex-1 font-mono text-xs">{entry.port}</span>
                  <span className="text-xs text-muted-foreground">
                    {entry.process ?? "--"}
                  </span>
                </label>
              </li>
            ))}
            {allowed.length > 0 && (
              <li className="flex items-center gap-3 px-3 py-2 text-sm text-muted-foreground">
                <span aria-hidden="true" className="w-4 text-center">
                  ✓
                </span>
                <span className="flex-1 font-mono text-xs">
                  {allowed.join(" · ")}
                </span>
                <span className="text-xs">Allowed already</span>
              </li>
            )}
            {options.length === 0 && allowed.length === 0 && (
              <li className="px-3 py-2 text-xs text-muted-foreground">
                Nothing listens there that Krynodes knows of. Add a port below.
              </li>
            )}
          </ul>
          <div className="grid grid-cols-[96px_minmax(0,1fr)] items-center gap-3">
            <Label htmlFor="rule-other">Other Port</Label>
            <Input
              id="rule-other"
              value={other}
              placeholder="9100/tcp"
              autoComplete="off"
              disabled={save.isPending}
              aria-invalid={!readable}
              onChange={(event) => setOther(event.target.value)}
            />
          </div>
        </fieldset>
        {ready && (
          <p className="text-sm">{addRuleEffect(rule, data.servers)}</p>
        )}
        <Said text={problem ?? save.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" disabled={save.isPending}>
              Cancel
            </Button>
          </DialogClose>
          <SignButton
            label="Save Rule"
            pending={save.isPending}
            disabled={!ready}
            onClick={() => {
              const wanted =
                index === null
                  ? [...connected.rules, rule]
                  : connected.rules.map((each, at) =>
                      at === index ? rule : each,
                    );
              save.mutate(
                {
                  rules: wanted,
                  expected: connected.block ?? "",
                  tag: false,
                  label,
                },
                {
                  onSuccess: (saved) =>
                    saved.saved
                      ? onClose()
                      : onChanged({
                          wanted,
                          block: saved.block,
                          now: saved.now,
                          tag: false,
                          label,
                        }),
                },
              );
            }}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
