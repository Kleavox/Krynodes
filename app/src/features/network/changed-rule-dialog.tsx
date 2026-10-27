import type { TailnetRule } from "@krynodes/protocol";
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
import { Said, SignButton } from "@/features/packages/lines";
import { clockTime } from "@/lib/format";
import { brokenLines, changedLines, keepChange } from "@/lib/tailscale";
import { cn } from "@/lib/utils";

import { useSaveRules, useTailnet } from "./use-tailscale";

export interface Changed {
  wanted: TailnetRule[];
  block: string;
  now: string[];
  tag: boolean;
  label: string;
}

const CHOICES = [
  {
    value: "keep",
    title: "Keep the Change",
    note: "Krynodes takes it as its own rule, then adds yours",
  },
  {
    value: "back",
    title: "Put Back Krynodes'",
    note: "Krynodes writes its own rules again, then adds yours",
  },
] as const;

export function ChangedRuleDialog({
  changed,
  onChanged,
  onClose,
}: {
  changed: Changed;
  onChanged: (changed: Changed) => void;
  onClose: () => void;
}) {
  const { data } = useTailnet();
  const save = useSaveRules();
  const [choice, setChoice] = useState<"keep" | "back">("keep");
  const connected = data?.connected;
  if (!connected) return null;
  const lines = changedLines(connected, changed.now, data.servers);
  const broken = brokenLines(connected, changed.now).length > 0;
  const chosen = broken ? "back" : choice;

  return (
    <Dialog open onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-[512px]">
        <DialogHeader>
          <DialogTitle>A Krynodes rule was changed</DialogTitle>
          <DialogDescription>
            Nothing was saved.{" "}
            {connected.savedAt
              ? `After ${clockTime(connected.savedAt)}, one`
              : "One"}{" "}
            of Krynodes' rules was changed in Tailscale's admin console:
          </DialogDescription>
        </DialogHeader>
        <ul className="space-y-1 rounded-md border bg-background p-3 font-mono text-xs">
          {lines.map((line) => (
            <li
              key={line}
              className={cn(
                "break-words",
                line.startsWith("-") ? "text-destructive" : "text-success",
              )}
            >
              {line}
            </li>
          ))}
        </ul>
        <fieldset className="space-y-2">
          {CHOICES.map((each) => (
            <label
              key={each.value}
              className="flex items-start gap-3 rounded-md border px-3 py-2.5 text-sm"
            >
              <input
                type="radio"
                name="changed-rule"
                className="mt-0.5 size-4 accent-primary"
                checked={chosen === each.value}
                disabled={save.isPending || (broken && each.value === "keep")}
                onChange={() => setChoice(each.value)}
              />
              <span>
                <span className="block font-medium">{each.title}</span>
                <span className="block text-xs text-muted-foreground">
                  {each.note}
                </span>
              </span>
            </label>
          ))}
        </fieldset>
        {broken && (
          <p className="text-sm text-warning">
            A changed line is not one grant on one line, so Krynodes cannot keep
            it as written. Put it on one line in Tailscale's admin console, or
            put Krynodes' back.
          </p>
        )}
        <Said text={save.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" disabled={save.isPending}>
              Cancel
            </Button>
          </DialogClose>
          <SignButton
            label="Save"
            pending={save.isPending}
            onClick={() => {
              const rules =
                chosen === "keep"
                  ? keepChange(connected, changed.now, changed.wanted)
                  : changed.wanted;
              save.mutate(
                {
                  rules,
                  expected: changed.block,
                  tag: changed.tag,
                  label: changed.label,
                },
                {
                  onSuccess: (saved) =>
                    saved.saved
                      ? onClose()
                      : onChanged({
                          ...changed,
                          block: saved.block,
                          now: saved.now,
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
