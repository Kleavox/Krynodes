import type { QuarantineSettings as Settings } from "@krynodes/protocol";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  useNetwork,
  useQuarantineSettings,
  useSaveQuarantineSettings,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { QUARANTINE_INTRO, settingsRows } from "@/lib/quarantine";

import { SettingsSection } from "./section";

export function QuarantineSettings() {
  const current = useQuarantineSettings();
  const network = useNetwork();
  return (
    <SettingsSection title="Quarantine" description={QUARANTINE_INTRO}>
      {current.data && network.data ? (
        <QuarantineForm
          initial={current.data.settings}
          member={network.data.network !== null}
        />
      ) : (
        <p className="text-sm text-muted-foreground">
          {current.error
            ? errorMessage(current.error)
            : network.error
              ? errorMessage(network.error)
              : "Loading…"}
        </p>
      )}
    </SettingsSection>
  );
}

function QuarantineForm({
  initial,
  member,
}: {
  initial: Settings;
  member: boolean;
}) {
  const save = useSaveQuarantineSettings();
  const [value, setValue] = useState(initial);
  const [saved, setSaved] = useState(initial);
  const changed = JSON.stringify(value) !== JSON.stringify(saved);
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(value, { onSuccess: (next) => setSaved(next.settings) });
      }}
    >
      <ul className="divide-y rounded-lg border bg-card">
        {settingsRows(member).map((row) => (
          <li
            key={row.key}
            className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between sm:gap-4"
          >
            <div className="min-w-0 text-sm">
              <label htmlFor={`quarantine-${row.key}`} className="font-medium">
                {row.title}
              </label>
              <p className="text-xs text-muted-foreground">{row.note}</p>
              {row.later && (
                <p className="text-xs text-muted-foreground">{row.later}</p>
              )}
            </div>
            <Select
              value={String(value[row.key])}
              onValueChange={(next) => {
                const choice = (
                  row.choices as { value: unknown; label: string }[]
                ).find((each) => String(each.value) === next);
                if (choice) setValue({ ...value, [row.key]: choice.value });
              }}
            >
              <SelectTrigger
                id={`quarantine-${row.key}`}
                className="w-full shrink-0 sm:w-52"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(row.choices as { value: unknown; label: string }[]).map(
                  (choice) => (
                    <SelectItem
                      key={String(choice.value)}
                      value={String(choice.value)}
                    >
                      {choice.label}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
          </li>
        ))}
      </ul>
      {save.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(save.error)}
        </p>
      )}
      <div className="flex items-center justify-end gap-3">
        {save.isSuccess && !changed && (
          <span role="status" className="text-xs text-success">
            Saved
          </span>
        )}
        <Button type="submit" size="sm" disabled={!changed || save.isPending}>
          {save.isPending ? "Saving…" : "Save"}
        </Button>
      </div>
    </form>
  );
}
