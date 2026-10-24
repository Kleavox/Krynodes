import { useState } from "react";

import { Button } from "@/components/ui/button";
import { SetupOptions } from "@/features/nodes/setup-options";
import {
  useEnrollDefaults,
  useSaveEnrollDefaults,
  type EnrollDefaults,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";

import { SettingsSection } from "./section";

export function EnrollDefaultsSettings() {
  const current = useEnrollDefaults(true);
  return (
    <SettingsSection
      title="Enroll Defaults"
      description="What a new install command sets up. You can still change it for one server when you enroll it."
    >
      {current.data ? (
        <DefaultsForm initial={current.data} />
      ) : (
        <p className="text-sm text-muted-foreground">
          {current.error ? errorMessage(current.error) : "Loading…"}
        </p>
      )}
    </SettingsSection>
  );
}

function DefaultsForm({ initial }: { initial: EnrollDefaults }) {
  const save = useSaveEnrollDefaults();
  const [value, setValue] = useState(initial);
  const [saved, setSaved] = useState(initial);
  const changed = JSON.stringify(value) !== JSON.stringify(saved);
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(value, { onSuccess: (next) => setSaved(next) });
      }}
    >
      <div className="rounded-lg border bg-card p-4">
        <SetupOptions value={value} onChange={setValue} />
      </div>
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
