import { Lock } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  useAddressDisplay,
  useSaveAddressDisplay,
  type AddressDisplay,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";

import { SettingsSection } from "./section";

const CHOICES: { value: AddressDisplay; title: string; detail: string }[] = [
  {
    value: "hidden",
    title: "Hidden until shown",
    detail:
      "Fleet and the server page show 103.•.•.214. The lock button shows them in this tab until it closes. Copy always copies the whole address.",
  },
  {
    value: "shown",
    title: "Always shown",
    detail: "Everyone sees the whole address, with no lock button.",
  },
];

export function ServerAddressesSettings() {
  const current = useAddressDisplay();
  return (
    <SettingsSection
      title="Server addresses"
      description={
        <>
          Each server's public IPv4 and IPv6, as Krynodes sees them, for SSH and
          the like. Agent 0.6.10 or newer checks them every 6 hours. The lock (
          <Lock aria-hidden="true" className="inline size-3.5 align-[-2px]" />)
          only hides them from view; it is not the fingerprint.
        </>
      }
    >
      {current.data ? (
        <DisplayForm initial={current.data.display} />
      ) : (
        <p className="text-sm text-muted-foreground">
          {current.error ? errorMessage(current.error) : "Loading…"}
        </p>
      )}
    </SettingsSection>
  );
}

function DisplayForm({ initial }: { initial: AddressDisplay }) {
  const save = useSaveAddressDisplay();
  const [value, setValue] = useState(initial);
  const [saved, setSaved] = useState(initial);
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(value, { onSuccess: (next) => setSaved(next.display) });
      }}
    >
      <fieldset className="divide-y rounded-lg border bg-card">
        <legend className="sr-only">How server addresses show</legend>
        {CHOICES.map((choice) => (
          <label
            key={choice.value}
            className="flex cursor-pointer items-start gap-3 px-4 py-3 text-sm"
          >
            <input
              type="radio"
              name="address-display"
              className="mt-1"
              checked={value === choice.value}
              onChange={() => setValue(choice.value)}
            />
            <span>
              <span className="block font-medium">{choice.title}</span>
              <span className="block text-xs text-muted-foreground">
                {choice.detail}
              </span>
            </span>
          </label>
        ))}
      </fieldset>
      {save.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(save.error)}
        </p>
      )}
      <div className="flex items-center justify-end gap-3">
        {save.isSuccess && value === saved && (
          <span role="status" className="text-xs text-success">
            Saved
          </span>
        )}
        <Button
          type="submit"
          size="sm"
          disabled={value === saved || save.isPending}
        >
          {save.isPending ? "Saving…" : "Save"}
        </Button>
      </div>
    </form>
  );
}
