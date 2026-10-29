import { KeyRound } from "lucide-react";
import { useRef, useState } from "react";

import { Busy } from "@/components/busy";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SetupOptions } from "@/features/nodes/setup-options";
import {
  addKeys,
  keysChanged,
  keyText,
  MAX_ADMIN_KEYS,
  type AdminKey,
} from "@/lib/admin-user";
import {
  useEnrollDefaults,
  useSaveEnrollDefaults,
  type EnrollDefaults,
  type SetupChoice,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";

import { SettingsSection } from "./section";

const MAX_KEY_FILE = 64 * 1024;

export function EnrollDefaultsSettings() {
  const current = useEnrollDefaults(true);
  return (
    <SettingsSection
      title="Enroll Defaults"
      description="What a new install command sets up. You can still change Docker and the private network for one server when you enroll it."
    >
      {current.data ? (
        <DefaultsForm initial={current.data} />
      ) : (
        <p className="text-sm text-muted-foreground">
          {current.error ? errorMessage(current.error) : <Busy>Loading</Busy>}
        </p>
      )}
    </SettingsSection>
  );
}

export function ProtectionOptions<T extends SetupChoice>({
  value,
  onChange,
}: {
  value: T;
  onChange: (next: T) => void;
}) {
  return (
    <div className="space-y-2">
      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-1"
          checked={value.recommended}
          onChange={() =>
            onChange({ ...value, recommended: !value.recommended })
          }
        />
        <span>
          <span className="block font-medium">
            Apply Recommended Protections
          </span>
          <span className="block text-xs text-muted-foreground">
            Automatic security updates, restart when needed, SSH keys only,
            blocking repeated login failures and a firewall.
          </span>
        </span>
      </label>
      {value.recommended && (
        <div className="flex items-center gap-2 pl-6">
          <Label htmlFor="setup-hour" className="text-xs">
            Restart Hour (Your Time)
          </Label>
          <Select
            value={String(value.hour)}
            onValueChange={(hour) => onChange({ ...value, hour: Number(hour) })}
          >
            <SelectTrigger id="setup-hour" className="h-8 w-24">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {Array.from({ length: 24 }, (_, hour) => (
                <SelectItem key={hour} value={String(hour)}>
                  {String(hour).padStart(2, "0")}:00
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
    </div>
  );
}

export function KeyRows({
  keys,
  onRemove,
}: {
  keys: AdminKey[];
  onRemove: (index: number) => void;
}) {
  if (keys.length === 0) return null;
  return (
    <ul className="divide-y rounded-md border px-3">
      {keys.map((key, index) => (
        <li key={key.line} className="flex items-center gap-2 py-1.5">
          <span className="min-w-0 flex-1 truncate font-mono text-xs">
            {keyText(key)}
          </span>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-9 md:h-7"
            onClick={() => onRemove(index)}
          >
            Remove
          </Button>
        </li>
      ))}
    </ul>
  );
}

export function KeysField({
  keys,
  onKeys,
}: {
  keys: AdminKey[];
  onKeys: (keys: AdminKey[]) => void;
}) {
  const [typed, setTyped] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const picker = useRef<HTMLInputElement>(null);
  const full = keys.length >= MAX_ADMIN_KEYS;
  const take = (read: Promise<string>) =>
    void read
      .then((text) => addKeys(text, keys))
      .then((added) => {
        onKeys(added.keys);
        setTyped(added.rest);
        setNote(added.note);
      })
      .catch((error: unknown) => setNote(errorMessage(error)));
  const browse = (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_KEY_FILE) {
      setNote("That file is too large to be a list of public keys.");
      return;
    }
    take(file.text());
  };
  return (
    <div className="space-y-1.5">
      <label htmlFor="admin-keys" className="text-sm font-medium">
        SSH Public Keys
      </label>
      <KeyRows
        keys={keys}
        onRemove={(index) => onKeys(keys.filter((_, at) => at !== index))}
      />
      {!full && (
        <div className="flex items-start gap-2">
          <textarea
            id="admin-keys"
            rows={1}
            autoComplete="off"
            spellCheck={false}
            placeholder="ssh-ed25519 AAAA… name"
            value={typed}
            aria-invalid={note !== null && typed !== ""}
            onChange={(event) => {
              setTyped(event.target.value);
              setNote(null);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                if (typed.trim() !== "") take(Promise.resolve(typed));
              }
            }}
            className="field-sizing-content max-h-40 min-h-9 w-full min-w-0 resize-none rounded-md border bg-transparent px-3 py-1.5 font-mono text-sm break-all shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 aria-invalid:border-destructive"
          />
          <input
            ref={picker}
            type="file"
            hidden
            tabIndex={-1}
            onChange={(event) => {
              browse(event.target.files?.[0]);
              event.target.value = "";
            }}
          />
          <Button
            type="button"
            variant="outline"
            className="shrink-0"
            onClick={() =>
              typed.trim() === ""
                ? picker.current?.click()
                : take(Promise.resolve(typed))
            }
          >
            {typed.trim() === "" ? "Browse" : "Add"}
          </Button>
        </div>
      )}
      <p
        className={
          note ? "text-xs text-destructive" : "text-xs text-muted-foreground"
        }
      >
        {note ??
          (full
            ? `Up to ${MAX_ADMIN_KEYS} keys. Changing the keys asks for your passkey.`
            : "Paste one or more public keys, or browse for a .pub or authorized_keys file. Changing the keys asks for your passkey.")}
      </p>
    </div>
  );
}

function DefaultsForm({ initial }: { initial: EnrollDefaults }) {
  const save = useSaveEnrollDefaults();
  const [value, setValue] = useState(initial);
  const [saved, setSaved] = useState(initial);
  const changed = JSON.stringify(value) !== JSON.stringify(saved);
  const confirming = keysChanged(saved.keys, value.keys);
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(value, {
          onSuccess: (stored) => {
            setSaved(stored);
            setValue(stored);
          },
        });
      }}
    >
      <div className="space-y-2 rounded-lg border bg-card p-4">
        <ProtectionOptions value={value} onChange={setValue} />
        <SetupOptions value={value} onChange={setValue} />
      </div>
      <div className="rounded-lg border bg-card p-4">
        <KeysField
          keys={value.keys}
          onKeys={(keys) => setValue((current) => ({ ...current, keys }))}
        />
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
          {confirming && !save.isPending && <KeyRound aria-hidden="true" />}
          {save.isPending ? <Busy>Saving</Busy> : "Save"}
        </Button>
      </div>
    </form>
  );
}
