import { Fingerprint } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SetupOptions } from "@/features/nodes/setup-options";
import {
  adminChanged,
  adminNameProblem,
  adminProblem,
  keyRow,
  keyText,
  MAX_ADMIN_KEYS,
  type AdminKey,
  type EnrollAdmin,
} from "@/lib/admin-user";
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

function AdminFields({
  name,
  keys,
  onName,
  onKeys,
}: {
  name: string;
  keys: AdminKey[];
  onName: (name: string) => void;
  onKeys: (keys: AdminKey[]) => void;
}) {
  const [typed, setTyped] = useState("");
  const [wrong, setWrong] = useState<string | null>(null);
  const nameWrong = adminNameProblem(name.trim());
  const add = async () => {
    const row = await keyRow(typed, keys.length).catch(() => null);
    if (!row) {
      setWrong("Paste a public key such as ssh-ed25519 AAAA… name.");
      return;
    }
    if (keys.some((key) => key.fingerprint === row.fingerprint)) {
      setWrong("That key is already here.");
      return;
    }
    onKeys([...keys, row]);
    setTyped("");
    setWrong(null);
  };
  return (
    <div className="space-y-4 rounded-lg border bg-card p-4">
      <div className="space-y-1.5">
        <label htmlFor="admin-name" className="text-sm font-medium">
          Admin User
        </label>
        <Input
          id="admin-name"
          className="font-mono"
          autoComplete="off"
          spellCheck={false}
          placeholder="musyaf"
          value={name}
          aria-invalid={nameWrong !== null}
          onChange={(event) => onName(event.target.value)}
        />
        <p
          className={
            nameWrong
              ? "text-xs text-destructive"
              : "text-xs text-muted-foreground"
          }
        >
          Lowercase letters, digits, dashes and underscores. Not root.
        </p>
      </div>
      <div className="space-y-1.5">
        <label htmlFor="admin-key" className="text-sm font-medium">
          SSH Public Keys
        </label>
        <KeyRows
          keys={keys}
          onRemove={(index) => onKeys(keys.filter((_, at) => at !== index))}
        />
        {keys.length < MAX_ADMIN_KEYS && (
          <div className="flex gap-2">
            <Input
              id="admin-key"
              className="font-mono"
              autoComplete="off"
              spellCheck={false}
              placeholder="ssh-ed25519 AAAA… name"
              value={typed}
              aria-invalid={wrong !== null}
              onChange={(event) => {
                setTyped(event.target.value);
                setWrong(null);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void add();
                }
              }}
            />
            <Button
              type="button"
              variant="outline"
              disabled={typed.trim() === ""}
              onClick={() => void add()}
            >
              Add
            </Button>
          </div>
        )}
        <p
          className={
            wrong ? "text-xs text-destructive" : "text-xs text-muted-foreground"
          }
        >
          {wrong ??
            (keys.length < MAX_ADMIN_KEYS
              ? "Paste a public key, one line. Changing the keys asks for your fingerprint."
              : `Up to ${MAX_ADMIN_KEYS} keys. Changing the keys asks for your fingerprint.`)}
        </p>
      </div>
    </div>
  );
}

function DefaultsForm({ initial }: { initial: EnrollDefaults }) {
  const save = useSaveEnrollDefaults();
  const [value, setValue] = useState(initial);
  const [saved, setSaved] = useState(initial);
  const [name, setName] = useState(initial.admin?.name ?? "");
  const [keys, setKeys] = useState<AdminKey[]>(initial.admin?.keys ?? []);
  const admin: EnrollAdmin | null =
    name.trim() === "" && keys.length === 0
      ? null
      : { name: name.trim(), keys };
  const next = { ...value, admin };
  const problem = adminProblem(name, keys);
  const changed = JSON.stringify(next) !== JSON.stringify(saved);
  const confirming = adminChanged(saved.admin, admin);
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (problem) return;
        save.mutate(next, {
          onSuccess: (stored) => {
            setSaved(stored);
            setValue(stored);
            setKeys(stored.admin?.keys ?? []);
          },
        });
      }}
    >
      <div className="rounded-lg border bg-card p-4">
        <SetupOptions value={value} onChange={setValue} />
      </div>
      <AdminFields name={name} keys={keys} onName={setName} onKeys={setKeys} />
      {(problem ?? save.error) && (
        <p role="alert" className="text-sm text-destructive">
          {problem ?? errorMessage(save.error)}
        </p>
      )}
      <div className="flex items-center justify-end gap-3">
        {save.isSuccess && !changed && (
          <span role="status" className="text-xs text-success">
            Saved
          </span>
        )}
        <Button
          type="submit"
          size="sm"
          disabled={!changed || problem !== null || save.isPending}
        >
          {confirming && !save.isPending && <Fingerprint aria-hidden="true" />}
          {save.isPending ? "Saving…" : "Save"}
        </Button>
      </div>
    </form>
  );
}
