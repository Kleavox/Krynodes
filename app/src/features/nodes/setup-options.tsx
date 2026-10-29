import { Input } from "@/components/ui/input";
import { adminNameProblem, adminOption, type AdminKey } from "@/lib/admin-user";
import { useNetwork, type SetupChoice } from "@/lib/api";

export function SetupOptions<T extends SetupChoice>({
  value,
  onChange,
  keys,
  adminLocked = false,
  disabled = false,
}: {
  value: T;
  onChange: (next: T) => void;
  keys?: AdminKey[];
  adminLocked?: boolean;
  disabled?: boolean;
}) {
  const network = useNetwork().data?.network;
  const option = keys === undefined ? null : adminOption(keys);
  const adding = option?.available === true && value.adminUser === true;
  const name = value.adminName ?? "";
  const wrong = name.trim() === "" ? null : adminNameProblem(name.trim());
  return (
    <fieldset className="space-y-2" disabled={disabled}>
      <legend className="sr-only">Set the server up</legend>
      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-1"
          checked={value.docker}
          onChange={() => onChange({ ...value, docker: !value.docker })}
        />
        <span>
          <span className="block font-medium">Install Docker</span>
          <span className="block text-xs text-muted-foreground">
            With Compose, from Docker&apos;s own repository.
          </span>
        </span>
      </label>
      {network && (
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={value.network}
            onChange={() => onChange({ ...value, network: !value.network })}
          />
          <span>
            <span className="block font-medium">Join Private Network</span>
            <span className="block text-xs text-muted-foreground">
              Gets it ready while it enrolls. It joins once it shows up and you
              allow it with your passkey.
            </span>
          </span>
        </label>
      )}
      {option && (
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            disabled={!option.available || adminLocked}
            checked={adding}
            onChange={() => onChange({ ...value, adminUser: !value.adminUser })}
          />
          <span>
            <span className="block font-medium">Add Admin User</span>
            <span className="block text-xs text-muted-foreground">
              {option.text}
            </span>
            {adminLocked && !adding && (
              <span className="block text-xs text-muted-foreground">
                Set when the command is made.
              </span>
            )}
          </span>
        </label>
      )}
      {adding && (
        <div className="space-y-1.5 pl-6">
          <label htmlFor="enroll-admin-name" className="text-xs font-medium">
            User Name
          </label>
          <Input
            id="enroll-admin-name"
            className="h-8 font-mono"
            autoComplete="off"
            spellCheck={false}
            placeholder="musyaf"
            value={name}
            disabled={adminLocked}
            autoFocus={!adminLocked}
            aria-invalid={wrong !== null}
            onChange={(event) =>
              onChange({ ...value, adminName: event.target.value })
            }
          />
          <p
            className={
              wrong
                ? "text-xs text-destructive"
                : "text-xs text-muted-foreground"
            }
          >
            {adminLocked
              ? "Set when the command is made."
              : "Lowercase letters, digits, dashes and underscores. Not root."}
          </p>
        </div>
      )}
    </fieldset>
  );
}
