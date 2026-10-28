import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { adminOption, type EnrollAdmin } from "@/lib/admin-user";
import { useNetwork, type SetupChoice } from "@/lib/api";

export function SetupOptions<T extends SetupChoice>({
  value,
  onChange,
  admin,
  disabled = false,
}: {
  value: T;
  onChange: (next: T) => void;
  admin?: EnrollAdmin | null;
  disabled?: boolean;
}) {
  const network = useNetwork().data?.network;
  const option = admin === undefined ? null : adminOption(admin);
  return (
    <fieldset className="space-y-2" disabled={disabled}>
      <legend className="sr-only">Set the server up</legend>
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
            Restart hour (your time)
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
            disabled={!option.available}
            checked={option.available && value.adminUser === true}
            onChange={() => onChange({ ...value, adminUser: !value.adminUser })}
          />
          <span>
            <span className="block font-medium">Add Admin User</span>
            <span className="block text-xs text-muted-foreground">
              {option.text}
            </span>
          </span>
        </label>
      )}
    </fieldset>
  );
}
