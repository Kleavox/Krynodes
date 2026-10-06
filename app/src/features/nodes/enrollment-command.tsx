import { useState } from "react";

import { CopyCommand } from "@/components/copy-command";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { setupFlags } from "@/lib/enroll";
import { countdown } from "@/lib/format";
import { useNow } from "@/lib/use-now";
import type { Enrollment } from "@/types";

export function EnrollmentCommand({ enrollment }: { enrollment: Enrollment }) {
  const now = useNow();
  const [recommended, setRecommended] = useState(true);
  const [docker, setDocker] = useState(true);
  const [hour, setHour] = useState("3");
  const remaining = Date.parse(enrollment.enrollmentExpiresAt) - now;
  const flags = setupFlags({
    recommended,
    docker,
    hour: Number(hour),
    offset: new Date().getTimezoneOffset(),
  });
  return (
    <div className="space-y-3">
      <fieldset className="space-y-2">
        <legend className="sr-only">Set the server up</legend>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={recommended}
            onChange={() => setRecommended(!recommended)}
          />
          <span>
            <span className="block font-medium">
              Apply recommended protections
            </span>
            <span className="block text-xs text-muted-foreground">
              Automatic security updates, restart when needed, SSH keys only and
              blocking repeated login failures.
            </span>
          </span>
        </label>
        {recommended && (
          <div className="flex items-center gap-2 pl-6">
            <Label htmlFor="enroll-hour" className="text-xs">
              Restart hour (your time)
            </Label>
            <Select value={hour} onValueChange={setHour}>
              <SelectTrigger id="enroll-hour" className="h-8 w-24">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Array.from({ length: 24 }, (_, value) => (
                  <SelectItem key={value} value={String(value)}>
                    {String(value).padStart(2, "0")}:00
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
            checked={docker}
            onChange={() => setDocker(!docker)}
          />
          <span>
            <span className="block font-medium">Install Docker</span>
            <span className="block text-xs text-muted-foreground">
              With Compose, from Docker&apos;s own repository.
            </span>
          </span>
        </label>
      </fieldset>
      <CopyCommand command={enrollment.command + flags} />
      <p className="font-mono text-xs text-muted-foreground">
        {remaining > 0
          ? `Expires in ${countdown(remaining)}`
          : "Expired. Create a new command."}
        {flags && " · Setup takes a few minutes on a fresh server."}
      </p>
    </div>
  );
}
