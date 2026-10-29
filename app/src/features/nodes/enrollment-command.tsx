import { CopyCommand } from "@/components/copy-command";
import type { AdminKey } from "@/lib/admin-user";
import type { SetupChoice } from "@/lib/api";
import { countdown } from "@/lib/format";
import { useNow } from "@/lib/use-now";
import type { Enrollment } from "@/types";

import { SetupOptions } from "./setup-options";

export function EnrollmentCommand({
  enrollment,
  setup,
  onSetupChange,
  keys,
}: {
  enrollment: Enrollment;
  setup: SetupChoice;
  onSetupChange: (next: SetupChoice) => void;
  keys: AdminKey[];
}) {
  const now = useNow();
  const remaining = Date.parse(enrollment.enrollmentExpiresAt) - now;
  return (
    <div className="space-y-3">
      <SetupOptions
        value={setup}
        onChange={onSetupChange}
        keys={keys}
        adminLocked
        disabled={remaining <= 0}
      />
      <CopyCommand command={enrollment.command} />
      <p className="font-mono text-xs text-muted-foreground">
        {remaining > 0
          ? `Expires in ${countdown(remaining)}`
          : "Expired. Create a new command."}
        {(setup.recommended || setup.docker) &&
          " · Setup takes a few minutes on a fresh server."}
      </p>
    </div>
  );
}
