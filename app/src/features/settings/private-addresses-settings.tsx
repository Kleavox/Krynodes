import { useState } from "react";

import { Button } from "@/components/ui/button";
import { usePrivateRanges, useSavePrivateRanges } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { rangeLines } from "@/lib/security";

import { SettingsSection } from "./section";

const AREA =
  "w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

export function PrivateAddressesSettings() {
  const current = usePrivateRanges(true);
  return (
    <SettingsSection
      title="Private addresses"
      description="Listeners on addresses in these ranges, such as a VPN's, are not counted as public on any server. A server's addresses in these ranges show on Fleet under their interface name, such as tailscale0. One range per line, such as 10.8.0.0/24."
    >
      {current.data ? (
        <RangesForm initial={current.data.ranges} />
      ) : (
        <p className="text-sm text-muted-foreground">
          {current.error ? errorMessage(current.error) : "Loading…"}
        </p>
      )}
    </SettingsSection>
  );
}

function RangesForm({ initial }: { initial: string[] }) {
  const save = useSavePrivateRanges();
  const [text, setText] = useState(initial.join("\n"));
  const changed = rangeLines(text).join("\n") !== initial.join("\n");
  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(rangeLines(text), {
          onSuccess: (saved) => setText(saved.ranges.join("\n")),
        });
      }}
    >
      <textarea
        aria-label="Address ranges"
        value={text}
        rows={8}
        spellCheck={false}
        autoCapitalize="off"
        placeholder={"100.64.0.0/10\nfd7a:115c:a1e0::/48"}
        onChange={(event) => setText(event.target.value)}
        className={AREA}
      />
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
