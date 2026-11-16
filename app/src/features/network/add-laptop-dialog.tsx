import { useEffect, useRef } from "react";

import { Busy } from "@/components/busy";
import { CopyCommand } from "@/components/copy-command";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Said } from "@/features/packages/lines";
import { useAddLaptop } from "@/lib/api";
import { countdown } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import { useNow } from "@/lib/use-now";

const DOWNLOAD =
  "https://github.com/Kleavox/Krynodes/releases/latest/download/krynodes-windows-amd64.exe";

function installCommand(
  code: string,
  origin: string,
  endpoint: string,
): string {
  const args = ["install", "--code", code, "--origin", origin];
  if (endpoint !== origin) args.push("--endpoint", endpoint);
  return `& "$HOME\\Downloads\\krynodes-windows-amd64.exe" ${args.join(" ")} | Out-Host`;
}

export function CodeSheet({
  code,
  expiresAt,
  origin,
  endpoint,
  now,
}: {
  code: string;
  expiresAt: string;
  origin: string;
  endpoint: string;
  now: number;
}) {
  const remaining = Date.parse(expiresAt) - now;
  return (
    <div className="space-y-3">
      <p className="text-sm">
        On the laptop, download Krynodes for Windows to Downloads. Then run this
        in PowerShell as Administrator.
      </p>
      <p className="text-xs text-muted-foreground">
        Delete any older copy in Downloads first.
      </p>
      <a
        className="block w-fit text-sm underline underline-offset-4"
        href={DOWNLOAD}
      >
        Download Krynodes for Windows
      </a>
      <CopyCommand command={installCommand(code, origin, endpoint)} />
      <p className="font-mono text-xs text-muted-foreground">
        {remaining > 0
          ? `Expires in ${countdown(remaining)} · Works once`
          : "Expired. Close this and choose Add Laptop again."}
      </p>
      <p className="text-xs text-muted-foreground">
        The code alone gives no access. The laptop shows up here, and joins the
        private network when you approve it.
      </p>
    </div>
  );
}

export function AddLaptopDialog({ onClose }: { onClose: () => void }) {
  const make = useAddLaptop();
  const now = useNow();
  const asked = useRef(false);

  useEffect(() => {
    if (asked.current) return;
    asked.current = true;
    make.mutate();
  }, []);

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onInteractOutside={(event) => event.preventDefault()}>
        <DialogHeader>
          <DialogTitle>Add Laptop</DialogTitle>
          <DialogDescription>
            A laptop joins the private network and reaches every server on its
            private address.
          </DialogDescription>
        </DialogHeader>
        {make.data ? (
          <CodeSheet
            code={make.data.code}
            expiresAt={make.data.expiresAt}
            origin={make.data.origin}
            endpoint={make.data.endpoint}
            now={now}
          />
        ) : (
          !make.error && (
            <p role="status" className="text-sm text-muted-foreground">
              <Busy>Making a code</Busy>
            </p>
          )
        )}
        <Said text={make.error ? errorMessage(make.error) : null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Done</Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
