import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";

export function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(command).then(
      () => setCopied(true),
      () => toast.error("Copy failed. Select the command and copy it by hand."),
    );
  };
  return (
    <div className="space-y-2">
      <pre className="rounded-md border bg-background p-3 font-mono text-xs break-all whitespace-pre-wrap">
        {command}
      </pre>
      <Button variant="outline" size="sm" onClick={copy}>
        {copied ? "Copied" : "Copy Command"}
      </Button>
    </div>
  );
}
