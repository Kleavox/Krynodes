import { useState } from "react";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ActionDialog } from "@/features/actions/action-dialog";
import type { FleetNode } from "@/types";

const ALL = "*";

export const linesValid = (text: string) =>
  /^[1-9]\d{0,2}$/u.test(text) && Number(text) <= 500;

export function LogsDialog({
  node,
  kind,
  name,
  services = [],
  onClose,
}: {
  node: FleetNode;
  kind: "stack" | "container";
  name: string;
  services?: string[];
  onClose: () => void;
}) {
  const [lines, setLines] = useState("200");
  const [service, setService] = useState(ALL);
  const count = linesValid(lines);
  return (
    <ActionDialog
      node={node}
      onClose={onClose}
      ready={count}
      ask={{
        kind,
        action: "logs",
        name,
        title: `Logs of ${name}`,
        args: {
          lines,
          ...(kind === "stack" && service !== ALL ? { service } : {}),
        },
        heading: `Logs of ${name}`,
        body: `${node.name} sends the last lines of ${name}. Logs can hold secrets, so reading them is signed too.`,
        confirm: "Show Logs",
      }}
    >
      <div className="space-y-2">
        <Label htmlFor="logs-lines">Lines</Label>
        <Input
          id="logs-lines"
          inputMode="numeric"
          value={lines}
          aria-invalid={!count}
          onChange={(event) => setLines(event.target.value)}
        />
        {!count && (
          <p className="text-xs text-destructive">
            Choose from 1 to 500 lines.
          </p>
        )}
      </div>
      {kind === "stack" && services.length > 1 && (
        <div className="space-y-2">
          <Label htmlFor="logs-service">Service</Label>
          <Select value={service} onValueChange={setService}>
            <SelectTrigger id="logs-service" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All Services</SelectItem>
              {services.map((one) => (
                <SelectItem key={one} value={one}>
                  {one}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
    </ActionDialog>
  );
}
