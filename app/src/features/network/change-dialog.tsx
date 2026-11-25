import type { NetworkDocument, NetworkRule } from "@krynodes/protocol";
import { useState, type ReactNode } from "react";

import { Waiting } from "@/components/busy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { changeNetwork } from "@/lib/approve";
import {
  networkFailure,
  withExit,
  withoutMember,
  withoutNetwork,
} from "@/lib/network";
import { describeRule, dropRule, ruleDeleteText } from "@/lib/rules";

import { useOneTimeCheck } from "./one-time-check";
import { useRefreshNetwork } from "./use-network";

export interface Change {
  heading: string;
  body: string;
  confirm: string;
  destructive?: boolean;
  change: string;
  edit: (next: NetworkDocument) => NetworkDocument;
}

type Named = { node: string; name: string };

export const exitChange = ({ node, name }: Named, on: boolean): Change =>
  on
    ? {
        heading: `Exit Node for Laptops on ${name}`,
        body: `Laptops in the private network can then send all their internet traffic out through ${name}. Sites see ${name}'s address, not the laptop's.`,
        confirm: "Turn On",
        change: `Make ${name} the exit node for laptops`,
        edit: (next) => withExit(next, node),
      }
    : {
        heading: `Exit Node for Laptops on ${name}`,
        body: `Laptops stop sending their internet traffic out through ${name} and go back to their own connection.`,
        confirm: "Turn Off",
        destructive: true,
        change: `Stop using ${name} as the exit node for laptops`,
        edit: (next) => withExit(next, null),
      };

export const removeChange = ({ node, name }: Named): Change => ({
  heading: `Remove ${name} from the Network?`,
  body: `Every member drops ${name} and stops accepting its key. ${name} itself keeps running.`,
  confirm: "Remove",
  destructive: true,
  change: `Remove ${name} from the private network`,
  edit: (next) => withoutMember(next, node),
});

export const deleteRuleChange = (
  index: number,
  rule: NetworkRule,
  names: ReadonlyMap<string, string>,
): Change => {
  const sentence = describeRule(rule, names);
  return {
    heading: "Delete This Rule?",
    body: `${sentence} After you delete it, new connections of that kind are refused unless another rule allows them. A connection already open keeps running until it closes.`,
    confirm: "Delete Rule",
    destructive: true,
    change: ruleDeleteText(rule, names),
    edit: (next) => dropRule(next, index, rule),
  };
};

export const deleteChange: Change = {
  heading: "Delete the Private Network?",
  body: "Every member leaves the private network, its keys stop working and its rules are deleted. You can create a new network later.",
  confirm: "Delete Network",
  destructive: true,
  change: "Delete the private network",
  edit: withoutNetwork,
};

type ChangePhase = "confirm" | "running" | "done";

export function ChangeBody({
  change,
  phase,
  said,
  checking,
  onStart,
  onClose,
  children,
}: {
  change: Change;
  phase: ChangePhase;
  said: { text: string; failed: boolean } | null;
  checking: boolean;
  onStart: () => void;
  onClose: () => void;
  children?: ReactNode;
}) {
  return (
    <>
      {said && (
        <p
          role={said.failed ? "alert" : "status"}
          className={said.failed ? "text-sm text-destructive" : "text-sm"}
        >
          {said.text}
        </p>
      )}
      {children}
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>
          {phase === "confirm" ? "Cancel" : "Close"}
        </Button>
        {phase !== "done" && (
          <Button
            variant={change.destructive ? "destructive" : "default"}
            disabled={phase === "running"}
            onClick={onStart}
          >
            {phase === "running" && !checking ? <Waiting /> : change.confirm}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}

export function ChangeDialog({
  change,
  onClose,
}: {
  change: Change;
  onClose: () => void;
}) {
  const refresh = useRefreshNetwork();
  const { check, panel, checking } = useOneTimeCheck();
  const [phase, setPhase] = useState<ChangePhase>("confirm");
  const [said, setSaid] = useState<{ text: string; failed: boolean } | null>(
    null,
  );
  const start = () => {
    setPhase("running");
    setSaid(null);
    void changeNetwork(change.edit, change.change, { check })
      .then(
        (version) =>
          setSaid({
            text: `Signed and sent as version ${version}. Each member shows when it has applied it.`,
            failed: false,
          }),
        (error: unknown) =>
          setSaid({ text: networkFailure(error), failed: true }),
      )
      .finally(() => {
        setPhase("done");
        refresh();
      });
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{change.heading}</DialogTitle>
          <DialogDescription>{change.body}</DialogDescription>
        </DialogHeader>
        <ChangeBody
          change={change}
          phase={phase}
          said={said}
          checking={checking}
          onStart={start}
          onClose={onClose}
        >
          {panel}
        </ChangeBody>
      </DialogContent>
    </Dialog>
  );
}
