import { useCallback, useState } from "react";

import { Button } from "@/components/ui/button";
import type { Unchecked } from "@/lib/pins";

export function OneTimeCheck({
  members,
  onAnswer,
}: {
  members: Unchecked[];
  onAnswer: (match: boolean) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Check Fingerprints"
      className="space-y-3 rounded-lg border p-3"
    >
      <p className="text-sm">
        This browser has not checked these members yet, or their keys changed.
        Compare each fingerprint with the machine itself before anything is
        signed. You do this once in each browser.
      </p>
      <ul className="space-y-2">
        {members.map((member) => (
          <li key={member.node} className="space-y-0.5">
            <p className="text-sm font-medium">{member.name}</p>
            {member.warning && (
              <p className="text-sm text-destructive">{member.warning}</p>
            )}
            <p className="font-mono text-sm tracking-wider">
              {member.fingerprint}
            </p>
            <p className="text-xs text-muted-foreground">{member.line}</p>
          </li>
        ))}
      </ul>
      <div className="flex justify-end gap-2">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => onAnswer(false)}
        >
          Cancel
        </Button>
        <Button type="button" size="sm" onClick={() => onAnswer(true)}>
          They Match
        </Button>
      </div>
    </div>
  );
}

export function useOneTimeCheck() {
  const [asked, setAsked] = useState<{
    members: Unchecked[];
    answer: (match: boolean) => void;
  } | null>(null);
  const check = useCallback(
    (members: Unchecked[]) =>
      new Promise<boolean>((resolve) => {
        setAsked({
          members,
          answer: (match) => {
            setAsked(null);
            resolve(match);
          },
        });
      }),
    [],
  );
  const panel = asked && (
    <OneTimeCheck members={asked.members} onAnswer={asked.answer} />
  );
  return { check, panel };
}
