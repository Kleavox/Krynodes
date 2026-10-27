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
import { Said, SignButton } from "@/features/packages/lines";
import { useNetwork } from "@/lib/api";
import { removeText, ruleText } from "@/lib/tailscale";

import type { Changed } from "./changed-rule-dialog";
import { useSaveRules, useTailnet } from "./use-tailscale";

export function RemoveRuleDialog({
  index,
  onChanged,
  onClose,
}: {
  index: number;
  onChanged: (changed: Changed) => void;
  onClose: () => void;
}) {
  const { data } = useTailnet();
  const network = useNetwork().data;
  const save = useSaveRules();
  const connected = data?.connected;
  const rule = connected?.rules[index];
  if (!connected || !rule) return null;
  const members = (network?.members ?? []).map((member) => member.nodeId);
  const text =
    "ports" in rule
      ? removeText(rule, data.servers, members)
      : {
          title: "Remove this rule?",
          body: `${ruleText(rule, data.servers)} goes out of your policy file.`,
        };
  const wanted = connected.rules.filter((_, at) => at !== index);

  return (
    <Dialog open onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-[512px]">
        <DialogHeader>
          <DialogTitle>{text.title}</DialogTitle>
          <DialogDescription>{text.body}</DialogDescription>
        </DialogHeader>
        <Said text={save.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" disabled={save.isPending}>
              Cancel
            </Button>
          </DialogClose>
          <SignButton
            label="Remove"
            destructive
            pending={save.isPending}
            onClick={() =>
              save.mutate(
                {
                  rules: wanted,
                  expected: connected.block ?? "",
                  tag: false,
                  label: "Remove",
                },
                {
                  onSuccess: (saved) =>
                    saved.saved
                      ? onClose()
                      : onChanged({
                          wanted,
                          block: saved.block,
                          now: saved.now,
                          tag: false,
                          label: "Remove",
                        }),
                },
              )
            }
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
