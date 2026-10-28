import { KeyRound } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

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
import { useApproveProposal, useOpenProposal } from "@/lib/api";
import {
  decodeChange,
  describeChange,
  predictMissing,
  usable,
} from "@/lib/devices";
import { capitalize } from "@/lib/format";
import { approveChange } from "@/lib/passkeys";
import type { ProposalRecord } from "@/types";

import { ChangeDetails } from "./change-details";
import { failure } from "@/lib/proof";
import { when } from "./parts";
import type { Fleet } from "./use-fleet";

export interface Review {
  text: string;
  proposal?: ProposalRecord;
}

export const SHEET =
  "max-h-[92dvh] overflow-y-auto max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none";

export function approvalLine(fleet: Fleet, proposal: ProposalRecord): string {
  const names = proposal.approvals.map((id) => `${fleet.name(id)} ✓`);
  const more = /needs (\d+) more/u.exec(proposal.missing ?? "");
  const total = more ? proposal.approvals.length + Number(more[1]) : null;
  return [
    total ? `${proposal.approvals.length} of ${total}` : null,
    ...names,
    proposal.missing ? capitalize(proposal.missing) : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function ApprovalDialog({
  fleet,
  review,
  onClose,
}: {
  fleet: Fleet;
  review: Review | null;
  onClose: () => void;
}) {
  return (
    <Dialog open={review !== null} onOpenChange={(open) => !open && onClose()}>
      {review && <Body fleet={fleet} review={review} onClose={onClose} />}
    </Dialog>
  );
}

function Body({
  fleet,
  review,
  onClose,
}: {
  fleet: Fleet;
  review: Review;
  onClose: () => void;
}) {
  const open = useOpenProposal();
  const approve = useApproveProposal();
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const change = decodeChange(review.text);
  const { proposal } = review;
  const approved = proposal?.approvals ?? [];
  const mineApproved = fleet.mine.some((id) => approved.includes(id));
  const signers = fleet.core
    .filter(usable)
    .map((device) => device.id)
    .filter((id) => !approved.includes(id));
  const me = fleet.mine.find((id) => signers.includes(id));

  if (!change) {
    return (
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>This change cannot be read</DialogTitle>
          <DialogDescription>
            Its bytes are not a trust change. Do not approve it; cancel it
            instead.
          </DialogDescription>
        </DialogHeader>
      </DialogContent>
    );
  }

  const summary = describeChange(fleet.view, change);
  const after = me
    ? predictMissing(fleet.view, change, [...approved, me])
    : undefined;

  const submit = async () => {
    setWorking(true);
    setError(null);
    try {
      const approval = await approveChange(
        review.text,
        signers,
        window.location.hostname,
      );
      const reply = proposal
        ? await approve.mutateAsync({ id: proposal.id, approval })
        : await open.mutateAsync({ change: review.text, approval });
      if (reply.status === "applied") {
        toast.success(
          "Approved and sent to your servers. They apply it within a minute.",
        );
      } else {
        toast.success(
          `Approved. ${capitalize(reply.missing ?? "it needs more approvals")}.`,
        );
      }
      onClose();
    } catch (caught) {
      setError(failure(caught));
    } finally {
      setWorking(false);
    }
  };

  return (
    <DialogContent className={SHEET}>
      <DialogHeader>
        <DialogTitle>{summary.title}</DialogTitle>
        <DialogDescription>
          {proposal
            ? `Opened by ${fleet.name(proposal.openedBy)} · Expires ${when(change.expiresAt)}`
            : `Expires ${when(change.expiresAt)} unless enough passkeys approve it.`}
        </DialogDescription>
      </DialogHeader>
      <ChangeDetails fleet={fleet} change={change} />
      <div className="rounded-md bg-muted/50 px-3 py-2 text-sm">
        {proposal && <p>{approvalLine(fleet, proposal)}</p>}
        {!mineApproved && after === null && (
          <p>Applies as soon as you approve.</p>
        )}
        {!mineApproved && after && (
          <p>After you approve: {capitalize(after)}.</p>
        )}
        {mineApproved && (
          <p>You approved this. Approve with another passkey.</p>
        )}
        {!proposal && after === undefined && (
          <p>
            Approve with one of your trusted passkeys. The servers count the
            approvals.
          </p>
        )}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={working}>
          {mineApproved ? "Close" : "Cancel"}
        </Button>
        {!mineApproved && (
          <Button
            disabled={working || signers.length === 0}
            onClick={() => void submit()}
          >
            <KeyRound aria-hidden="true" />
            {working ? <Waiting /> : "Approve with Passkey"}
          </Button>
        )}
      </DialogFooter>
    </DialogContent>
  );
}
