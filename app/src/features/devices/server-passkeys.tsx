import { useEffect, useState } from "react";

import { accessChange, buildChange } from "@/lib/devices";
import type { NodeRecord } from "@/types";

import { AccessDialog } from "./access-dialog";
import { ApprovalDialog, type Review } from "./approval-dialog";
import { useFleet } from "./use-fleet";

export function ServerPasskeys({
  node,
  removing,
  onClose,
}: {
  node: NodeRecord;
  removing: boolean;
  onClose: () => void;
}) {
  const fleet = useFleet();
  const [review, setReview] = useState<Review | null>(null);
  const server = fleet?.servers.find((entry) => entry.node.id === node.id);
  useEffect(() => {
    if (!removing || !fleet || review) return;
    setReview({
      text: buildChange(
        fleet.view,
        accessChange(fleet.view, { [node.id]: [] }),
      ),
    });
  }, [removing, fleet, review, node.id]);
  if (!fleet || !server) return null;
  return (
    <>
      <AccessDialog
        fleet={fleet}
        scope={removing || review ? null : { server }}
        onClose={onClose}
        onReview={(text) => setReview({ text })}
      />
      <ApprovalDialog fleet={fleet} review={review} onClose={onClose} />
    </>
  );
}
