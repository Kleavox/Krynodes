export interface QuorumInput {
  current: {
    core: string[];
    access: string[];
    accounts?: Record<string, string>;
  };
  change: {
    core: string[] | null;
    access: string[];
    accounts?: Record<string, string>;
  };
  approvals: string[];
  unsynced?: string[];
}

export type QuorumResult = { ok: true } | { ok: false; reason: string };

const WITH_ACCESS =
  "needs approval from another device that reaches this server";

const OTHER_ACCOUNT = "from another account or a passkey that is not synced";

const quorum = (devices: number) => (devices > 2 ? 2 : 1);

const sameSet = (a: string[], b: string[]) =>
  a.length === b.length && a.every((item) => b.includes(item));

export function evaluateQuorum({
  current,
  change,
  approvals,
  unsynced = [],
}: QuorumInput): QuorumResult {
  const approvers = [...new Set(approvals)];
  if (approvers.length === 0) return { ok: false, reason: "needs an approval" };
  if (approvers.some((id) => !current.core.includes(id))) {
    return {
      ok: false,
      reason: "an approval comes from a device the servers do not trust",
    };
  }
  const core = change.core ?? current.core;
  if (change.access.some((id) => !core.includes(id))) {
    return {
      ok: false,
      reason: "access names a device the servers do not trust",
    };
  }
  const owners = current.accounts ?? {};
  const named = change.accounts ?? {};
  const owner = (id: string) => owners[id] ?? "";
  const stored = current.core.some((id) => owner(id) !== "");
  if (
    change.core !== null &&
    (stored || change.core.some((id) => named[id])) &&
    change.core.some((id) => !named[id])
  ) {
    return { ok: false, reason: "every passkey needs its account" };
  }
  const moved =
    change.core === null
      ? []
      : change.core.filter(
          (id) => current.core.includes(id) && (named[id] ?? "") !== owner(id),
        );
  const coreChanged =
    change.core !== null &&
    (!sameSet(change.core, current.core) || moved.length > 0);
  const need = quorum(current.core.length);
  const strict =
    need === 2 &&
    new Set(current.core.map(owner).filter((account) => account !== "")).size >
      1 &&
    !approvers.some((id) => unsynced.includes(id));
  if (coreChanged && approvers.length < need) {
    const missing = need - approvers.length;
    return {
      ok: false,
      reason: `needs ${missing} more approval${missing === 1 ? "" : "s"}${strict ? `, ${OTHER_ACCOUNT}` : ""}`,
    };
  }
  if (
    moved.some(
      (id) =>
        owner(id) !== "" &&
        !approvers.some((approver) => owner(approver) === owner(id)),
    )
  ) {
    return {
      ok: false,
      reason: "needs approval from a passkey of the account it leaves",
    };
  }
  if (coreChanged && strict && new Set(approvers.map(owner)).size < 2) {
    return {
      ok: false,
      reason:
        "needs approval from another account's passkey, or from one that is not synced",
    };
  }
  for (const id of change.access) {
    if (current.access.includes(id)) continue;
    const others = approvers.filter((approver) => approver !== id);
    if (others.some((approver) => current.access.includes(approver))) continue;
    if (current.access.some((member) => member !== id)) {
      return { ok: false, reason: WITH_ACCESS };
    }
    const need = Math.max(
      1,
      Math.min(
        quorum(current.core.length),
        current.core.filter((member) => member !== id).length,
      ),
    );
    if (others.length < need) {
      return {
        ok: false,
        reason: `needs approval from ${need === 1 ? "another trusted device" : "two other trusted devices"}`,
      };
    }
  }
  for (const id of current.access) {
    if (change.access.includes(id)) continue;
    if (coreChanged && !core.includes(id)) continue;
    if (
      !approvers.some(
        (approver) => approver === id || current.access.includes(approver),
      )
    ) {
      return { ok: false, reason: WITH_ACCESS };
    }
  }
  return { ok: true };
}
