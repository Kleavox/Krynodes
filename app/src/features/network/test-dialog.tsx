import { useEffect, useRef, useState } from "react";
import type { NetworkTest } from "@krynodes/protocol";

import { Busy } from "@/components/busy";
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
import { Said, SHEET, SignButton } from "@/features/packages/lines";
import { postNetworkTest, useServices } from "@/lib/api";
import { formatDuration } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import {
  fixLabel,
  mostLikely,
  networkText,
  seatOf,
  testEnd,
  testingText,
  testOthers,
  testRows,
  testSummary,
  type Presence,
  type TestFix,
} from "@/lib/network";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import type { NetworkServer, NetworkView, NodeRecord } from "@/types";

import { MarkRows } from "./sections";
import {
  testPair,
  useNetworkKeys,
  useSignChange,
  type Change,
} from "./use-network-sign";

type Pair = [NetworkServer, NetworkServer];

interface Outcome {
  results: Record<string, NetworkTest | null>;
  took: number;
  error: string | null;
}

const keyOf = ([a, b]: Pair) => `${a.nodeId}:${b.nodeId}`;

export function TestDialog({
  title,
  pairs,
  view,
  presence,
  nodes,
  onClose,
}: {
  title: string;
  pairs: Pair[];
  view: NetworkView;
  presence: Presence;
  nodes: NodeRecord[];
  onClose: () => void;
}) {
  const now = useNow(1_000);
  const reports = useServices().data?.nodes ?? [];
  const keys = useNetworkKeys(view.members);
  const [run, setRun] = useState(0);
  const [outcomes, setOutcomes] = useState<Record<string, Outcome>>({});
  const [current, setCurrent] = useState<{ key: string; at: number } | null>(
    null,
  );
  const [fixed, setFixed] = useState<Set<string>>(new Set());
  const sent = useRef<string | null>(null);
  const alive = useRef(true);
  const mtu = view.network?.mtu ?? 1420;
  const online = (id: string) => presence[id]?.online === true;
  const pairsKey = pairs.map(keyOf).join(",");

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  useEffect(() => {
    const token = `${run}:${pairsKey}`;
    if (sent.current === token) return;
    sent.current = token;
    const stopped = () => !alive.current || sent.current !== token;
    const all = async () => {
      for (const pair of pairs) {
        const [a, b] = pair;
        if (stopped()) return;
        if (!online(a.nodeId) || !online(b.nodeId)) continue;
        const started = Date.now();
        setCurrent({ key: keyOf(pair), at: started });
        let outcome: Outcome;
        try {
          const results = await testPair(
            [
              { nodeId: a.nodeId, peer: b.nodeId, address: b.address ?? "" },
              { nodeId: b.nodeId, peer: a.nodeId, address: a.address ?? "" },
            ],
            Math.min(mtu, a.mtu ?? mtu, b.mtu ?? mtu),
          );
          outcome = { results, took: Date.now() - started, error: null };
        } catch (error) {
          outcome = { results: {}, took: 0, error: errorMessage(error) };
        }
        if (stopped()) return;
        setOutcomes((all) => ({ ...all, [keyOf(pair)]: outcome }));
        if (!outcome.error) {
          const { rows, likely } = judge(pair, outcome);
          void postNetworkTest({
            change: networkText.test(a.name, b.name),
            detail: testSummary(rows, likely.fix),
            nodes: [a.nodeId, b.nodeId],
          }).catch(() => undefined);
        }
      }
      if (!stopped()) setCurrent(null);
    };
    void all();
  }, [run, pairsKey]);

  const firewallOf = (id: string) => {
    const node = nodes.find((entry) => entry.id === id);
    return node
      ? seatOf(
          node,
          reports.find((entry) => entry.id === id),
        ).firewall
      : null;
  };

  function judge(pair: Pair, outcome: Outcome | undefined) {
    const offline = pair.find((end) => !online(end.nodeId));
    const ordered = offline
      ? ([offline, pair.find((end) => end !== offline)!] as Pair)
      : pair;
    const [first, second] = ordered.map((member) =>
      testEnd(
        member,
        presence,
        now,
        { firewall: firewallOf(member.nodeId) },
        offline ? null : (outcome?.results[member.nodeId] ?? null),
      ),
    ) as [ReturnType<typeof testEnd>, ReturnType<typeof testEnd>];
    const network = {
      version: view.version,
      mtu: Math.min(mtu, pair[0].mtu ?? mtu, pair[1].mtu ?? mtu),
    };
    return {
      rows: testRows(first, second, network),
      likely: mostLikely(
        first,
        second,
        network,
        testOthers(view, pair[0].nodeId, pair[1].nodeId),
      ),
    };
  }

  const changeFor = (pair: Pair, chosen: TestFix): Omit<Change, "signers"> => {
    const named = pair.find(
      (member) => "nodeId" in chosen && member.nodeId === chosen.nodeId,
    );
    if (chosen.kind === "mtu") {
      return {
        change: { kind: "mtu", nodeId: chosen.nodeId, mtu: chosen.size },
        text: networkText.mtu(named?.name ?? "--", chosen.size),
      };
    }
    return {
      change: { kind: "again" },
      text:
        chosen.kind === "rule"
          ? networkText.rule(named?.name ?? "--")
          : networkText.again,
    };
  };

  const running = current !== null;
  const took = Object.values(outcomes).reduce(
    (sum, outcome) => sum + outcome.took,
    0,
  );
  const runningPair = pairs.find((pair) => keyOf(pair) === current?.key);
  const single = pairs.length === 1;

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[560px]")}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            Test Link reads both servers and changes nothing.
            {running && runningPair
              ? ` ${testingText(runningPair[0].name, runningPair[1].name, now - current.at)}.`
              : took > 0
                ? ` Took ${formatDuration(took)}.`
                : ""}
          </DialogDescription>
        </DialogHeader>
        {pairs.length === 0 && (
          <p className="text-sm text-muted-foreground">
            There is no other server to test with.
          </p>
        )}
        {pairs.map((pair) => {
          const key = keyOf(pair);
          const outcome = outcomes[key];
          const offline = pair.some((end) => !online(end.nodeId));
          if (!offline && !outcome) {
            return (
              <section key={key} className="space-y-2">
                {!single && <PairName pair={pair} />}
                <p className="text-sm text-muted-foreground">
                  {current?.key === key ? (
                    <Busy>Testing</Busy>
                  ) : (
                    <Busy>Waiting its turn</Busy>
                  )}
                </p>
              </section>
            );
          }
          if (outcome?.error) {
            return (
              <section key={key} className="space-y-2">
                {!single && <PairName pair={pair} />}
                <Said text={outcome.error} />
              </section>
            );
          }
          const { rows, likely } = judge(pair, outcome);
          const fine = !rows.some((row) => row.mark === "✕");
          return (
            <section key={key} className="space-y-2">
              {!single && <PairName pair={pair} />}
              {(single || !fine) && <MarkRows rows={rows} />}
              <div className="rounded-lg border bg-muted/40 px-3.5 py-3 text-sm">
                {(single || !fine) && (
                  <p className="mb-1 text-xs font-medium text-muted-foreground">
                    Most Likely
                  </p>
                )}
                <p>{likely.text}</p>
                {likely.detail && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {likely.detail}
                  </p>
                )}
                {likely.fix && (
                  <FixRow
                    label={fixLabel(likely.fix)}
                    change={{
                      ...changeFor(pair, likely.fix),
                      detail: likely.text,
                      signers: keys.signers,
                    }}
                    fixed={fixed.has(key)}
                    onFixed={() =>
                      setFixed((current) => new Set(current).add(key))
                    }
                  />
                )}
              </div>
            </section>
          );
        })}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Close</Button>
          </DialogClose>
          <Button
            disabled={running || pairs.length === 0}
            onClick={() => {
              setOutcomes({});
              setFixed(new Set());
              setRun((count) => count + 1);
            }}
          >
            {running ? <Busy>Testing</Busy> : "Test Again"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function FixLine({
  label,
  fixed,
  pending,
  error,
  onFix,
}: {
  label: string;
  fixed: boolean;
  pending: boolean;
  error: string | null;
  onFix: () => void;
}) {
  return (
    <div className="mt-2 space-y-2">
      {fixed ? (
        <p role="status" className="text-xs text-success">
          Sent. Test again once the servers have it.
        </p>
      ) : (
        <SignButton label={label} pending={pending} onClick={onFix} />
      )}
      <Said text={error} />
    </div>
  );
}

function FixRow({
  label,
  change,
  fixed,
  onFixed,
}: {
  label: string;
  change: Change;
  fixed: boolean;
  onFixed: () => void;
}) {
  const fix = useSignChange();
  return (
    <FixLine
      label={label}
      fixed={fixed}
      pending={fix.isPending}
      error={fix.error?.message ?? null}
      onFix={() => fix.mutate(change, { onSuccess: onFixed })}
    />
  );
}

function PairName({ pair }: { pair: Pair }) {
  return (
    <h3 className="text-xs font-medium text-muted-foreground">
      {pair[0].name} ↔ {pair[1].name}
    </h3>
  );
}
