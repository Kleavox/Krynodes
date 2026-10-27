import { useEffect, useRef, useState } from "react";
import {
  agentHasFeatures,
  dnsName,
  NETWORK,
  type NetworkInspect,
} from "@krynodes/protocol";

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
import { useDevices, useNetworkNext, useRequestAgentUpdate } from "@/lib/api";
import { agentState } from "@/lib/agent";
import { signersFor } from "@/lib/devices";
import { capitalize, parseTimestamp } from "@/lib/format";
import {
  candidateState,
  checkRows,
  heldNote,
  LEGEND,
  linkProgress,
  pickMtu,
  pickRange,
  portLine,
  preparedOf,
  presenceOf,
  probeOf,
  probePlan,
  progressRows,
  seatOf,
  type Joining,
} from "@/lib/network";
import { errorLine, isPending, runningText } from "@/lib/services";
import { cn } from "@/lib/utils";
import type { NetworkView, NodeRecord, ServicesResponse } from "@/types";

import { MarkRows } from "./sections";
import {
  clearJoin,
  finishJoin,
  useAsk,
  useJoin,
  useStartJoin,
  type Job,
  type JoinSeat,
} from "./use-network-sign";

type Kind = "create" | "add";

const QUIET = new Set(["inspect", "probe"]);

const TITLE: Record<Kind, string> = {
  create: "Create Network",
  add: "Add Server",
};

const STATE_TONE = (text: string) =>
  text.startsWith("Ready")
    ? "text-success"
    : /to fix$/u.test(text)
      ? "text-warning"
      : "text-muted-foreground";

export function JoinDialog({
  kind,
  nodes,
  services,
  view,
  ranges,
  release,
  preset,
  now,
  onClose,
}: {
  kind: Kind;
  nodes: NodeRecord[];
  services: ServicesResponse | undefined;
  view: NetworkView;
  ranges: string[];
  release: string | null;
  preset?: string;
  now: number;
  onClose: () => void;
}) {
  const job = useJoin();
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[512px]")}>
        {job ? (
          <Progress job={job} view={view} nodes={nodes} now={now} />
        ) : (
          <Picker
            kind={kind}
            nodes={nodes}
            services={services}
            view={view}
            ranges={ranges}
            release={release}
            preset={preset}
            now={now}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function Picker({
  kind,
  nodes,
  services,
  view,
  ranges,
  release,
  preset,
  now,
}: {
  kind: Kind;
  nodes: NodeRecord[];
  services: ServicesResponse | undefined;
  view: NetworkView;
  ranges: string[];
  release: string | null;
  preset?: string;
  now: number;
}) {
  const devices = useDevices();
  const update = useRequestAgentUpdate();
  const start = useStartJoin();
  const inspect = useAsk<NetworkInspect>("inspect");
  const probe = useAsk<{ listened: boolean; arrived: string[] }>("probe");
  const [details, setDetails] = useState<string | null>(null);
  const presence = presenceOf(nodes, now);
  const reports = new Map(
    (services?.nodes ?? []).map((entry) => [entry.id, entry]),
  );
  const taken = new Set(view.members.map((member) => member.nodeId));
  const waiting = new Map(view.waiting.map((entry) => [entry.nodeId, entry]));
  const candidates = nodes.filter((node) => !taken.has(node.id));
  const eligible = (node: NodeRecord) =>
    presence[node.id]?.online === true && agentHasFeatures(node.agent_version);
  const [picked, setPicked] = useState<string[]>(() =>
    preset
      ? [preset]
      : kind === "create"
        ? candidates.filter(eligible).map((node) => node.id)
        : [],
  );
  const asked = useRef(false);
  const probed = useRef("");

  useEffect(() => {
    if (asked.current) return;
    asked.current = true;
    inspect.ask(
      candidates.filter(eligible).map((node) => ({ nodeId: node.id })),
    );
  });

  const seats = new Map(
    candidates.map((node) => [node.id, seatOf(node, reports.get(node.id))]),
  );
  const found = (id: string) => inspect.answers[id]?.value ?? null;
  const portOf = (id: string) =>
    waiting.get(id)?.port ?? found(id)?.port ?? null;
  const live = view.network;
  const range =
    live?.range ??
    pickRange(
      picked.map((id) => found(id)?.used ?? []),
      ranges,
    );
  const mtu = live?.mtu ?? pickMtu(picked.map((id) => found(id)?.mtu ?? null));
  const members = view.members
    .filter((member) => member.state === "in")
    .map((member) => {
      const node = nodes.find((entry) => entry.id === member.nodeId);
      return {
        nodeId: member.nodeId,
        name: member.name,
        publicAddress: node
          ? seatOf(node, reports.get(node.id)).publicAddress
          : null,
        nat: true,
        port: member.port,
      };
    });
  const listeners = [
    ...picked.flatMap((id) => {
      const seat = seats.get(id);
      return seat ? [{ ...seat, port: portOf(id) }] : [];
    }),
    ...members,
  ];
  const plan = probePlan(listeners);
  const probeAnswers = Object.fromEntries(
    Object.entries(probe.answers).map(([id, answer]) => [
      id,
      answer.value ?? undefined,
    ]),
  );
  const inspected = picked.every((id) => found(id) !== null || waiting.has(id));
  const pickedKey = [...picked].sort().join(",");

  useEffect(() => {
    if (!inspected || pickedKey === probed.current || plan.length === 0) {
      return;
    }
    probed.current = pickedKey;
    probe.ask(plan);
  });

  const rowsOf = (id: string) => {
    const seat = seats.get(id);
    const inspected = found(id);
    if (!seat || !inspected || !range) return null;
    const listener = listeners.find((entry) => entry.nodeId === id);
    return checkRows(
      inspected,
      seat,
      { range, mtu },
      listener ? probeOf(listener, listeners, plan, probeAnswers) : null,
    );
  };
  const next = useNetworkNext(
    kind === "add" ? picked : [],
    kind === "add" ? undefined : (range ?? undefined),
  );
  const addressOf = (id: string) =>
    next.data?.addresses.find((entry) => entry.nodeId === id) ?? null;
  const port = portLine(
    live?.port ?? NETWORK.port,
    picked.map((id) => ({
      name: seats.get(id)?.name ?? "",
      port: portOf(id),
      others: found(id)?.others ?? [],
    })),
  );

  const shown = details ? candidates.find((node) => node.id === details) : null;
  if (shown) {
    const rows = rowsOf(shown.id) ?? [];
    const fixes = rows.some((row) => row.mark === "✕");
    return (
      <>
        <DialogHeader>
          <button
            type="button"
            onClick={() => setDetails(null)}
            className="w-fit text-left text-sm text-muted-foreground hover:text-foreground"
          >
            ‹ {TITLE[kind]}
          </button>
          <DialogTitle>{shown.name}, before it joins</DialogTitle>
        </DialogHeader>
        <MarkRows
          rows={rows}
          onAgain={() => probe.ask(plan)}
          againing={
            probe.sending ||
            Object.values(probe.answers).some((answer) => answer.waiting)
          }
        />
        <p className="text-xs text-muted-foreground">
          {LEGEND}
          {fixes &&
            ` ${shown.name} can still join; its links come up once it is fixed.`}
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={() => setDetails(null)}>
            ‹ Back
          </Button>
        </DialogFooter>
      </>
    );
  }

  const ready = picked.length > 0 && inspected && range !== null;
  const go = () => {
    const trust = new Map(
      (services?.nodes ?? []).map((entry) => [entry.id, entry.trust]),
    );
    const everyone = [...picked, ...members.map((member) => member.nodeId)];
    const joining: JoinSeat[] = picked.map((id) => {
      const seat = seats.get(id)!;
      const prepared = waiting.get(id);
      const listener = listeners.find((entry) => entry.nodeId === id);
      const heard = listener
        ? probeOf(listener, listeners, plan, probeAnswers)
        : null;
      return {
        ...seat,
        port: portOf(id) ?? NETWORK.port,
        tools: found(id)?.tools === false,
        waitingFor:
          heard && !heard.arrived ? `UDP ${portOf(id)} to open` : null,
        ...(prepared
          ? {
              prepared: {
                key: prepared.key,
                signer: prepared.signer,
                port: prepared.port,
                mtu: prepared.mtu,
              },
            }
          : {}),
      };
    });
    start.mutate({
      kind,
      range: range!,
      port: live?.port ?? NETWORK.port,
      mtu,
      seats: joining,
      signers: signersFor(
        devices.data?.devices ?? [],
        everyone.map((id) => trust.get(id) ?? null),
      ),
      sealKeys: Object.fromEntries(
        (services?.nodes ?? []).flatMap((entry) =>
          entry.sealKey ? [[entry.id, entry.sealKey]] : [],
        ),
      ),
    });
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>{TITLE[kind]}</DialogTitle>
        <DialogDescription>
          {kind === "create"
            ? "Pick the servers that join. Others can join later."
            : "Pick the servers that join. The others learn their keys in the same step."}
        </DialogDescription>
      </DialogHeader>
      {candidates.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          Every server is already in the network.
        </p>
      ) : (
        <ul className="divide-y rounded-lg border bg-card">
          {candidates.map((node) => {
            const seat = seats.get(node.id)!;
            const online = presence[node.id]?.online === true;
            const error = inspect.answers[node.id]?.error ?? null;
            const running = services?.actions.find(
              (action) =>
                action.nodeId === node.id &&
                action.kind === "network" &&
                isPending(action) &&
                !QUIET.has(action.action),
            );
            const state = !online
              ? { text: "Offline", details: false, joinable: false }
              : running
                ? {
                    text: capitalize(runningText(running)),
                    details: false,
                    joinable: false,
                  }
                : error
                  ? { text: error, details: false, joinable: false }
                  : waiting.has(node.id) && !found(node.id)
                    ? { text: "Ready", details: false, joinable: true }
                    : candidateState(node.agent_version, rowsOf(node.id));
            const on = picked.includes(node.id);
            const gets = on ? addressOf(node.id) : null;
            const old = !agentHasFeatures(node.agent_version);
            const updatable =
              old &&
              release !== null &&
              ["available", "failed"].includes(agentState(node, release, now));
            return (
              <li
                key={node.id}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3.5 py-2.5 text-sm"
              >
                <input
                  type="checkbox"
                  aria-label={`${node.name} joins`}
                  className="size-4 accent-primary"
                  checked={on}
                  disabled={!state.joinable && !on}
                  onChange={(event) =>
                    setPicked((current) =>
                      event.target.checked
                        ? [...current, node.id]
                        : current.filter((id) => id !== node.id),
                    )
                  }
                />
                <span className="min-w-0 flex-1">
                  <span className="font-medium">{node.name}</span>{" "}
                  <span className="font-mono text-xs text-muted-foreground">
                    {seat.nat ? "Behind NAT" : (seat.publicAddress ?? "--")}
                  </span>
                  {kind === "add" && on && (
                    <span className="block font-mono text-xs text-muted-foreground">
                      {gets
                        ? `Gets ${gets.address} · ${dnsName(node.name)}.kry`
                        : "Gets --"}
                    </span>
                  )}
                </span>
                <span className={cn("text-xs", STATE_TONE(state.text))}>
                  {state.text}
                </span>
                {state.details && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 md:h-7"
                    onClick={() => setDetails(node.id)}
                  >
                    Details
                  </Button>
                )}
                {updatable && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 md:h-7"
                    disabled={update.isPending}
                    onClick={() => update.mutate(node.id)}
                  >
                    Update Agent
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {kind === "create" ? (
        <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
          <dt className="font-mono text-xs text-muted-foreground">Addresses</dt>
          <dd>
            {range ? (
              <>
                <span className="font-mono text-xs">{range}</span>{" "}
                <span className="text-xs text-muted-foreground">
                  · free on every server
                </span>
              </>
            ) : picked.length > 0 && inspected ? (
              <span className="text-xs text-destructive">
                Every range from 10.88.0.0/24 to 10.88.255.0/24 is in use here.
              </span>
            ) : (
              <span className="font-mono text-xs text-muted-foreground">
                --
              </span>
            )}
          </dd>
          <dt className="font-mono text-xs text-muted-foreground">Port</dt>
          <dd>
            <span className="font-mono text-xs">{port.port}</span>
            {port.note && (
              <span className="text-xs text-muted-foreground">
                {" "}
                · {port.note}
              </span>
            )}
          </dd>
        </dl>
      ) : (
        heldNote(view) && (
          <p className="text-xs text-muted-foreground">{heldNote(view)}</p>
        )
      )}
      <Said
        text={inspect.error ?? probe.error ?? start.error?.message ?? null}
      />
      <DialogFooter>
        <DialogClose asChild>
          <Button variant="outline">Cancel</Button>
        </DialogClose>
        <SignButton
          label={kind === "create" ? "Create" : "Add"}
          pending={start.isPending}
          disabled={!ready}
          onClick={go}
        />
      </DialogFooter>
    </>
  );
}

function Progress({
  job,
  view,
  nodes,
  now,
}: {
  job: Job;
  view: NetworkView;
  nodes: NodeRecord[];
  now: number;
}) {
  const presence = presenceOf(nodes, now);
  const others = view.members.filter(
    (member) =>
      member.state === "in" &&
      !job.seats.some((seat) => seat.nodeId === member.nodeId),
  ).length;
  const joining: Joining[] = job.seats.map((seat) => {
    const action = job.actions[seat.nodeId];
    const prepared = seat.prepared ?? (action ? preparedOf(action) : null);
    const ended = action !== undefined && !isPending(action);
    const entry = view.live[seat.nodeId];
    const up =
      job.phase === "done" &&
      job.postedAt !== null &&
      entry !== undefined &&
      entry.at >= job.postedAt;
    const answered =
      entry?.links.some(
        (link) =>
          link.handshake !== null &&
          now / 1000 - link.handshake < NETWORK.answerSeconds,
      ) ?? false;
    const lonely = job.seats.length + others <= 1;
    return {
      name: seat.name,
      address: job.addresses[seat.nodeId] ?? "--",
      port: seat.port,
      tools: seat.tools,
      status:
        ended && !prepared
          ? "failed"
          : up
            ? answered || lonely
              ? "up"
              : "waiting"
            : "working",
      seconds:
        action?.sentAt && action.finishedAt
          ? Math.max(
              1,
              Math.round(
                (parseTimestamp(action.finishedAt) -
                  parseTimestamp(action.sentAt)) /
                  1000,
              ),
            )
          : null,
      ...(seat.waitingFor ? { waiting: seat.waitingFor } : {}),
      ...(ended && !prepared
        ? { failure: errorLine(action.output) ?? "It did not get ready." }
        : {}),
    };
  });
  const rows = progressRows(joining);
  const title =
    job.kind === "create"
      ? "Creating Private Network"
      : "Adding to Private Network";
  return (
    <>
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>
          Closing this does not stop it. Progress stays on the Network page.
        </DialogDescription>
      </DialogHeader>
      <ul className="divide-y rounded-lg border bg-card">
        {rows.map((row) => (
          <li
            key={row.name}
            className="flex items-start gap-2.5 px-3.5 py-2.5 text-sm"
          >
            <span
              aria-hidden="true"
              className={cn(
                "w-4 shrink-0 text-center font-bold",
                row.mark === "✓"
                  ? "text-success"
                  : row.mark === "✕"
                    ? "text-destructive"
                    : "text-warning",
              )}
            >
              {row.mark}
            </span>
            <span className="min-w-0 flex-1">
              <span className="font-medium">{row.name}</span>
              <span className="block text-xs break-words text-muted-foreground">
                {row.text}
              </span>
            </span>
            {row.time && (
              <span className="font-mono text-xs text-muted-foreground">
                {row.time}
              </span>
            )}
          </li>
        ))}
        {job.phase === "done" && (
          <li className="px-3.5 py-2.5 text-sm">
            {linkProgress(
              view,
              presence,
              [
                ...job.seats.map((seat) => seat.nodeId),
                ...view.members.map((member) => member.nodeId),
              ],
              now,
            )}
          </li>
        )}
      </ul>
      <Said text={job.error} />
      <DialogFooter>
        {job.phase === "sign" && (
          <SignButton
            label="Finish"
            pending={false}
            onClick={() => void finishJoin()}
          />
        )}
        <DialogClose asChild>
          <Button
            variant="outline"
            onClick={() => {
              if (job.phase === "done" || job.phase === "failed") clearJoin();
            }}
          >
            Close
          </Button>
        </DialogClose>
      </DialogFooter>
    </>
  );
}
