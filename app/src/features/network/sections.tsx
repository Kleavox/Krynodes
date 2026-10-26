import { Link } from "react-router";

import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useDevices, useNetworkNext } from "@/lib/api";
import { clockTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import {
  heldRows,
  networkFacts,
  problemRows,
  serverRow,
  waitingLine,
  type Mark,
  type Presence,
  type Row,
} from "@/lib/network";
import { actorOf } from "@/lib/operations";
import { cn } from "@/lib/utils";
import type { NetworkServer, NetworkView } from "@/types";

const sectionTitle = "mb-2 text-xs font-medium text-muted-foreground";
const card = "divide-y rounded-lg border bg-card";

const TONE: Record<Mark, string> = {
  "✓": "text-success",
  "+": "text-muted-foreground",
  "✕": "text-destructive",
  "!": "text-warning",
  "−": "text-destructive",
  "·": "text-muted-foreground",
  "…": "text-warning",
  "–": "text-muted-foreground",
};

export function MarkRows({
  rows,
  onAgain,
  againing = false,
}: {
  rows: Row[];
  onAgain?: () => void;
  againing?: boolean;
}) {
  return (
    <ul className={card}>
      {rows.map((row, index) => (
        <li
          key={`${index}:${row.text}`}
          className="flex items-start gap-2.5 px-3.5 py-2.5 text-sm"
        >
          <span
            aria-hidden="true"
            className={cn("w-4 shrink-0 text-center font-bold", TONE[row.mark])}
          >
            {row.mark}
          </span>
          <span className="min-w-0 flex-1 break-words">
            {row.text}
            {row.detail && (
              <span className="mt-0.5 block text-xs text-muted-foreground">
                {row.detail}
              </span>
            )}
          </span>
          {row.action === "edit" && row.nodeId && (
            <Button asChild variant="outline" size="sm" className="h-9 md:h-7">
              <Link to={`/nodes/${row.nodeId}`}>Edit Compose</Link>
            </Button>
          )}
          {row.action === "again" && onAgain && (
            <Button
              variant="outline"
              size="sm"
              className="h-9 md:h-7"
              disabled={againing}
              onClick={onAgain}
            >
              {againing ? "Checking…" : "Check Again"}
            </Button>
          )}
        </li>
      ))}
    </ul>
  );
}

export function ProblemsCard({
  view,
  presence,
  now,
  onTest,
}: {
  view: NetworkView;
  presence: Presence;
  now: number;
  onTest: (a: string, b: string) => void;
}) {
  const problems = problemRows(view, presence, now);
  if (problems.length === 0) return null;
  return (
    <ul className={cn(card, "border-destructive/40")}>
      {problems.map((problem) => (
        <li
          key={`${problem.a}-${problem.b}`}
          className="flex items-start gap-3 px-3.5 py-3 text-sm"
        >
          <StatusDot tone="bad" className="mt-1.5" />
          <span className="min-w-0 flex-1">
            <span className="font-medium">{problem.pair}</span>{" "}
            <span className="font-mono text-xs text-destructive">
              {problem.text}
            </span>
            <span className="block text-xs text-muted-foreground">
              {problem.detail}
            </span>
          </span>
          <Button
            variant="outline"
            size="sm"
            className="h-9 md:h-8"
            onClick={() => onTest(problem.a, problem.b)}
          >
            Test Link
          </Button>
        </li>
      ))}
    </ul>
  );
}

export function WaitingCard({
  view,
  onJoin,
}: {
  view: NetworkView;
  onJoin: (nodeId: string) => void;
}) {
  const next = useNetworkNext(view.waiting.map((server) => server.nodeId));
  const later = useSignedAction(false);
  if (view.waiting.length === 0) return null;
  return (
    <section className="space-y-2">
      <ul className={cn(card, "border-warning/40")}>
        {view.waiting.map((server) => {
          const line = waitingLine(
            server,
            next.data?.addresses.find((entry) => entry.nodeId === server.nodeId)
              ?.address ?? null,
          );
          return (
            <li
              key={server.nodeId}
              className="flex flex-wrap items-center gap-3 px-3.5 py-3 text-sm"
            >
              <StatusDot tone="warn" />
              <span className="min-w-0 flex-1">
                <span className="font-medium">{line.title}</span>
                <span className="block font-mono text-xs text-muted-foreground">
                  {line.state}
                </span>
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="h-9 md:h-8"
                disabled={later.isPending}
                onClick={() =>
                  later.mutate({
                    action: "unprepare",
                    mode: "parallel",
                    targets: [
                      { nodeId: server.nodeId, kind: "network", name: "kry0" },
                    ],
                  })
                }
              >
                Not Now
              </Button>
              <Button
                size="sm"
                className="h-9 md:h-8"
                onClick={() => onJoin(server.nodeId)}
              >
                Join
              </Button>
            </li>
          );
        })}
      </ul>
      {later.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(later.error)}
        </p>
      )}
    </section>
  );
}

export function ServersCard({
  view,
  presence,
  now,
  onOpen,
  onTest,
  onRemove,
}: {
  view: NetworkView;
  presence: Presence;
  now: number;
  onOpen: (server: NetworkServer) => void;
  onTest: (server: NetworkServer) => void;
  onRemove: (server: NetworkServer) => void;
}) {
  const members = view.members.filter((member) => member.state === "in");
  return (
    <section>
      <h2 className={sectionTitle}>Servers</h2>
      <ul className={card}>
        {members.map((member) => {
          const row = serverRow(member, view, presence, now);
          return (
            <li key={member.nodeId} className="flex items-center pr-2">
              <button
                type="button"
                onClick={() => onOpen(member)}
                className="grid min-w-0 flex-1 grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 px-3.5 py-3 text-left text-sm hover:bg-accent md:grid-cols-[minmax(0,1fr)_190px_110px]"
              >
                <span className="min-w-0">
                  <span className="flex items-center gap-2">
                    <StatusDot tone={row.offline ? "idle" : "ok"} />
                    <span className="font-medium">{row.name}</span>
                    <span className="truncate font-mono text-xs text-muted-foreground">
                      {row.address}
                    </span>
                  </span>
                  {row.offline && (
                    <span className="mt-0.5 block text-xs text-muted-foreground">
                      {row.offline}
                    </span>
                  )}
                </span>
                <span className="hidden truncate font-mono text-xs text-muted-foreground md:block">
                  {row.endpoint}
                </span>
                <span
                  className={cn(
                    "font-mono text-xs",
                    row.offline && "text-muted-foreground",
                    row.short && "text-warning",
                  )}
                >
                  {row.links}
                </span>
              </button>
              <RowMenu
                label={`More for ${member.name}`}
                items={[
                  { label: "Test Links", onSelect: () => onTest(member) },
                  {
                    label: "Remove from Network",
                    destructive: true,
                    onSelect: () => onRemove(member),
                  },
                ]}
              />
            </li>
          );
        })}
      </ul>
      <p className="mt-2 text-xs text-muted-foreground">
        An offline server is not counted in Links.
      </p>
    </section>
  );
}

export function ChangesCard({ view }: { view: NetworkView }) {
  const devices = useDevices().data?.devices;
  if (view.changes.length === 0) return null;
  return (
    <section>
      <h2 className={sectionTitle}>Recent Changes</h2>
      <ul className={card}>
        {view.changes.map((change) => (
          <li
            key={change.id}
            className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-1 px-3.5 py-2.5 text-sm sm:grid-cols-[auto_minmax(0,1fr)_auto]"
          >
            <span className="font-mono text-xs leading-5 text-muted-foreground">
              {clockTime(change.at)}
            </span>
            <span className="min-w-0 break-words">
              {change.change}
              {change.detail && (
                <span className="block font-mono text-xs text-muted-foreground">
                  {change.detail}
                </span>
              )}
            </span>
            <span className="col-start-2 font-mono text-xs text-muted-foreground sm:col-start-auto">
              {actorOf(change, devices)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ThisNetwork({
  view,
  presence,
  onTestAll,
  onKeys,
  onDelete,
}: {
  view: NetworkView;
  presence: Presence;
  onTestAll: () => void;
  onKeys: () => void;
  onDelete: () => void;
}) {
  return (
    <section>
      <div className="mb-1 flex items-center justify-between">
        <h2 className="text-xs font-medium text-muted-foreground">
          This Network
        </h2>
        <RowMenu
          label="More for this network"
          items={[
            { label: "Test All Links", onSelect: onTestAll },
            { label: "Make New Keys", onSelect: onKeys },
            { label: "Delete Network", destructive: true, onSelect: onDelete },
          ]}
        />
      </div>
      <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-3 gap-y-3.5 rounded-lg border bg-card p-3.5 text-sm">
        {networkFacts(view, presence).map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="font-mono text-xs text-muted-foreground">{label}</dt>
            <dd className="font-mono text-xs">{value}</dd>
          </div>
        ))}
        {heldRows(view).map((held) => (
          <div key={held} className="contents">
            <dt className="font-mono text-xs text-muted-foreground">Held</dt>
            <dd className="text-xs">{held}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-2 text-xs text-muted-foreground">
        Each server keeps its address for good. The range is also listed under
        Settings, Private Addresses.
      </p>
    </section>
  );
}
