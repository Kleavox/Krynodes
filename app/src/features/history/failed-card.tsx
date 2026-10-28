import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { RowMenu } from "@/components/row-menu";
import { Button } from "@/components/ui/button";
import type { DeployRequest } from "@/features/deploy/deploy-dialog";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { Lines as PackageLines } from "@/features/packages/lines";
import type { ActionRequest } from "@/features/services/action-dialog";
import { useLogsRead, type LogsTarget } from "@/features/services/logs-dialog";
import { useDevices, useHideAction, useServices } from "@/lib/api";
import { agentCurrent } from "@/lib/devices";
import {
  actionLine,
  causedText,
  lastLines,
  logTargets,
  retryOf,
} from "@/lib/history";
import { aptOutput, historyLines, retryDialog } from "@/lib/packages";
import { displayName } from "@/lib/services";
import { deployBlocker, groupStacks } from "@/lib/stacks";
import { cn } from "@/lib/utils";
import type { AttentionItem, NodeRecord } from "@/types";

const SHOWN = 12;

function Lines({ text, empty }: { text: string | null; empty: string }) {
  const [all, setAll] = useState(false);
  if (!text?.trim()) {
    return <p className="font-mono text-xs text-muted-foreground">{empty}</p>;
  }
  const tail = lastLines(text, SHOWN);
  return (
    <div className="space-y-1">
      <pre
        tabIndex={0}
        className="max-h-72 min-w-0 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere]"
      >
        {all ? text : tail.text}
      </pre>
      {tail.hidden > 0 && (
        <Button
          variant="link"
          size="sm"
          className="h-auto px-0 font-mono text-xs"
          onClick={() => setAll(!all)}
        >
          {all
            ? `Last ${SHOWN} lines`
            : `Show all ${tail.hidden + SHOWN} lines`}
        </Button>
      )}
    </div>
  );
}

function LogsTab({ target }: { target: LogsTarget }) {
  const { waiting, output, problem, action, fetchLogs } = useLogsRead(target);
  return (
    <div className="space-y-1">
      {waiting ? (
        <p className="font-mono text-xs text-muted-foreground">
          Reading the last 300 lines from {target.nodeName}…
        </p>
      ) : problem ? (
        <p role="alert" className="font-mono text-xs text-destructive">
          {problem}
        </p>
      ) : (
        <Lines text={output} empty="No log lines." />
      )}
      {!waiting && action && (
        <Button
          variant="link"
          size="sm"
          className="h-auto px-0 font-mono text-xs"
          onClick={fetchLogs}
        >
          Read Again
        </Button>
      )}
    </div>
  );
}

export function FailedCard({
  item,
  nodes,
  onRequest,
  onDeploy,
}: {
  item: AttentionItem;
  nodes: NodeRecord[];
  onRequest: (request: ActionRequest) => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const { action, incident } = item;
  const services = useServices();
  const devices = useDevices().data?.devices;
  const hide = useHideAction();
  const run = useSignedAction();
  const navigate = useNavigate();
  const [tab, setTab] = useState("output");
  const [opened, setOpened] = useState<string[]>([]);
  const node = nodes.find((entry) => entry.id === action.nodeId);
  const inventory = services.data?.nodes.find(
    (entry) => entry.id === action.nodeId,
  );
  const line = actionLine(action, {
    nodeName: node?.name,
    showServer: true,
    devices,
    stacks: inventory?.stacks,
    names: Object.fromEntries(nodes.map((entry) => [entry.id, entry.name])),
  });
  const logs =
    inventory && node && agentCurrent(node)
      ? logTargets(action, inventory).map((target) => ({
          key: `${target.kind}:${target.name}`,
          label: `${displayName(target.kind, target.name)} logs`,
          target: { ...target, nodeId: node.id, nodeName: node.name },
        }))
      : [];
  const member =
    action.kind === "compose" && services.data
      ? groupStacks(services.data, nodes, "")
          .find((group) => group.project === action.name)
          ?.members.find((entry) => entry.node.id === action.nodeId)
      : undefined;
  const ready = member && deployBlocker(member) === null ? member : undefined;
  const trusted = (inventory?.trust?.access.length ?? 0) > 0;
  const retry = retryOf(action);
  const kind =
    action.kind === "docker" || action.kind === "systemd" ? action.kind : null;
  const target =
    kind && node
      ? { nodeId: node.id, nodeName: node.name, kind, name: action.name }
      : null;
  let tryAgain: (() => void) | undefined;
  if (retry?.via === "deploy" || retry?.via === "rollback") {
    const via = retry.via;
    if (ready) {
      tryAgain = () =>
        onDeploy({ action: via, project: action.name, members: [ready] });
    }
  } else if (retry?.via === "run" && trusted) {
    const verb = retry.action;
    tryAgain = () =>
      run.mutate({
        action: verb,
        targets: [
          { nodeId: action.nodeId, kind: action.kind, name: action.name },
        ],
      });
  } else if (retry?.via === "confirm" && trusted && target) {
    const verb = retry.action;
    tryAgain = () => onRequest({ action: verb, target });
  } else if (
    retry?.via === "packages" &&
    (inventory?.trust?.core.length ?? 0) > 0
  ) {
    const dialog = retryDialog(action);
    tryAgain = () =>
      void navigate(`/nodes/${action.nodeId}/packages`, { state: { dialog } });
  }
  const rollBack =
    action.action === "deploy" && ready?.stack.rollback
      ? () =>
          onDeploy({
            action: "rollback",
            project: action.name,
            members: [ready],
          })
      : undefined;
  const open = (key: string) => {
    setTab(key);
    if (key !== "output" && key !== "changed" && !opened.includes(key)) {
      setOpened([...opened, key]);
    }
  };
  const changed = historyLines(action, node?.name ?? "");
  const tabs = [
    { key: "output", label: "Output" },
    ...(changed ? [{ key: "changed", label: "What Changed" }] : []),
    ...logs,
  ];

  return (
    <article className="space-y-2 rounded-lg border border-destructive/40 bg-card p-3">
      <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
        <div className="min-w-0">
          <h3 className="text-sm font-medium">{line.text}</h3>
          <p className="font-mono text-xs text-muted-foreground">
            {[
              node ? `On ${node.name}` : null,
              line.time,
              line.device,
              line.duration,
            ]
              .filter(Boolean)
              .join(" · ")}
            {action.exitCode !== null && (
              <span className="text-destructive">
                {" "}
                · Exit {action.exitCode}
              </span>
            )}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {tryAgain && (
            <Button
              variant={rollBack ? "outline" : "default"}
              size="sm"
              className="h-9 md:h-8"
              disabled={run.isPending}
              onClick={tryAgain}
            >
              Try Again
            </Button>
          )}
          {rollBack && (
            <Button size="sm" className="h-9 md:h-8" onClick={rollBack}>
              Roll Back
            </Button>
          )}
          <RowMenu
            label={`${line.text} actions`}
            items={[{ label: "Hide", onSelect: () => hide.mutate(action.id) }]}
          />
        </div>
      </div>
      <div
        role="tablist"
        aria-label={`What ${line.text} left`}
        className="flex gap-1 overflow-x-auto border-b"
      >
        {tabs.map((entry) => (
          <button
            key={entry.key}
            type="button"
            role="tab"
            aria-selected={tab === entry.key}
            onClick={() => open(entry.key)}
            className={cn(
              "-mb-px h-8 shrink-0 border-b-2 border-transparent px-2 font-mono text-xs text-muted-foreground hover:text-foreground",
              tab === entry.key && "border-primary text-foreground",
            )}
          >
            {entry.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" hidden={tab !== "output"}>
        <Lines
          text={aptOutput(action)}
          empty={
            action.status === "expired"
              ? "It expired before the server took it. Nothing ran."
              : (line.failure ?? "Nothing was printed.")
          }
        />
      </div>
      {changed && (
        <div role="tabpanel" hidden={tab !== "changed"}>
          <PackageLines lines={changed} className="space-y-1 text-xs" />
        </div>
      )}
      {logs
        .filter((entry) => opened.includes(entry.key))
        .map((entry) => (
          <div key={entry.key} role="tabpanel" hidden={tab !== entry.key}>
            <LogsTab target={entry.target} />
          </div>
        ))}
      {incident && (
        <Link
          to={`/incidents/${incident.id}`}
          className="flex flex-wrap items-baseline justify-between gap-x-3 rounded-md border border-destructive/30 bg-destructive/5 px-2.5 py-1.5 text-xs hover:border-destructive/60"
        >
          <span className="font-mono">{causedText(incident, Date.now())}</span>
          <span className="font-mono text-primary">Incident →</span>
        </Link>
      )}
    </article>
  );
}
