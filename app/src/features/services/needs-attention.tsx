import { useState } from "react";
import { Link } from "react-router";

import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import type { DeployRequest } from "@/features/deploy/deploy-dialog";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { agentCurrent } from "@/lib/devices";
import { isPending, verb } from "@/lib/services";
import type { ServiceProblem } from "@/lib/stacks";
import { cn } from "@/lib/utils";

import { LogsDialog } from "./logs-dialog";
import { KindLabel, PendingText } from "./service-list";

export function ProblemFix({
  problem,
  onDeploy,
}: {
  problem: ServiceProblem;
  onDeploy: (request: DeployRequest) => void;
}) {
  const [reading, setReading] = useState(false);
  const run = useSignedAction();
  const { node, target, latest, stack } = problem;
  const act = () =>
    problem.primary === "rollback"
      ? onDeploy({
          action: "rollback",
          project: target.name,
          members: stack ? [stack] : [],
        })
      : run.mutate({ action: problem.primary, targets: [target] });
  return (
    <>
      {latest && isPending(latest) ? (
        <PendingText action={latest} nodeName={node.name} />
      ) : problem.blocker ? (
        problem.blocker === "Not trusted yet" ? (
          <Link
            to="/devices"
            className="font-mono text-xs text-warning underline-offset-4 hover:underline"
          >
            {problem.blocker}
          </Link>
        ) : (
          <span className="font-mono text-xs text-muted-foreground">
            {problem.blocker}
          </span>
        )
      ) : (
        <div className="flex shrink-0 items-center gap-1">
          {agentCurrent(node) && (
            <Button
              variant="outline"
              size="sm"
              className="h-9 md:h-8"
              aria-label={`Logs of ${problem.name} on ${node.name}`}
              onClick={() => setReading(true)}
            >
              Logs
            </Button>
          )}
          <Button
            size="sm"
            className="h-9 md:h-8"
            disabled={run.isPending}
            aria-label={`${verb(problem.primary)} ${problem.name} on ${node.name}`}
            onClick={act}
          >
            {verb(problem.primary)}
          </Button>
        </div>
      )}
      <LogsDialog target={target} open={reading} onOpenChange={setReading} />
    </>
  );
}

function ProblemRow({
  problem,
  onDeploy,
}: {
  problem: ServiceProblem;
  onDeploy: (request: DeployRequest) => void;
}) {
  const { node, stack } = problem;
  const down = stack
    ? stack.stack.running === 0
    : problem.state !== "Running" && problem.state !== "Starting";
  return (
    <li className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-3 py-2.5">
      <div className="min-w-0 space-y-0.5">
        <p className="flex flex-wrap items-center gap-x-1.5 text-sm">
          <span className="font-medium">{problem.name}</span>
          <KindLabel kind={problem.kind} />
          <span className="font-mono text-xs text-muted-foreground">
            on {node.name}
          </span>
          <span className="font-mono text-xs text-muted-foreground">·</span>
          <span
            className={cn(
              "font-mono text-xs",
              down ? "text-destructive" : "text-warning",
            )}
          >
            {problem.state}
          </span>
        </p>
        <p className="font-mono text-xs break-words text-muted-foreground">
          {problem.reason}
        </p>
      </div>
      <ProblemFix problem={problem} onDeploy={onDeploy} />
    </li>
  );
}

export function NeedsAttention({
  problems,
  onDeploy,
}: {
  problems: ServiceProblem[];
  onDeploy: (request: DeployRequest) => void;
}) {
  if (problems.length === 0) {
    return (
      <p className="flex items-center gap-2 rounded-lg border bg-card px-3 py-2.5 text-sm text-muted-foreground">
        <StatusDot tone="ok" />
        Nothing needs attention.
      </p>
    );
  }
  return (
    <section
      aria-labelledby="needs-attention"
      className="rounded-lg border border-destructive/40 bg-card"
    >
      <h2
        id="needs-attention"
        className="flex items-center gap-2 px-3 py-2.5 text-sm font-medium"
      >
        <StatusDot tone="bad" />
        Needs attention
        <span className="font-mono text-xs font-normal text-muted-foreground">
          {problems.length}
        </span>
      </h2>
      <ul className="divide-y border-t">
        {problems.map((problem) => (
          <ProblemRow
            key={`${problem.node.id}|${problem.kind}|${problem.target.name}`}
            problem={problem}
            onDeploy={onDeploy}
          />
        ))}
      </ul>
    </section>
  );
}
