import { useEffect, useState } from "react";
import {
  Link,
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router";

import { Busy } from "@/components/busy";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { PackageDialogs } from "@/features/packages/dialogs";
import type { PackagesDialog } from "@/features/packages/lines";
import {
  InstalledSection,
  OnTheirOwn,
  RestartCard,
  RunningJobs,
  SourcesSection,
  UpdatesSection,
} from "@/features/packages/sections";
import {
  useAskApt,
  useNodeActions,
  useOverview,
  usePackages,
  useRequestAgentUpdate,
  useServices,
} from "@/lib/api";
import { agentState } from "@/lib/agent";
import { canRestartServer } from "@/lib/devices";
import { errorMessage } from "@/lib/http";
import {
  agentNeeded,
  packagesBlocker,
  packagesHeader,
  runningPackages,
} from "@/lib/packages";
import { useNow } from "@/lib/use-now";

const notice = "mb-4 rounded-md border px-3 py-2 text-sm";

export function PackagesPage() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const overview = useOverview();
  const services = useServices();
  const packages = usePackages(id);
  const actions = useNodeActions(id);
  const refresh = useAskApt();
  const update = useRequestAgentUpdate();
  const now = useNow(5_000);
  const location = useLocation();
  const navigate = useNavigate();
  const asked = (location.state as { dialog?: PackagesDialog } | null)?.dialog;
  const [dialog, setDialog] = useState<PackagesDialog | null>(asked ?? null);

  useEffect(() => {
    if (!asked) return;
    void navigate(
      { pathname: location.pathname, search: location.search },
      { replace: true, state: null },
    );
  }, [asked, location.pathname, location.search, navigate]);

  const setParam = (key: string, value: string | null) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (value === null) next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: true },
    );

  if (!overview.data) {
    return (
      <>
        <PageHeader title="Packages" />
        <Skeleton className="h-96" />
      </>
    );
  }

  const node = overview.data.nodes.find((item) => item.id === id);
  if (!node) {
    return (
      <EmptyState
        title="Server Not Found"
        body="It may have been deleted."
        action={
          <Button asChild variant="outline">
            <Link to="/">Back to Fleet</Link>
          </Button>
        }
      />
    );
  }

  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const trust = entry?.trust ?? null;
  const trusted = (trust?.core.length ?? 0) > 0;
  const blocker = packagesBlocker(node, trusted, now);
  const header = packagesHeader(node, packages.data, now);
  const report = packages.data?.report ?? null;
  const apt = report?.apt ? report : null;
  const jobs = runningPackages(actions.data?.actions ?? [], node.id);
  const reason =
    blocker ??
    (jobs.length > 0 ? "Waits until the running job finishes" : null);
  const checking =
    refresh.isPending || jobs.some((job) => job.action === "refresh");
  const needed = agentNeeded(node);
  const release = overview.data.agentRelease.version;
  const updatable =
    release !== null &&
    ["available", "failed"].includes(agentState(node, release, now));

  return (
    <>
      <PageHeader
        crumb={
          <>
            <Link to="/" className="hover:underline">
              Fleet
            </Link>{" "}
            /{" "}
            <Link to={`/nodes/${node.id}`} className="hover:underline">
              {node.name}
            </Link>{" "}
            / Packages
          </>
        }
        title="Packages"
        actions={
          apt && (
            <>
              <Button
                variant="outline"
                size="sm"
                className="h-9 md:h-8"
                disabled={reason !== null || checking}
                title={reason ?? undefined}
                onClick={() =>
                  refresh.mutate({
                    nodeId: node.id,
                    action: "refresh",
                    name: "system",
                  })
                }
              >
                {checking ? <Busy>Checking</Busy> : "Check for Updates"}
              </Button>
              <Button
                size="sm"
                className="h-9 md:h-8"
                disabled={reason !== null}
                title={reason ?? undefined}
                onClick={() => setDialog({ kind: "install" })}
              >
                Install Package
              </Button>
            </>
          )
        }
      />

      <p className="-mt-3 mb-5 font-mono text-[11px] text-muted-foreground">
        {header.line}
      </p>

      {needed && (
        <div
          className={`${notice} flex flex-wrap items-center gap-2 border-warning/40 bg-warning/10`}
        >
          <span className="min-w-0 flex-1">{needed}</span>
          {updatable && (
            <Button
              variant="outline"
              size="sm"
              className="h-9 md:h-8"
              disabled={update.isPending}
              onClick={() => update.mutate(node.id)}
            >
              Update Agent
            </Button>
          )}
        </div>
      )}
      {header.offline && (
        <p className={`${notice} border-warning/40 bg-warning/10`}>
          {header.offline}
        </p>
      )}
      {!needed && !header.offline && services.data && !trusted && (
        <p className={notice}>
          {node.name} is not trusted yet. Trust it from{" "}
          <Link to="/devices" className="underline underline-offset-4">
            Passkeys
          </Link>{" "}
          before changing its packages.
        </p>
      )}
      {refresh.error && (
        <p role="alert" className="mb-4 text-sm text-destructive">
          {errorMessage(refresh.error)}
        </p>
      )}

      {!packages.data ? (
        packages.error ? (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(packages.error)}
          </p>
        ) : (
          <Skeleton className="h-96" />
        )
      ) : header.noApt ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          {header.noApt}
        </p>
      ) : !apt ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          Krynodes has not read the packages on {node.name} yet.
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
          <div className="min-w-0 space-y-6">
            {jobs.length > 0 && (
              <RunningJobs
                jobs={jobs}
                nodeName={node.name}
                now={now}
                onOpen={setDialog}
              />
            )}
            {apt.restart && (
              <RestartCard
                restart={apt.restart}
                nodeId={node.id}
                restartable={canRestartServer(node, trust)}
                now={now}
              />
            )}
            <UpdatesSection report={apt} reason={reason} onOpen={setDialog} />
            <InstalledSection
              report={apt}
              nodeName={node.name}
              query={params.get("q") ?? ""}
              all={params.get("show") === "all"}
              onQuery={(query) => setParam("q", query || null)}
              onAll={(all) => setParam("show", all ? "all" : null)}
              reason={reason}
              onOpen={setDialog}
            />
          </div>
          <aside className="min-w-0 space-y-6">
            <SourcesSection report={apt} reason={reason} onOpen={setDialog} />
            <OnTheirOwn report={apt} security={entry?.security} now={now} />
          </aside>
        </div>
      )}

      {apt && (
        <PackageDialogs
          dialog={dialog}
          onDialog={setDialog}
          node={node}
          report={apt}
          actions={actions.data?.actions ?? []}
        />
      )}
    </>
  );
}
