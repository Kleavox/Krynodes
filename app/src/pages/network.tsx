import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { JoinDialog } from "@/features/network/create-dialog";
import { DeleteDialog } from "@/features/network/delete-dialog";
import { KeysDialog } from "@/features/network/keys-dialog";
import { LinksDialog } from "@/features/network/links-dialog";
import { RemoveDialog } from "@/features/network/remove-dialog";
import {
  ChangesCard,
  ProblemsCard,
  ServersCard,
  ThisNetwork,
  WaitingCard,
} from "@/features/network/sections";
import { TestDialog } from "@/features/network/test-dialog";
import { useJoin } from "@/features/network/use-network-sign";
import {
  useNetwork,
  useOverview,
  usePrivateRanges,
  useServices,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { presenceOf, testPairs } from "@/lib/network";
import { queryKeys } from "@/lib/query-client";
import { useNow } from "@/lib/use-now";

type Open =
  | { kind: "create" }
  | { kind: "add"; preset?: string }
  | { kind: "links"; nodeId: string }
  | { kind: "test"; nodeId?: string; pair?: [string, string] }
  | { kind: "remove"; nodeId: string }
  | { kind: "keys" }
  | { kind: "delete" };

export function NetworkPage() {
  const job = useJoin();
  const network = useNetwork(job?.phase === "done" ? 5_000 : 60_000);
  const overview = useOverview();
  const services = useServices();
  const ranges = usePrivateRanges(true);
  const client = useQueryClient();
  const now = useNow(5_000);
  const [search, setSearch] = useSearchParams();
  const joining = search.get("join");
  const [open, setOpen] = useState<Open | null>(
    joining ? { kind: "add", preset: joining } : null,
  );

  useEffect(() => {
    if (joining) setSearch({}, { replace: true });
  }, [joining, setSearch]);

  useEffect(() => {
    if (job?.phase === "done") {
      void client.invalidateQueries({ queryKey: queryKeys.network });
      void client.invalidateQueries({ queryKey: queryKeys.overview });
    }
  }, [job?.phase, client]);

  if (!network.data || !overview.data) {
    return (
      <>
        <PageHeader title="Network" />
        {network.error ? (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(network.error)}
          </p>
        ) : (
          <Skeleton className="h-96" />
        )}
      </>
    );
  }

  const view = network.data;
  const nodes = overview.data.nodes.filter(
    (node) => node.enrolled_at !== null && node.disabled_at === null,
  );
  const presence = presenceOf(nodes, now);
  const memberOf = (id: string | undefined) =>
    view.members.find((member) => member.nodeId === id);
  const linked = open?.kind === "links" ? memberOf(open.nodeId) : undefined;
  const removing = open?.kind === "remove" ? memberOf(open.nodeId) : undefined;
  const creating = job?.kind === "create";
  const close = () => setOpen(null);

  const testing = (() => {
    if (open?.kind !== "test") return null;
    if (open.pair) {
      const [a, b] = open.pair.map(memberOf);
      return a && b
        ? {
            title: `${a.name} ↔ ${b.name}`,
            pairs: [[a, b] as [typeof a, typeof b]],
          }
        : null;
    }
    const server = memberOf(open.nodeId);
    return {
      title: server ? `Test ${server.name}'s Links` : "Test All Links",
      pairs: testPairs(view, open.nodeId),
    };
  })();

  return (
    <>
      <PageHeader
        title="Network"
        actions={
          view.network && (
            <Button
              variant="outline"
              size="sm"
              className="h-9 md:h-8"
              onClick={() => setOpen({ kind: "add" })}
            >
              {job?.kind === "add" ? "Adding…" : "Add Server"}
            </Button>
          )
        }
      />
      {!view.network ? (
        <EmptyState
          title={creating ? "Creating…" : "No private network yet"}
          body="Connect your servers to each other over WireGuard, so a stack on one can reach a database on another without opening it to the internet."
          action={
            <Button onClick={() => setOpen({ kind: "create" })}>
              {creating ? "Show Progress" : "Create Network"}
            </Button>
          }
        />
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
          <div className="min-w-0 space-y-6">
            <ProblemsCard
              view={view}
              presence={presence}
              now={now}
              onTest={(a, b) => setOpen({ kind: "test", pair: [a, b] })}
            />
            <WaitingCard
              view={view}
              onJoin={(nodeId) => setOpen({ kind: "add", preset: nodeId })}
            />
            <ServersCard
              view={view}
              presence={presence}
              now={now}
              onOpen={(server) =>
                setOpen({ kind: "links", nodeId: server.nodeId })
              }
              onTest={(server) =>
                setOpen({ kind: "test", nodeId: server.nodeId })
              }
              onRemove={(server) =>
                setOpen({ kind: "remove", nodeId: server.nodeId })
              }
            />
            <ChangesCard view={view} />
          </div>
          <aside className="min-w-0">
            <ThisNetwork
              view={view}
              presence={presence}
              onTestAll={() => setOpen({ kind: "test" })}
              onKeys={() => setOpen({ kind: "keys" })}
              onDelete={() => setOpen({ kind: "delete" })}
            />
          </aside>
        </div>
      )}
      {(open?.kind === "create" || open?.kind === "add") && (
        <JoinDialog
          kind={open.kind}
          nodes={nodes}
          services={services.data}
          view={view}
          ranges={ranges.data?.ranges ?? []}
          release={overview.data.agentRelease.version}
          preset={open.kind === "add" ? open.preset : undefined}
          now={now}
          onClose={close}
        />
      )}
      {linked && (
        <LinksDialog
          server={linked}
          view={view}
          presence={presence}
          now={now}
          onClose={close}
          onTest={() => setOpen({ kind: "test", nodeId: linked.nodeId })}
          onTestPair={(peer) =>
            setOpen({ kind: "test", pair: [linked.nodeId, peer] })
          }
          onRemove={() => setOpen({ kind: "remove", nodeId: linked.nodeId })}
        />
      )}
      {testing && (
        <TestDialog
          title={testing.title}
          pairs={testing.pairs}
          view={view}
          presence={presence}
          nodes={nodes}
          onClose={close}
        />
      )}
      {removing && (
        <RemoveDialog
          server={removing}
          view={view}
          nodes={nodes}
          onClose={close}
        />
      )}
      {open?.kind === "keys" && (
        <KeysDialog view={view} presence={presence} onClose={close} />
      )}
      {open?.kind === "delete" && (
        <DeleteDialog
          view={view}
          presence={presence}
          checks={overview.data.checks}
          nodes={nodes}
          onClose={close}
        />
      )}
    </>
  );
}
