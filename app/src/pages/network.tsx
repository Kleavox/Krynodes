import type { NetworkRule } from "@krynodes/protocol";
import { useState } from "react";
import { toast } from "sonner";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useFleet } from "@/features/fleet/use-fleet";
import { ApproveDialog } from "@/features/network/approve-dialog";
import {
  ChangeDialog,
  deleteChange,
  deleteRuleChange,
  exitChange,
  removeChange,
  type Change,
} from "@/features/network/change-dialog";
import { Connections } from "@/features/network/connections";
import { KeysDialog } from "@/features/network/keys-dialog";
import { AddLaptopDialog, LaptopDns } from "@/features/network/laptops";
import { MemberList } from "@/features/network/members";
import { RequestList } from "@/features/network/requests";
import { RuleDialog } from "@/features/network/rule-dialog";
import { TestDialog } from "@/features/network/test-dialog";
import {
  useCurrentDocument,
  useNetworkView,
  useRefreshNetwork,
} from "@/features/network/use-network";
import { networkApi } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { exitOf, firstReadyServer, networkFailure } from "@/lib/network";
import { namesOf } from "@/lib/rules";
import type { FleetNode, JoinRequest } from "@/types";

type Open =
  | { kind: "approve"; request: JoinRequest }
  | { kind: "change"; change: Change }
  | { kind: "keys"; node: string; name: string }
  | { kind: "rule"; editing: { index: number; rule: NetworkRule } | null }
  | { kind: "test"; node: FleetNode }
  | { kind: "laptop" };

export function NetworkPage() {
  const view = useNetworkView();
  const fleet = useFleet();
  const live = Boolean(view.data?.network && !view.data.network.deleted);
  const current = useCurrentDocument(live);
  const refresh = useRefreshNetwork();
  const [open, setOpen] = useState<Open | null>(null);
  const nodes = fleet.data ?? [];
  const networkDocument = current.data?.document;
  const exit = exitOf(networkDocument);
  const flip = (verb: "reject" | "askAgain", node: string) =>
    void networkApi[verb](node)
      .catch((error: unknown) => {
        toast.error(networkFailure(error));
      })
      .finally(refresh);
  const close = () => setOpen(null);
  const data = view.data;

  return (
    <>
      <PageHeader
        title="Network"
        meta={
          live &&
          data?.network && (
            <span className="font-mono text-xs text-muted-foreground">
              {data.network.range} · Version {data.network.version}
            </span>
          )
        }
        actions={
          live && (
            <Button onClick={() => setOpen({ kind: "laptop" })}>
              Add Laptop
            </Button>
          )
        }
      />
      {data ? (
        <div className="space-y-6">
          <RequestList
            requests={data.requests}
            rejected={data.rejected}
            onApprove={(request) => setOpen({ kind: "approve", request })}
            onReject={(request) => flip("reject", request.node)}
            onAskAgain={(node) => flip("askAgain", node)}
          />
          {live ? (
            <>
              {current.isError && (
                <p role="alert" className="text-sm text-destructive">
                  {networkFailure(current.error)}
                </p>
              )}
              <MemberList
                view={data}
                nodes={nodes}
                exit={exit}
                onAsk={(member, ask) => {
                  const node = nodes.find((one) => one.id === member.node);
                  if (ask === "remove") {
                    setOpen({ kind: "change", change: removeChange(member) });
                  } else if (ask === "exit") {
                    if (exit === undefined) return;
                    setOpen({
                      kind: "change",
                      change: exitChange(member, exit !== member.node),
                    });
                  } else if (ask === "keys") {
                    setOpen({
                      kind: "keys",
                      node: member.node,
                      name: member.name,
                    });
                  } else if (!node) {
                    toast.error(`${member.name} was not found in Fleet.`);
                  } else {
                    setOpen({ kind: "test", node });
                  }
                }}
              />
              <section className="space-y-2">
                <h2 className="font-medium">Laptops</h2>
                <LaptopDns
                  key={(data.network?.dns ?? []).join(" ")}
                  dns={data.network?.dns ?? null}
                />
              </section>
              {networkDocument ? (
                <Connections
                  document={networkDocument}
                  onAdd={() => setOpen({ kind: "rule", editing: null })}
                  onEdit={(index, rule) =>
                    setOpen({ kind: "rule", editing: { index, rule } })
                  }
                  onDelete={(index, rule) =>
                    setOpen({
                      kind: "change",
                      change: deleteRuleChange(
                        index,
                        rule,
                        namesOf(networkDocument),
                      ),
                    })
                  }
                />
              ) : (
                !current.isError && <Skeleton className="h-14" />
              )}
              <div>
                <Button
                  variant="outline"
                  className="text-destructive"
                  onClick={() =>
                    setOpen({ kind: "change", change: deleteChange })
                  }
                >
                  Delete Network
                </Button>
              </div>
            </>
          ) : (
            <NoNetwork
              requests={data.requests}
              onCreate={(request) => setOpen({ kind: "approve", request })}
            />
          )}
        </div>
      ) : view.isError ? (
        <EmptyState
          title="The network can't load"
          body={errorMessage(view.error)}
          action={<Button onClick={() => void view.refetch()}>Retry</Button>}
        />
      ) : (
        <div role="status" aria-label="Loading network" className="space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      )}
      {open?.kind === "approve" && (
        <ApproveDialog request={open.request} onClose={close} />
      )}
      {open?.kind === "change" && (
        <ChangeDialog change={open.change} onClose={close} />
      )}
      {open?.kind === "keys" && (
        <KeysDialog node={open.node} name={open.name} onClose={close} />
      )}
      {open?.kind === "rule" && networkDocument && (
        <RuleDialog
          document={networkDocument}
          editing={open.editing}
          onClose={close}
        />
      )}
      {open?.kind === "test" && data && (
        <TestDialog node={open.node} view={data} onClose={close} />
      )}
      {open?.kind === "laptop" && <AddLaptopDialog onClose={close} />}
    </>
  );
}

function NoNetwork({
  requests,
  onCreate,
}: {
  requests: JoinRequest[];
  onCreate: (request: JoinRequest) => void;
}) {
  const first = firstReadyServer(requests);
  return (
    <EmptyState
      title="No private network yet"
      body={
        first
          ? `Create Network starts the private network with ${first.name}.`
          : "A private network starts with a server. Enroll one and it asks to join here."
      }
      action={
        <Button disabled={!first} onClick={() => first && onCreate(first)}>
          Create Network
        </Button>
      }
    />
  );
}
