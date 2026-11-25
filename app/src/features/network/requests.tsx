import { RowMenu } from "@/components/row-menu";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { stampTime } from "@/lib/format";
import type { JoinRequest, NetworkView } from "@/types";

export function RequestList({
  requests,
  rejected,
  onApprove,
  onReject,
  onAskAgain,
}: {
  requests: JoinRequest[];
  rejected: NetworkView["rejected"];
  onApprove: (request: JoinRequest) => void;
  onReject: (request: JoinRequest) => void;
  onAskAgain: (node: string) => void;
}) {
  if (requests.length === 0 && rejected.length === 0) return null;
  return (
    <section className="space-y-2">
      {requests.length > 0 && (
        <>
          <h2 className="font-medium">Join Requests</h2>
          <ul className="divide-y rounded-lg border bg-card">
            {requests.map((request) => (
              <li
                key={request.node}
                className="flex flex-wrap items-center gap-3 px-4 py-3"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="truncate font-medium">{request.name}</span>
                    <Badge variant="outline">
                      {request.kind === "laptop" ? "Laptop" : "Server"}
                    </Badge>
                  </div>
                  <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                    <span>{request.os ?? "--"}</span>
                    <span>{request.hostname ?? "--"}</span>
                    <span>Since {stampTime(request.since)}</span>
                    <span
                      className={
                        request.ready ? "text-success" : "text-destructive"
                      }
                    >
                      {request.reason ??
                        (request.ready ? "Ready" : "Not ready yet")}
                    </span>
                  </p>
                </div>
                {request.ready && (
                  <Button size="sm" onClick={() => onApprove(request)}>
                    Approve
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onReject(request)}
                >
                  Reject
                </Button>
              </li>
            ))}
          </ul>
        </>
      )}
      {rejected.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-2 text-sm text-muted-foreground">
          Rejected:
          {rejected.map((machine) => (
            <span key={machine.node} className="inline-flex items-center">
              {machine.name}
              <RowMenu
                label={`Actions for ${machine.name}`}
                items={[
                  {
                    label: "Ask to Join Again",
                    onSelect: () => onAskAgain(machine.node),
                  },
                ]}
              />
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
