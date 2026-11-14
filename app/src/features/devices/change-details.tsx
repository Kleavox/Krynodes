import type { TrustChange } from "@krynodes/protocol";

import { describeChange } from "@/lib/devices";
import { shortDate } from "@/lib/format";

import { BigPrint } from "./parts";
import type { Fleet } from "./use-fleet";

const HEADING = "mb-1.5 text-xs font-medium text-muted-foreground";

export function ChangeDetails({
  fleet,
  change,
}: {
  fleet: Fleet;
  change: TrustChange;
}) {
  const summary = describeChange(fleet.view, change);
  const serverName = (id: string) =>
    fleet.servers.find((server) => server.node.id === id)?.node.name ??
    "An unknown server";
  const admitted = (change.core ?? []).filter((key) =>
    summary.admitted.includes(key.id),
  );
  const owner = (id: string) =>
    change.core?.find((key) => key.id === id)?.account ?? "";
  const empty =
    admitted.length === 0 &&
    summary.removed.length === 0 &&
    summary.moved.length === 0 &&
    summary.recorded.length === 0 &&
    summary.access.length === 0;

  return (
    <div className="space-y-4 text-sm">
      {admitted.map((key) => {
        const record = fleet.devices.find((device) => device.id === key.id);
        return (
          <section
            key={key.id}
            aria-label={`New passkey ${key.name}`}
            className="rounded-md border bg-card p-3"
          >
            <p className="font-medium">
              {key.name}
              {record && (
                <span className="font-normal text-muted-foreground">
                  {" "}
                  · Registered {shortDate(record.createdAt)}
                </span>
              )}
            </p>
            <BigPrint publicKey={key.publicKey} className="my-2" />
            <p className="text-muted-foreground">
              Check that the new device shows the same code.
            </p>
            {key.account && (
              <p className="mt-1 break-all">Belongs to {key.account}</p>
            )}
          </section>
        );
      })}
      {summary.removed.length > 0 && (
        <section>
          <h3 className={HEADING}>Leaving</h3>
          <ul className="space-y-1">
            {summary.removed.map((id) => (
              <li key={id}>
                <span className="font-medium">{fleet.name(id)}</span> loses
                access to every server and can no longer approve.
              </li>
            ))}
          </ul>
        </section>
      )}
      {summary.moved.length > 0 && (
        <section>
          <h3 className={HEADING}>Moving</h3>
          <ul className="space-y-1">
            {summary.moved.map((entry) => (
              <li key={entry.id} className="break-words">
                <span className="font-medium">{fleet.name(entry.id)}</span> goes
                from {entry.from} to {entry.to}. Only {entry.to} signs with it
                afterwards.
              </li>
            ))}
          </ul>
        </section>
      )}
      {summary.recorded.length > 0 && (
        <section>
          <h3 className={HEADING}>Owners</h3>
          <ul className="divide-y rounded-md border">
            {summary.recorded.map((id) => (
              <li
                key={id}
                className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2"
              >
                <span className="min-w-0 flex-1 truncate font-medium">
                  {fleet.name(id)}
                </span>
                <span className="font-mono text-xs break-all">{owner(id)}</span>
              </li>
            ))}
          </ul>
          <p className="mt-1.5 text-muted-foreground">
            Your servers store who owns each passkey from now on. Check each
            address before you approve.
          </p>
        </section>
      )}
      {summary.access.length > 0 && (
        <section>
          <h3 className={HEADING}>Access</h3>
          <ul className="divide-y rounded-md border">
            {summary.access.map((entry) => (
              <li
                key={entry.nodeId}
                className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2"
              >
                <span className="min-w-0 flex-1 truncate font-medium">
                  {serverName(entry.nodeId)}
                </span>
                {entry.added.map((id) => (
                  <span
                    key={`+${id}`}
                    className="font-mono text-xs text-success"
                  >
                    + {fleet.name(id)}
                  </span>
                ))}
                {entry.removed.map((id) => (
                  <span
                    key={`-${id}`}
                    className="font-mono text-xs text-destructive"
                  >
                    − {fleet.name(id)}
                  </span>
                ))}
              </li>
            ))}
          </ul>
        </section>
      )}
      {empty && (
        <p className="text-muted-foreground">
          Nothing changes for your passkeys. Servers that missed an earlier
          change catch up with the current core and access.
        </p>
      )}
    </div>
  );
}
