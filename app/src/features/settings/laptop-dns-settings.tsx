import { KeyRound } from "lucide-react";
import { useState } from "react";

import { Busy, Waiting } from "@/components/busy";
import { Field } from "@/components/field";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  useNetworkKeys,
  useSignChange,
} from "@/features/network/use-network-sign";
import { NotFollowing } from "@/features/packages/lines";
import { useNetwork, useOverview } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { dnsFields, laptopBlocker, networkText, parseDns } from "@/lib/network";
import type { NetworkView, NodeRecord } from "@/types";

import { SettingsSection } from "./section";

export function LaptopDnsSettings() {
  const network = useNetwork();
  const overview = useOverview();
  return (
    <SettingsSection
      title="DNS for Laptops on an Exit Node"
      description="A laptop that sends its traffic out through an Exit Node asks these DNS servers. Use one or two IPv4 addresses; a private address, such as a DNS server in a stack, works too. Saving takes your passkey."
    >
      {network.data && overview.data ? (
        network.data.network ? (
          <DnsForm view={network.data} nodes={overview.data.nodes} />
        ) : (
          <p className="text-sm text-muted-foreground">
            Create the private network first.
          </p>
        )
      ) : (
        <p className="text-sm text-muted-foreground">
          {network.error ? errorMessage(network.error) : <Busy>Loading</Busy>}
        </p>
      )}
    </SettingsSection>
  );
}

function DnsForm({
  view,
  nodes,
}: {
  view: NetworkView;
  nodes: Pick<NodeRecord, "id" | "name" | "agent_version">[];
}) {
  const saved = view.document?.dns;
  const [initialFirst, initialSecond] = dnsFields(saved);
  const [first, setFirst] = useState(initialFirst);
  const [second, setSecond] = useState(initialSecond);
  const keys = useNetworkKeys(view.members);
  const send = useSignChange();
  const parsed = parseDns(first, second);
  const blocker = laptopBlocker(view, nodes);
  const problem = blocker ?? send.error?.message ?? parsed.problem;
  const changed =
    saved === undefined || parsed.dns.join(" ") !== saved.join(" ");
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (parsed.problem === null) {
          send.mutate({
            change: { kind: "dns", dns: parsed.dns },
            text: networkText.dns(parsed.dns),
            signers: keys.signers,
          });
        }
      }}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="laptop-dns-first" label="First address">
          <Input
            id="laptop-dns-first"
            value={first}
            inputMode="decimal"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono"
            onChange={(event) => setFirst(event.target.value)}
          />
        </Field>
        <Field id="laptop-dns-second" label="Second address (optional)">
          <Input
            id="laptop-dns-second"
            value={second}
            inputMode="decimal"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono"
            onChange={(event) => setSecond(event.target.value)}
          />
        </Field>
      </div>
      {saved === undefined && (
        <p className="text-xs text-muted-foreground">
          Nothing is saved yet. These two are a starting point, and they only
          count once you save them.
        </p>
      )}
      <NotFollowing lines={keys.unfollowed} />
      {problem && (
        <p role="alert" className="text-sm text-destructive">
          {problem}
        </p>
      )}
      <div className="flex items-center justify-end gap-3">
        {send.isSuccess && !changed && (
          <span role="status" className="text-xs text-success">
            Saved
          </span>
        )}
        <Button
          type="submit"
          size="sm"
          disabled={
            !changed ||
            parsed.problem !== null ||
            blocker !== null ||
            send.isPending
          }
        >
          {send.isPending ? (
            <Waiting />
          ) : (
            <>
              <KeyRound aria-hidden="true" />
              Save
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
