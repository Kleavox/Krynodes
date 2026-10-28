import { useState, type FormEvent } from "react";

import { Busy } from "@/components/busy";
import { CopyCommand } from "@/components/copy-command";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useOverview, useSaveBudget, useUsage } from "@/lib/api";
import { estimateDailyUse, formatBytes, formatThousands } from "@/lib/budget";
import { clockTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import { cn } from "@/lib/utils";
import type { UsageShare } from "@/types";

import { SettingsSection } from "./section";

const SECRET_COMMAND =
  "pnpm exec wrangler secret put CF_ANALYTICS_TOKEN --config worker/wrangler.jsonc --env production";

const FIELDS: { key: keyof UsageShare; label: string }[] = [
  { key: "requests", label: "Requests" },
  { key: "writes", label: "D1 Writes" },
  { key: "reads", label: "D1 Reads" },
];

function Bar({ used, limit }: { used: number; limit: number }) {
  const percent = limit > 0 ? (used / limit) * 100 : 0;
  return (
    <div
      aria-hidden="true"
      className="h-1.5 overflow-hidden rounded-full bg-accent"
    >
      <div
        className={cn(
          "h-full rounded-full bg-primary",
          percent >= 80 && "bg-warning",
          percent > 100 && "bg-destructive",
        )}
        style={{ width: `${Math.min(100, percent)}%` }}
      />
    </div>
  );
}

function Meter({
  label,
  used,
  limit,
  note,
  format = formatThousands,
}: {
  label: string;
  used: number | null;
  limit: number;
  note: string;
  format?: (value: number) => string;
}) {
  const percent = used === null ? null : Math.round((used / limit) * 100);
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span>{label}</span>
        <span className="font-mono text-xs text-muted-foreground">
          {used === null
            ? "No Data"
            : `${format(used)} of ${format(limit)} · ${percent}%`}
        </span>
      </div>
      <Bar used={used ?? 0} limit={limit} />
      <p className="text-xs text-muted-foreground">{note}</p>
    </div>
  );
}

function BudgetForm({ budget }: { budget: UsageShare }) {
  const save = useSaveBudget();
  const [values, setValues] = useState<Record<keyof UsageShare, string>>({
    requests: String(budget.requests),
    writes: String(budget.writes),
    reads: String(budget.reads),
  });
  const parsed: UsageShare = {
    requests: Number(values.requests),
    writes: Number(values.writes),
    reads: Number(values.reads),
  };
  const valid = FIELDS.every(
    ({ key }) => Number.isInteger(parsed[key]) && parsed[key] > 0,
  );
  const changed = FIELDS.some(({ key }) => parsed[key] !== budget[key]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) save.mutate(parsed);
  };
  return (
    <form className="space-y-3" onSubmit={submit}>
      <div>
        <h3 className="text-sm font-medium">Krynodes Share</h3>
        <p className="text-xs text-muted-foreground">
          How much of the account's daily quotas Krynodes may use, when other
          projects share the account.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        {FIELDS.map(({ key, label }) => (
          <div key={key} className="grid gap-1.5">
            <Label htmlFor={`share-${key}`}>{label}</Label>
            <Input
              id={`share-${key}`}
              inputMode="numeric"
              className="font-mono"
              value={values[key]}
              aria-invalid={!(Number(values[key]) > 0)}
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  [key]: event.target.value.replace(/[^0-9]/gu, ""),
                }))
              }
            />
          </div>
        ))}
      </div>
      {save.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(save.error)}
        </p>
      )}
      <div className="flex items-center justify-end gap-3">
        {save.isSuccess && !changed && (
          <span role="status" className="text-xs text-success">
            Saved
          </span>
        )}
        <Button
          type="submit"
          size="sm"
          disabled={!valid || !changed || save.isPending}
        >
          {save.isPending ? <Busy>Saving</Busy> : "Save Share"}
        </Button>
      </div>
    </form>
  );
}

export function UsageSettings() {
  const usage = useUsage().data;
  const estimate = estimateDailyUse(useOverview().data?.nodes ?? []);
  const budget = usage?.budget ?? {
    requests: 20_000,
    writes: 30_000,
    reads: 1_000_000,
  };
  const quotas = usage?.quotas ?? {
    requests: 100_000,
    writes: 100_000,
    reads: 5_000_000,
    objects: 100_000,
  };
  const real = usage?.source === "cloudflare" ? usage.krynodes : null;
  const account = usage?.source === "cloudflare" ? usage.account : null;
  const mine = real ?? { ...estimate, reads: null };
  return (
    <SettingsSection
      title="Usage"
      description={
        <>
          {real && usage?.fetchedAt
            ? `Today, from Cloudflare, updated ${clockTime(usage.fetchedAt)}.`
            : "Today, estimated from your servers and their reporting mode."}{" "}
          Free quotas reset at {usage ? clockTime(usage.resetAt) : "00:00 UTC"},
          midnight UTC.
        </>
      }
    >
      <div className="space-y-4">
        {usage?.error && (
          <p
            role="status"
            className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm"
          >
            Cloudflare did not answer: {usage.error}{" "}
            {real ? "Showing the last numbers." : "Showing the estimate."}
          </p>
        )}
        <section className="space-y-4" aria-label="Krynodes today">
          <Meter
            label="Requests"
            used={mine.requests}
            limit={budget.requests}
            note="Worker requests from agents, the dashboard and the status page."
          />
          <Meter
            label="D1 Writes"
            used={mine.writes}
            limit={budget.writes}
            note="Rows written by reports, history and actions."
          />
          <Meter
            label="D1 Reads"
            used={mine.reads}
            limit={budget.reads}
            note={
              real
                ? "Rows read by every query."
                : "Only Cloudflare knows; set up counting to see it."
            }
          />
        </section>
        {usage && (
          <section className="border-t pt-4" aria-label="Database">
            <Meter
              label="Database Size"
              used={usage.storage.bytes}
              limit={usage.storage.limit}
              format={formatBytes}
              note="A daily cleanup keeps it small: actions 90 days, server metrics 8 days, trust changes a year."
            />
          </section>
        )}
        {account && (
          <section
            className="space-y-4 border-t pt-4"
            aria-label="Whole account today"
          >
            <h3 className="text-sm font-medium">Whole account, all projects</h3>
            <Meter
              label="Requests"
              used={account.requests}
              limit={quotas.requests}
              note="Free plan quota."
            />
            <Meter
              label="D1 Writes"
              used={account.writes}
              limit={quotas.writes}
              note="Free plan quota."
            />
            <Meter
              label="D1 Reads"
              used={account.reads}
              limit={quotas.reads}
              note="Free plan quota."
            />
            <Meter
              label="Durable Object requests"
              used={account.objects}
              limit={quotas.objects}
              note="Live agent connections; 20 messages count as one."
            />
          </section>
        )}
        <section className="border-t pt-4">
          <BudgetForm key={usage ? "ready" : "waiting"} budget={budget} />
        </section>
        {usage && !usage.configured && (
          <details className="rounded-md border px-3 py-2 text-sm">
            <summary className="cursor-pointer font-medium">
              Set Up Real Counting
            </summary>
            <ol className="mt-2 list-decimal space-y-2 pl-5 text-muted-foreground">
              <li>
                In Cloudflare, open My Profile, API Tokens, Create Token, and
                make a custom token with one permission: Account, Account
                Analytics, Read. It can only read statistics.
              </li>
              <li>
                Save it in GitHub as the production secret{" "}
                <code className="font-mono">CF_ANALYTICS_TOKEN</code>. The next
                deploy hands it to the Worker. Or set it by hand:
                <div className="mt-1.5">
                  <CopyCommand command={SECRET_COMMAND} />
                </div>
              </li>
            </ol>
          </details>
        )}
      </div>
    </SettingsSection>
  );
}
