import { Link } from "react-router";

import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  onTheirOwn,
  packageMenu,
  repoName,
  restartFacts,
  runningJob,
  shownPackages,
  updateRow,
  updatesHeader,
} from "@/lib/packages";
import { cn } from "@/lib/utils";
import type { ActionRecord, AptReport, SecurityReport } from "@/types";

import { Lines, type PackagesDialog } from "./lines";

const sectionTitle = "text-xs font-medium text-muted-foreground";
const columns =
  "md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_minmax(0,0.8fr)_minmax(0,0.7fr)_2.25rem]";

type Open = (dialog: PackagesDialog) => void;

const CHOICE_LABEL = {
  hold: "Hold at This Version",
  unhold: "Release Hold",
  remove: "Remove",
} as const;

export function RunningJobs({
  jobs,
  nodeName,
  now,
  onOpen,
}: {
  jobs: ActionRecord[];
  nodeName: string;
  now: number;
  onOpen: Open;
}) {
  return (
    <ul className="space-y-2">
      {jobs.map((job) => {
        const { title, step } = runningJob(job, nodeName, now);
        return (
          <li key={job.id}>
            <button
              type="button"
              onClick={() => onOpen({ kind: "job", id: job.id })}
              className="flex w-full items-center gap-2.5 rounded-lg border border-warning/40 bg-card px-3 py-2 text-left text-sm hover:bg-accent"
            >
              <StatusDot tone="warn" pulse />
              <span className="min-w-0 flex-1">
                <span className="block truncate">{title}</span>
                {step && (
                  <span className="block truncate font-mono text-xs text-muted-foreground">
                    {step}
                  </span>
                )}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

export function RestartCard({
  restart,
  nodeId,
  restartable,
  now,
}: {
  restart: NonNullable<AptReport["restart"]>;
  nodeId: string;
  restartable: boolean;
  now: number;
}) {
  const facts = restartFacts(restart, now);
  return (
    <section
      aria-labelledby="restart-needed"
      className="rounded-lg border border-warning/40 bg-warning/10 p-3"
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <h2 id="restart-needed" className="text-sm font-medium">
          Restart Needed
        </h2>
        <span className="font-mono text-[11px] text-muted-foreground">
          {facts.since}
        </span>
        {restartable && (
          <Button
            asChild
            variant="outline"
            size="sm"
            className="ml-auto h-9 md:h-8"
          >
            <Link to={`/nodes/${nodeId}?restart=1`}>Restart Server</Link>
          </Button>
        )}
      </div>
      {facts.read && (
        <p className="mt-1 text-xs text-muted-foreground">{facts.read}</p>
      )}
    </section>
  );
}

export function UpdatesSection({
  report,
  reason,
  onOpen,
}: {
  report: AptReport;
  reason: string | null;
  onOpen: Open;
}) {
  const upgradable = report.updates.some(
    (update) => !update.held && (update.back?.removes.length ?? 0) === 0,
  );
  return (
    <section aria-labelledby="updates">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2 id="updates" className={sectionTitle}>
          {updatesHeader(report)}
        </h2>
        {upgradable && (
          <Button
            variant="outline"
            size="sm"
            className="ml-auto h-9 md:h-8"
            disabled={reason !== null}
            title={reason ?? undefined}
            onClick={() => onOpen({ kind: "upgrade" })}
          >
            Upgrade All
          </Button>
        )}
      </div>
      {report.updates.length > 0 && (
        <ul className="divide-y rounded-lg border bg-card">
          {report.updates.map((update) => {
            const row = updateRow(update);
            return (
              <li key={update.name} className="px-3 py-2 text-sm">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                  <span className="font-medium">{update.name}</span>
                  {row.tag && (
                    <Badge
                      variant="secondary"
                      className={cn(row.tag === "Security" && "text-warning")}
                    >
                      {row.tag}
                    </Badge>
                  )}
                  <span className="font-mono text-xs break-all text-muted-foreground">
                    {row.versions}
                  </span>
                  {update.source && (
                    <span className="ml-auto text-xs text-muted-foreground">
                      {update.source}
                    </span>
                  )}
                </div>
                {row.note && (
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {row.note}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

export function InstalledSection({
  report,
  nodeName,
  query,
  all,
  onQuery,
  onAll,
  reason,
  onOpen,
}: {
  report: AptReport;
  nodeName: string;
  query: string;
  all: boolean;
  onQuery: (query: string) => void;
  onAll: (all: boolean) => void;
  reason: string | null;
  onOpen: Open;
}) {
  const shown = shownPackages(report, { all, query });
  const brought = report.packages.find((entry) => entry.more > 0);
  return (
    <section aria-labelledby="installed">
      <div className="mb-2 flex min-h-8 flex-wrap items-center gap-2">
        <h2 id="installed" className={sectionTitle}>
          Installed
        </h2>
        <Input
          type="search"
          value={query}
          onChange={(event) => onQuery(event.target.value)}
          placeholder={`Search ${report.installed} packages`}
          aria-label="Search packages"
          className="order-last h-9 w-full sm:order-none sm:ml-auto sm:w-56 md:h-8"
        />
        <Select
          value={all ? "all" : "here"}
          onValueChange={(value) => onAll(value === "all")}
        >
          <SelectTrigger
            size="sm"
            aria-label="Which packages"
            className="ml-auto h-9 sm:ml-0 md:h-8"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="here">Added Here</SelectItem>
            <SelectItem value="all">All</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="rounded-lg border bg-card">
        <div
          className={cn(
            "hidden gap-3 border-b px-3 py-1.5 text-[11px] text-muted-foreground md:grid",
            columns,
          )}
        >
          <span>Package</span>
          <span>Version</span>
          <span>From</span>
          <span>Added by</span>
          <span />
        </div>
        {shown.length === 0 ? (
          <p className="p-4 text-sm text-muted-foreground">
            {query.trim()
              ? `No package matches ${query.trim()}.`
              : "Nothing was added here yet. All lists every package."}
          </p>
        ) : (
          <ul className="divide-y">
            {shown.map((entry) => {
              const menu = packageMenu(entry);
              return (
                <li
                  key={entry.name}
                  className={cn(
                    "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-1 text-sm",
                    columns,
                  )}
                >
                  <span className="min-w-0">
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="truncate">
                        {entry.name}
                        {entry.more > 0 && (
                          <span className="text-muted-foreground">
                            {" "}
                            + {entry.more} more
                          </span>
                        )}
                      </span>
                      {entry.held && <Badge variant="secondary">Held</Badge>}
                    </span>
                    <span className="block truncate text-xs text-muted-foreground md:hidden">
                      {entry.from ?? "--"} · {entry.by ?? "--"}
                    </span>
                  </span>
                  <span className="hidden truncate font-mono text-xs md:block">
                    {entry.version}
                  </span>
                  <span className="hidden truncate md:block">
                    {entry.from ?? "--"}
                  </span>
                  <span className="hidden truncate md:block">
                    {entry.by ?? "--"}
                  </span>
                  <RowMenu
                    label={`${entry.name} actions`}
                    items={[
                      ...(menu.note ? [{ label: menu.note }] : []),
                      ...menu.items.map((choice) => ({
                        label: CHOICE_LABEL[choice],
                        destructive: choice === "remove",
                        disabled: reason !== null,
                        onSelect: () =>
                          onOpen(
                            choice === "remove"
                              ? { kind: "remove", name: entry.name }
                              : {
                                  kind: "hold",
                                  name: entry.name,
                                  held: choice === "unhold",
                                },
                          ),
                      })),
                    ]}
                  />
                </li>
              );
            })}
          </ul>
        )}
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        "Added by" comes from apt's own history on {nodeName} (Requested-By),
        and from what Krynodes did itself. Anything older than that history
        shows under All.
        {brought &&
          ` "+ ${brought.more} more" are the packages that came with ${brought.name}.`}
      </p>
    </section>
  );
}

export function SourcesSection({
  report,
  reason,
  onOpen,
}: {
  report: AptReport;
  reason: string | null;
  onOpen: Open;
}) {
  return (
    <section aria-labelledby="sources">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2 id="sources" className={sectionTitle}>
          Sources
        </h2>
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto h-8"
          disabled={reason !== null}
          title={reason ?? undefined}
          onClick={() => onOpen({ kind: "repo" })}
        >
          Add Repository
        </Button>
      </div>
      <ul className="divide-y rounded-lg border bg-card">
        {report.sources.map((source) => (
          <li
            key={source.file}
            className="flex min-h-12 items-center gap-2 px-3 py-1.5 text-sm"
          >
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2">
                {source.name}
                {source.krynodes && <Badge variant="secondary">Krynodes</Badge>}
              </span>
              <span className="block truncate font-mono text-xs text-muted-foreground">
                {[
                  source.host,
                  source.system || !source.key
                    ? source.suites.join(", ")
                    : null,
                  source.key ? `key ${source.key}` : null,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
            </span>
            {!source.system && (
              <RowMenu
                label={`${source.name} actions`}
                items={[
                  {
                    label: "Remove",
                    destructive: true,
                    disabled: reason !== null,
                    onSelect: () =>
                      onOpen({
                        kind: "droprepo",
                        name: repoName(source.file),
                        label: source.name,
                      }),
                  },
                ]}
              />
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function OnTheirOwn({
  report,
  security,
  now,
}: {
  report: AptReport;
  security: SecurityReport | null | undefined;
  now: number;
}) {
  const own = onTheirOwn(report, security, now);
  return (
    <section aria-labelledby="on-their-own">
      <h2
        id="on-their-own"
        className={cn(sectionTitle, "mb-2 flex min-h-8 items-center")}
      >
        On Their Own
      </h2>
      <dl className="space-y-3 rounded-lg border bg-card p-3">
        {(
          [
            ["Security", own.security],
            ["Restarts", own.restarts],
          ] as const
        ).map(([label, line]) => (
          <div key={label}>
            <dt className="mb-1 text-xs text-muted-foreground">{label}</dt>
            <dd>
              <Lines lines={[line]} />
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
