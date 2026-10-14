import { useState } from "react";

import { FilterChips } from "@/components/filter-chips";
import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  useDeleteIncidentUpdate,
  usePostIncidentUpdate,
  useSession,
} from "@/lib/api";
import {
  clockTime,
  displayHandle,
  parseTimestamp,
  shortDate,
} from "@/lib/format";
import { errorMessage } from "@/lib/http";
import type { IncidentDetail, IncidentUpdateStatus } from "@/types";

export const UPDATE_LABEL: Record<IncidentUpdateStatus, string> = {
  investigating: "Investigating",
  identified: "Identified",
  monitoring: "Monitoring",
  update: "Update",
};

const STATUSES = Object.keys(UPDATE_LABEL) as IncidentUpdateStatus[];
const LIMIT = 1000;

const AREA =
  "w-full resize-y rounded-md border bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

const when = (value: string) =>
  `${shortDate(parseTimestamp(value))} ${clockTime(parseTimestamp(value))}`;

interface Entry {
  key: string;
  at: number;
  title: string;
  body: string | null;
  by: string;
  tone: "bad" | "warn" | "ok" | "idle";
  updateId?: string;
  mine?: boolean;
}

export function IncidentTimeline({ detail }: { detail: IncidentDetail }) {
  const session = useSession();
  const remove = useDeleteIncidentUpdate(detail.incident.id);
  const me = session.data?.identity?.email;
  const { incident } = detail;
  const opened: Entry = {
    key: "opened",
    at: parseTimestamp(incident.started_at),
    title: "Opened",
    body: incident.summary,
    by: "Krynodes",
    tone: "bad",
  };
  const entries: Entry[] = [
    opened,
    ...(detail.updates ?? []).map((update) => ({
      key: update.id,
      at: parseTimestamp(update.createdAt),
      title: UPDATE_LABEL[update.status],
      body: update.message,
      by: displayHandle(null, update.author),
      tone: "warn" as const,
      updateId: update.id,
      mine: update.author === me,
    })),
    ...(incident.resolved_at
      ? [
          {
            key: "resolved",
            at: parseTimestamp(incident.resolved_at),
            title: "Resolved",
            body: "The check passes again.",
            by: "Krynodes",
            tone: "ok" as const,
          },
        ]
      : []),
  ].sort((a, b) => a.at - b.at);
  return (
    <ol className="divide-y rounded-lg border bg-card">
      {entries.map((entry) => (
        <li key={entry.key} className="flex gap-3 px-3 py-2.5 text-sm">
          <span className="pt-1.5">
            <StatusDot tone={entry.tone} />
          </span>
          <div className="min-w-0 flex-1">
            <p className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-medium">{entry.title}</span>
              <span className="font-mono text-xs text-muted-foreground">
                {when(new Date(entry.at).toISOString())} · {entry.by}
              </span>
            </p>
            {entry.body && (
              <p className="mt-0.5 break-words whitespace-pre-wrap text-muted-foreground">
                {entry.body}
              </p>
            )}
          </div>
          {entry.mine && entry.updateId && (
            <RowMenu
              label={`Options for the ${entry.title.toLowerCase()} update`}
              items={[
                {
                  label: "Delete",
                  destructive: true,
                  onSelect: () => remove.mutate(entry.updateId!),
                },
              ]}
            />
          )}
        </li>
      ))}
    </ol>
  );
}

export function UpdateForm({ detail }: { detail: IncidentDetail }) {
  const post = usePostIncidentUpdate(detail.incident.id);
  const latest = detail.updates?.at(-1)?.status;
  const [status, setStatus] = useState<IncidentUpdateStatus>(
    latest ?? "investigating",
  );
  const [message, setMessage] = useState("");
  const text = message.trim();
  return (
    <form
      className="space-y-3 rounded-lg border bg-card p-3"
      onSubmit={(event) => {
        event.preventDefault();
        post.mutate(
          { status, message: text },
          { onSuccess: () => setMessage("") },
        );
      }}
    >
      <FilterChips
        label="Status of this update"
        value={status}
        onChange={setStatus}
        options={STATUSES.map((value) => ({
          value,
          label: UPDATE_LABEL[value],
        }))}
      />
      <textarea
        aria-label="What is going on"
        value={message}
        rows={3}
        maxLength={LIMIT}
        placeholder="What you know, what you are doing, what comes next."
        onChange={(event) => setMessage(event.target.value)}
        className={AREA}
      />
      {post.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(post.error)}
        </p>
      )}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">
          {detail.public
            ? "This check is on the status page, so this update is public there."
            : "Only people who can open Krynodes see this."}{" "}
          It resolves by itself when the check passes.
        </p>
        <Button
          type="submit"
          size="sm"
          disabled={text.length === 0 || post.isPending}
        >
          {post.isPending ? "Posting…" : "Post update"}
        </Button>
      </div>
    </form>
  );
}
