import { useState, type ReactNode } from "react";

import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ActionLine } from "@/features/services/action-line";
import {
  useDeleteIncidentUpdate,
  usePostIncidentUpdate,
  useSession,
} from "@/lib/api";
import { displayHandle, stampTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import {
  UPDATE_LABEL,
  runText,
  timeline,
  type TimelineEvent,
} from "@/lib/incidents";
import { cn } from "@/lib/utils";
import type { IncidentDetail, IncidentUpdateStatus } from "@/types";

const STATUSES = Object.keys(UPDATE_LABEL) as IncidentUpdateStatus[];
const LIMIT = 1000;

function Event({
  tone,
  title,
  when,
  by,
  body,
  mono = false,
  titleClass,
  bodyClass,
  children,
}: {
  tone: "bad" | "warn" | "ok" | "idle";
  title: string;
  when: string;
  by?: string;
  body?: string | null;
  mono?: boolean;
  titleClass?: string;
  bodyClass?: string;
  children?: ReactNode;
}) {
  return (
    <li className="flex gap-3 px-3 py-2.5 text-sm">
      <span className="pt-1.5">
        <StatusDot tone={tone} />
      </span>
      <div className="min-w-0 flex-1">
        <p className="flex flex-wrap items-baseline gap-x-2">
          <span className={cn("font-medium", titleClass)}>{title}</span>
          <span className="font-mono text-xs text-muted-foreground">
            {when}
            {by && ` · ${by}`}
          </span>
        </p>
        {body && (
          <p
            className={cn(
              "mt-0.5 break-words whitespace-pre-wrap text-muted-foreground",
              mono && "font-mono text-xs",
              bodyClass,
            )}
          >
            {body}
          </p>
        )}
      </div>
      {children}
    </li>
  );
}

function TimelineRow({
  event,
  detail,
  me,
  now,
  onDelete,
}: {
  event: TimelineEvent;
  detail: IncidentDetail;
  me: string | undefined;
  now: number;
  onDelete: (id: string) => void;
}) {
  switch (event.type) {
    case "run": {
      const text = runText(event.run, now);
      const down = event.run.status === "DOWN";
      return (
        <Event
          tone={down ? "bad" : "ok"}
          titleClass={down ? "text-destructive" : "text-success"}
          title={text.title}
          when={text.when}
          body={text.body}
          mono
        />
      );
    }
    case "update":
      return (
        <Event
          tone="warn"
          title={UPDATE_LABEL[event.update.status]}
          when={stampTime(event.at, now)}
          by={displayHandle(null, event.update.author)}
          body={event.update.message}
        >
          {event.update.author === me && (
            <RowMenu
              label={`Options for the ${UPDATE_LABEL[event.update.status].toLowerCase()} update`}
              items={[
                {
                  label: "Delete",
                  destructive: true,
                  onSelect: () => onDelete(event.update.id),
                },
              ]}
            />
          )}
        </Event>
      );
    case "opened":
      return (
        <Event
          tone="bad"
          title="Opened"
          when={stampTime(event.at, now)}
          by="Krynodes"
          body={event.summary}
          bodyClass="text-destructive"
          mono
        />
      );
    case "resolved":
      return (
        <Event
          tone="ok"
          title="Resolved"
          when={stampTime(event.at, now)}
          by="Krynodes"
          body="The check passes again."
        />
      );
    case "lastGood":
      return (
        <Event
          tone="ok"
          titleClass="text-success"
          title="Last Good Check"
          when={
            event.latencyMs === null
              ? stampTime(event.at, now)
              : `${stampTime(event.at, now)} · ${event.latencyMs}ms`
          }
        />
      );
    case "action":
      return (
        <ActionLine
          action={event.action}
          nodeName={detail.incident.node_name}
          now={now}
        />
      );
  }
}

export function IncidentTimeline({ detail }: { detail: IncidentDetail }) {
  const session = useSession();
  const remove = useDeleteIncidentUpdate(detail.incident.id);
  const me = session.data?.identity?.email;
  const now = Date.now();
  return (
    <ol className="divide-y rounded-lg border bg-card">
      {timeline(detail).map((event) => (
        <TimelineRow
          key={`${event.type}-${event.at}-${event.type === "update" ? event.update.id : event.type === "action" ? event.action.id : ""}`}
          event={event}
          detail={detail}
          me={me}
          now={now}
          onDelete={(id) => remove.mutate(id)}
        />
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
      className="space-y-1.5"
      onSubmit={(event) => {
        event.preventDefault();
        post.mutate(
          { status, message: text },
          { onSuccess: () => setMessage("") },
        );
      }}
    >
      <div className="flex flex-wrap items-start gap-2 sm:flex-nowrap">
        <Select
          value={status}
          onValueChange={(value) => setStatus(value as IncidentUpdateStatus)}
        >
          <SelectTrigger
            aria-label="Status of this update"
            className="h-9 w-36 shrink-0"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUSES.map((value) => (
              <SelectItem key={value} value={value}>
                {UPDATE_LABEL[value]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <textarea
          aria-label="What is going on"
          value={message}
          rows={1}
          maxLength={LIMIT}
          placeholder="Write an update for this incident…"
          onChange={(event) => setMessage(event.target.value)}
          className="field-sizing-content max-h-60 min-h-9 w-full min-w-0 resize-none rounded-md border bg-transparent px-3 py-1.5 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 max-sm:order-last"
        />
        <Button
          type="submit"
          className="h-9 shrink-0"
          disabled={text.length === 0 || post.isPending}
        >
          {post.isPending ? "Posting…" : "Post Update"}
        </Button>
      </div>
      {post.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(post.error)}
        </p>
      )}
      {text.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {detail.public
            ? "This check is on the status page, so this update is public there."
            : "Only people who can open Krynodes see this."}{" "}
          It resolves by itself when the check passes.
        </p>
      )}
    </form>
  );
}
