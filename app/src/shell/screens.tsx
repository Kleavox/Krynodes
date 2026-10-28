import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export function Mark() {
  return (
    <span className="flex items-center gap-2 text-sm font-semibold tracking-tight">
      <svg
        viewBox="0 0 24 24"
        aria-hidden="true"
        className="size-5 shrink-0 text-primary"
      >
        <path
          d="M6 3.75v16.5M6 12 17.75 5M6 12l11.75 7"
          fill="none"
          stroke="currentColor"
          strokeWidth={3}
          strokeLinecap="round"
        />
        <circle cx="6" cy="12" r="3.1" fill="var(--primary-text)" />
        <circle cx="17.75" cy="5" r="2.75" fill="var(--primary-text)" />
        <circle cx="17.75" cy="19" r="2.75" fill="var(--primary-text)" />
      </svg>
      Krynodes
    </span>
  );
}

function CenteredScreen({
  title,
  body,
  action,
}: {
  title: string;
  body: ReactNode;
  action?: ReactNode;
}) {
  return (
    <main className="grid min-h-dvh place-items-center p-4">
      <div className="w-full max-w-sm rounded-lg border bg-card p-6">
        <Mark />
        <h1 className="mt-6 text-lg font-semibold">{title}</h1>
        <p className="mt-2 text-sm break-words text-muted-foreground">{body}</p>
        {action && <div className="mt-6">{action}</div>}
      </div>
    </main>
  );
}

export function GuestScreen() {
  return (
    <CenteredScreen
      title="Your Zero Trust session ended"
      body="Krynodes is behind Cloudflare Access. Reload to sign in again."
      action={
        <Button className="w-full" onClick={() => window.location.reload()}>
          Reload
        </Button>
      }
    />
  );
}

export function FaultScreen({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <CenteredScreen
      title="Krynodes can't load"
      body={message}
      action={<Button onClick={onRetry}>Retry</Button>}
    />
  );
}

export function ShellSkeleton() {
  return (
    <div role="status" aria-label="Loading Krynodes" className="min-h-dvh">
      <div className="flex h-12 items-center border-b bg-card px-4">
        <Mark />
      </div>
      <div className="mx-auto grid max-w-[1400px] gap-3 p-4 sm:grid-cols-2 md:p-6 xl:grid-cols-3">
        {[0, 1, 2].map((key) => (
          <Skeleton key={key} className="h-36" />
        ))}
      </div>
    </div>
  );
}
