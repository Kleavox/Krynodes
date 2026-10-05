import { useEffect, useRef, useState } from "react";

import { useAction } from "@/lib/api";
import { isPending } from "@/lib/services";

import { useSignedAction } from "./use-signed-action";

export interface ComposeRead {
  compose: string;
  access: "contained" | "full" | "";
  files: { name: string; size: number }[];
  images: Record<string, string>;
}

function parse(output: string | null | undefined): ComposeRead | null {
  try {
    const value = JSON.parse(output ?? "") as ComposeRead;
    return typeof value.compose === "string" ? value : null;
  } catch {
    return null;
  }
}

export function useComposeRead(target: { nodeId: string; name: string }) {
  const run = useSignedAction(false);
  const [id, setId] = useState<string | null>(null);
  const action = useAction(id).data?.action;
  const started = useRef(false);
  const start = () => {
    setId(null);
    run.mutate(
      {
        action: "read",
        targets: [
          { nodeId: target.nodeId, kind: "compose", name: target.name },
        ],
      },
      { onSuccess: (batch) => setId(batch.actions[0]?.id ?? null) },
    );
  };
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    start();
  });
  const waiting =
    run.isPending || (id !== null && (!action || isPending(action)));
  const read =
    !waiting && action?.status === "done" ? parse(action.output) : null;
  const failure = run.error
    ? run.error
    : !waiting && action && !read
      ? new Error(action.output || "The server did not answer. Try again.")
      : null;
  return { waiting, read, failure, retry: start };
}
