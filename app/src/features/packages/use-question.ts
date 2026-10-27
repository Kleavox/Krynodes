import { useEffect, useRef, useState } from "react";

import { useAction, useAskApt } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { isPending } from "@/lib/services";

type Question = Parameters<ReturnType<typeof useAskApt>["mutate"]>[0];

function answerOf<T>(output: string | null): T | null {
  if (!output) return null;
  try {
    return JSON.parse(output) as T;
  } catch {
    return null;
  }
}

export function useQuestion<T>(first?: Question) {
  const send = useAskApt();
  const [id, setId] = useState<string | null>(null);
  const reply = useAction(id);
  const asked = useRef(false);
  const action = id === null ? undefined : reply.data?.action;
  const ended = action !== undefined && !isPending(action);
  const ask = (question: Question) => {
    setId(null);
    send.mutate(question, {
      onSuccess: (sent) => setId(sent.actions[0]?.id ?? null),
    });
  };
  useEffect(() => {
    if (!first || asked.current) return;
    asked.current = true;
    ask(first);
  });
  return {
    ask,
    value: action?.status === "done" ? answerOf<T>(action.output) : null,
    waiting:
      (first !== undefined && send.isIdle) ||
      send.isPending ||
      (id !== null && !ended),
    error: send.error
      ? errorMessage(send.error)
      : action && ended && action.status !== "done"
        ? action.output || "No answer came back."
        : null,
  };
}
