import { ChevronRight } from "lucide-react";
import { useId, useState } from "react";

import { Input } from "@/components/ui/input";
import { containerNameProblem, containerNames } from "@/lib/stacks";
import { cn } from "@/lib/utils";

interface NamesInput {
  text: string;
  project: string;
  saved?: Record<string, string> | null;
  typed: Record<string, string>;
  taken: string[];
  server: string;
}

export function namesState({
  text,
  project,
  saved,
  typed,
  taken,
  server,
}: NamesInput) {
  const rows = containerNames(text, project, saved ?? {}, typed);
  const problems = rows.map((_, index) =>
    containerNameProblem(rows, index, taken, server),
  );
  return {
    rows,
    typed,
    problems,
    project,
    problem: problems.find((problem) => problem !== null) ?? null,
    arg: rows.map((row) => `${row.service}=${row.value}`).join(","),
  };
}

export type NamesState = ReturnType<typeof namesState> & {
  type: (service: string, value: string) => void;
};

export function useContainerNames(input: Omit<NamesInput, "typed">) {
  const [typed, setTyped] = useState<Record<string, string>>({});
  return {
    ...namesState({ ...input, typed }),
    type: (service: string, value: string) =>
      setTyped((now) => ({ ...now, [service]: value })),
  };
}

export function ContainerNames({ names }: { names: NamesState }) {
  const id = useId();
  if (names.rows.length === 0) return null;
  const wrong = names.problems.filter((problem) => problem !== null).length;
  return (
    <details className="group rounded-md border bg-card">
      <summary className="flex cursor-pointer list-none items-center gap-1.5 rounded-md py-1 pr-2.5 pl-1.5 text-sm outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden">
        <ChevronRight
          aria-hidden="true"
          className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-90"
        />
        Container Names
        <span
          className={cn(
            "ml-auto truncate font-mono text-xs",
            wrong > 0 ? "text-destructive" : "text-muted-foreground",
          )}
        >
          {wrong > 0
            ? `${wrong} to fix`
            : names.rows.length === 1
              ? names.rows[0]!.value
              : `${names.rows.length} containers`}
        </span>
      </summary>
      <div className="space-y-2 border-t px-2.5 py-2">
        {names.rows.map((row, index) => {
          const field = `${id}-${index}`;
          const problem = names.problems[index];
          return (
            <div
              key={row.service}
              className="grid gap-x-2.5 gap-y-1 sm:grid-cols-[7rem_minmax(0,1fr)] sm:items-center"
            >
              <label
                htmlFor={field}
                className="truncate font-mono text-xs text-muted-foreground"
              >
                {row.service}
              </label>
              <Input
                id={field}
                value={names.typed[row.service] ?? row.suggested}
                placeholder={row.suggested}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={problem !== null}
                aria-describedby={problem ? `${field}-problem` : undefined}
                onChange={(event) =>
                  names.type(row.service, event.target.value)
                }
                className="h-8 font-mono text-xs md:text-xs"
              />
              {problem && (
                <p
                  id={`${field}-problem`}
                  className="text-xs text-destructive sm:col-start-2"
                >
                  {problem}
                </p>
              )}
            </div>
          );
        })}
        <p className="text-xs text-muted-foreground">
          An empty box takes the suggestion. Folder and Docker project:{" "}
          <span className="font-mono">{names.project}</span>
        </p>
      </div>
    </details>
  );
}
