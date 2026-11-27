import type { NetworkDocument } from "@krynodes/protocol";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";

import { Busy } from "@/components/busy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ActionBody, type RunState } from "@/features/actions/action-dialog";
import { runAction } from "@/features/actions/run-action";
import { useFleet } from "@/features/fleet/use-fleet";
import { useOneTimeCheck } from "@/features/network/one-time-check";
import { useCurrentDocument } from "@/features/network/use-network";
import { useRefreshStacks } from "@/lib/api";
import { failure } from "@/lib/passkeys";
import {
  ACCESS_LINES,
  buildStackArgs,
  type ReadStack,
  type SealDeps,
  type StackForm,
  CONNECTIONS_LINE,
  portAllowed,
  publishedPorts,
  readStack,
  stackNameValid,
  type Access,
} from "@/lib/stacks";
import type { ActionRow, FleetNode, StackNode } from "@/types";

const FIELD =
  "w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 dark:bg-input/30";

export function AccessChoice({
  value,
  onChange,
}: {
  value: Access;
  onChange: (access: Access) => void;
}) {
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">Access</legend>
      {(["contained", "full"] as const).map((access) => (
        <label key={access} className="flex items-start gap-2 text-sm">
          <input
            type="radio"
            name="stack-access"
            value={access}
            checked={value === access}
            onChange={() => onChange(access)}
            className="mt-1"
          />
          <span>
            <span className="font-medium">
              {access === "contained" ? "Contained" : "Full"}
            </span>
            <span className="block text-muted-foreground">
              {ACCESS_LINES[access]}
            </span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

export function PortChoices({
  ports,
  network,
  nodeId,
  document,
  onChange,
}: {
  ports: number[];
  network: number[];
  nodeId: string;
  document: NetworkDocument | undefined;
  onChange: (port: number, shared: boolean) => void;
}) {
  if (ports.length === 0) return null;
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">Published Ports</p>
      <ul className="space-y-2">
        {ports.map((port) => {
          const shared = network.includes(port);
          return (
            <li key={port} className="space-y-1">
              <div className="flex items-center gap-3">
                <span className="w-16 font-mono text-sm">{port}</span>
                <Select
                  value={shared ? "network" : "local"}
                  onValueChange={(value) => onChange(port, value === "network")}
                >
                  <SelectTrigger aria-label={`Port ${port}`} className="w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="local">Local Only</SelectItem>
                    <SelectItem value="network">Private Network</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {shared && !portAllowed(document, nodeId, port) && (
                <p className="text-xs text-muted-foreground">
                  {CONNECTIONS_LINE}{" "}
                  <Link to="/network" className="text-primary-text underline">
                    Open Connections
                  </Link>
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export interface Editing {
  entry: StackNode;
  project: string;
}

export interface ReadState {
  started: string | null;
  done: boolean;
  edited: boolean;
}

export const readKey = (project?: string, nodeId?: string) =>
  project && nodeId ? `${nodeId}/${project}` : null;

export const shouldStartRead = (key: string | null, state: ReadState) =>
  key !== null && !state.done && !state.edited && state.started !== key;

export const shouldPrefill = (state: ReadState) => !state.edited;

export function readForEdit(
  client: QueryClient,
  node: FleetNode,
  project: string,
  signal?: AbortSignal,
  deps?: SealDeps,
): Promise<ReadStack> {
  return runAction(
    client,
    node,
    {
      kind: "stack",
      action: "read",
      name: project,
      title: `Read Compose of ${project}`,
    },
    undefined,
    signal,
    deps,
  ).then((row) => {
    if (row.status === "failed") {
      throw new Error(
        [row.message ?? "The compose file could not be read.", row.output]
          .filter(Boolean)
          .join(" "),
      );
    }
    return readStack(row.output);
  });
}

export function saveStack(
  client: QueryClient,
  node: FleetNode,
  request: {
    name: string;
    editing: boolean;
    form: StackForm;
    deps?: SealDeps;
  },
  onLine?: (line: string) => void,
  signal?: AbortSignal,
): Promise<ActionRow> {
  const { name, editing, form, deps } = request;
  return buildStackArgs(form, node, deps).then((args) =>
    runAction(
      client,
      node,
      {
        kind: "stack",
        action: editing ? "edit" : "create",
        name,
        title: editing ? `Edit Compose of ${name}` : `New Stack ${name}`,
        args,
      },
      onLine,
      signal,
      deps,
    ),
  );
}

export function NewStackDialog({
  servers,
  editing,
  onClose,
}: {
  servers: StackNode[];
  editing?: Editing;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const fleet = useFleet();
  const document = useCurrentDocument().data?.document;
  const refresh = useRefreshStacks();
  const { check, panel, checking } = useOneTimeCheck();
  const ready = servers.filter((one) => one.online && one.docker === "ready");
  const [server, setServer] = useState(
    editing?.entry.nodeId ?? ready[0]?.nodeId ?? "",
  );
  const [name, setName] = useState(editing?.project ?? "");
  const [title, setTitle] = useState("");
  const [compose, setCompose] = useState("");
  const [access, setAccess] = useState<Access>("contained");
  const [network, setNetwork] = useState<number[]>([]);
  const [env, setEnv] = useState("");
  const [stored, setStored] = useState<string[]>([]);
  const [loading, setLoading] = useState(Boolean(editing));
  const [state, setState] = useState<RunState>({ phase: "confirm", lines: [] });
  const quit = useRef<AbortController | null>(null);
  const node = fleet.data?.find((one) => one.id === server);
  const ports = publishedPorts(compose);

  useEffect(() => () => quit.current?.abort(), []);

  const key = readKey(editing?.project, editing ? node?.id : undefined);
  const plan = useRef<ReadState>({ started: null, done: false, edited: false });
  const latest = useRef({ node, editing });
  latest.current = { node, editing };
  const edit =
    <T,>(set: (value: T) => void) =>
    (value: T) => {
      plan.current.edited = true;
      set(value);
    };
  const gone = Boolean(editing && fleet.data && !node);
  useEffect(() => {
    if (gone && loading && !plan.current.done) {
      setLoading(false);
      setState({
        phase: "result",
        lines: [],
        error: `${latest.current.editing?.entry.name ?? "The server"} is offline.`,
      });
    }
  }, [gone, loading]);
  useEffect(() => {
    const { node: from, editing: asked } = latest.current;
    if (!from || !asked || !shouldStartRead(key, plan.current)) return;
    plan.current.started = key;
    const controller = new AbortController();
    const live = () => !controller.signal.aborted;
    void readForEdit(client, from, asked.project, controller.signal, { check })
      .then((read) => {
        if (!live()) return;
        plan.current.done = true;
        if (!shouldPrefill(plan.current)) return;
        setCompose(read.compose);
        setAccess(read.access);
        setTitle(read.title);
        setNetwork(read.network);
        setStored(read.env);
      })
      .catch((error: unknown) => {
        if (live()) {
          setState({ phase: "result", lines: [], error: failure(error) });
        }
      })
      .finally(() => {
        if (live()) setLoading(false);
      });
    return () => {
      controller.abort();
      if (!plan.current.done) plan.current.started = null;
    };
  }, [client, key, check]);

  const busy = state.phase === "sending";
  const save = () => {
    if (!node) return;
    if (!stackNameValid(name)) {
      setState({
        phase: "confirm",
        lines: [],
        error:
          "A name uses lowercase letters, digits, - and _, and starts with a letter or digit.",
      });
      return;
    }
    setState({ phase: "sending", lines: [] });
    quit.current = new AbortController();
    const signal = quit.current.signal;
    void saveStack(
      client,
      node,
      {
        name,
        editing: Boolean(editing),
        form: {
          compose,
          access,
          network: network.filter((port) => ports.includes(port)),
          title,
          env,
        },
        deps: { check },
      },
      (line) => setState((now) => ({ ...now, lines: [...now.lines, line] })),
      signal,
    ).then(
      (row) => {
        setState((now) => ({ ...now, phase: "result", row }));
        refresh();
      },
      (error: unknown) =>
        setState((now) => ({
          ...now,
          phase: "result",
          error: failure(error),
        })),
    );
  };

  const editable = state.phase === "confirm" && !loading;
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent
        className="max-h-[90dvh] overflow-y-auto sm:max-w-2xl"
        showCloseButton={!busy}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>
            {editing ? `Edit Compose of ${editing.project}` : "New Stack"}
          </DialogTitle>
          <DialogDescription>
            The compose file, its settings and the sealed .env are signed with
            your passkey. The server checks them before anything runs.
          </DialogDescription>
        </DialogHeader>
        {loading && (
          <p role="status" className="text-sm text-muted-foreground">
            <Busy>{`Reading the compose file of ${name}`}</Busy>
          </p>
        )}
        {editable && (
          <div className="space-y-4">
            {!editing &&
              (ready.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No online server has Docker ready.
                </p>
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="stack-server">Server</Label>
                  <Select value={server} onValueChange={setServer}>
                    <SelectTrigger id="stack-server" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {ready.map((one) => (
                        <SelectItem key={one.nodeId} value={one.nodeId}>
                          {one.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ))}
            {!editing && (
              <div className="space-y-2">
                <Label htmlFor="stack-name">Name</Label>
                <Input
                  id="stack-name"
                  value={name}
                  maxLength={63}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => setName(event.target.value)}
                />
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="stack-title">Title</Label>
              <Input
                id="stack-title"
                value={title}
                maxLength={64}
                onChange={(event) => edit(setTitle)(event.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="stack-compose">Compose File</Label>
              <textarea
                id="stack-compose"
                rows={12}
                spellCheck={false}
                className={FIELD}
                value={compose}
                onChange={(event) => edit(setCompose)(event.target.value)}
              />
            </div>
            <AccessChoice value={access} onChange={edit(setAccess)} />
            <PortChoices
              ports={ports}
              network={network}
              nodeId={server}
              document={document}
              onChange={(port, shared) =>
                edit(setNetwork)((now: number[]) =>
                  shared
                    ? [...now.filter((one) => one !== port), port]
                    : now.filter((one) => one !== port),
                )
              }
            />
            <div className="space-y-2">
              <Label htmlFor="stack-env">.env</Label>
              <textarea
                id="stack-env"
                rows={4}
                spellCheck={false}
                autoComplete="off"
                className={FIELD}
                value={env}
                onChange={(event) => edit(setEnv)(event.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                {editing
                  ? stored.length > 0
                    ? `The stored .env sets ${stored.join(", ")}. Leave this blank to keep it.`
                    : "Leave this blank to keep the stored .env."
                  : "Sealed in this browser to the server's own key. The Worker never reads it."}
              </p>
            </div>
          </div>
        )}
        {panel}
        <ActionBody
          state={checking ? { ...state, phase: "confirm" } : state}
          name={node?.name ?? "the server"}
        />
        <DialogFooter>
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            {state.phase === "confirm" ? "Cancel" : "Close"}
          </Button>
          {editable && (
            <Button disabled={!node || compose.trim() === ""} onClick={save}>
              {editing ? "Save and Deploy" : "Create Stack"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
