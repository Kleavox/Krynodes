import {
  joinFingerprint,
  NETWORK,
  networkInspectSchema,
  networkPreparedSchema,
  networkProbeSchema,
  networkRekeySchema,
  type NetworkDocument,
  type NetworkInspect,
} from "@krynodes/protocol";

import type { ActionRow, FleetNode, JoinRequest } from "../types";
import { networkApi } from "./api";
import { onNetworkChange } from "./live";
import {
  appliedText,
  withNewKey,
  listeners,
  newDocument,
  nextOf,
  pickMtu,
  probeArrived,
  probePlan,
  randomUnit,
  rangeFor,
  withJoiner,
} from "./network";
import {
  browserStore,
  checkAnchor,
  checkBase,
  fingerprintOf,
  hashOf,
  remember,
  type PinStore,
  type Unchecked,
} from "./pins";
import {
  buildCommand,
  openSession,
  signCommand,
  signDocument,
  type Session,
} from "./sign";

export { fingerprintOf };

const POLL_MS = 2_000;
const TRIES = Math.ceil((NETWORK.answerSeconds * 1000) / POLL_MS);
const APPLIED_MS = 5_000;

export type ApproveStep =
  | { kind: "session" }
  | { kind: "inspect" }
  | { kind: "prepare" }
  | { kind: "probe" }
  | { kind: "sign" }
  | { kind: "applied"; members: { name: string; state: string }[] };

const SIGN = { openSession, buildCommand, signCommand, signDocument };

type Api = typeof networkApi;

export interface ApproveDeps {
  onStep: (step: ApproveStep) => void;
  api?: Pick<
    Api,
    | "nodes"
    | "network"
    | "applied"
    | "next"
    | "current"
    | "postDocument"
    | "sendAction"
    | "actions"
  >;
  sign?: typeof SIGN;
  random?: () => number;
  pause?: (milliseconds: number) => Promise<void>;
  changes?: (listener: () => void) => () => void;
  check?: Check;
  store?: PinStore | null;
}

type Check = (members: Unchecked[]) => Promise<boolean>;

type Anchored = Pick<ApproveDeps, "check" | "store">;

const refuse: Check = async () => false;

const storeOf = (deps: Anchored) =>
  deps.store === undefined ? browserStore() : deps.store;

async function anchored(
  current: { document: NetworkDocument; hash: string },
  deps: Anchored,
) {
  const { check = refuse } = deps;
  const store = storeOf(deps);
  const unchecked = await checkAnchor(current, store);
  if (unchecked.length > 0 && !(await check(unchecked))) {
    throw new Error("The fingerprints were not confirmed. Nothing was signed.");
  }
  remember(store, unchecked, {
    version: current.document.version,
    hash: current.hash,
  });
  return store;
}

async function signLast(
  sign: typeof SIGN,
  access: string[],
  document: NetworkDocument,
  failed: string,
) {
  try {
    return await sign.signDocument(await sign.openSession(access), document);
  } catch (error) {
    throw new Error(failed, { cause: error });
  }
}

const wait = (milliseconds: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

const changedMeanwhile = () =>
  new Error("Someone changed the network meanwhile. Open it again.");

async function rekeyAnswer(parsed: unknown, name: string, sealKey: string) {
  const read = networkRekeySchema.safeParse(parsed);
  if (!read.success) {
    throw new Error(`${name} sent an answer Krynodes cannot read.`);
  }
  const { key, signer } = read.data;
  return {
    key,
    signer,
    ...(await fingerprintOf({ name, kind: "server", key, signer, sealKey })),
  };
}

function signers(
  nodes: FleetNode[],
  machines: { node: string; name: string }[],
) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  let shared: string[] | null = null;
  for (const machine of machines) {
    const node = byId.get(machine.node);
    if (!node) throw new Error(`${machine.name} was not found.`);
    if (!node.trust) {
      throw new Error(`${node.name} has not reported its trust yet.`);
    }
    const access = node.trust.access;
    shared =
      shared === null ? access : shared.filter((id) => access.includes(id));
  }
  if (!shared?.length) {
    throw new Error(
      "None of your passkeys has access to every server in the network. Change access in Passkeys.",
    );
  }
  return shared;
}

const answer = (row: ActionRow) => {
  try {
    return JSON.parse(row.message ?? "") as unknown;
  } catch {
    return undefined;
  }
};

const commander =
  (
    api: Pick<Api, "sendAction" | "actions">,
    sign: typeof SIGN,
    open: () => Promise<Session>,
    pause: (milliseconds: number) => Promise<void>,
  ) =>
  async (
    target: { node: string; name: string },
    action: string,
    title: string,
    args?: Record<string, string>,
  ) => {
    const id = crypto.randomUUID();
    const session = await open();
    const signed = await sign.signCommand(
      session,
      sign.buildCommand(session, {
        id,
        nodeId: target.node,
        kind: "network",
        name: NETWORK.interface,
        action,
        args,
      }),
    );
    let row = await api.sendAction({
      id,
      nodeId: target.node,
      kind: "network",
      name: NETWORK.interface,
      action,
      title,
      signed,
    });
    for (let tries = 0; row.status === "sent" || row.status === "running";) {
      if ((tries += 1) > TRIES) {
        throw new Error(`${target.name} did not answer.`);
      }
      await pause(POLL_MS);
      row =
        (await api.actions(target.node)).find((one) => one.id === id) ?? row;
    }
    if (row.status === "failed") {
      throw new Error(row.message ?? `${target.name} could not finish.`);
    }
    return answer(row);
  };

export async function renewKeys(
  node: string,
  confirm: (shown: { fingerprint: string; line: string }) => Promise<boolean>,
  deps: Pick<ApproveDeps, "sign" | "pause"> &
    Anchored & {
      api?: Pick<
        Api,
        "current" | "nodes" | "postDocument" | "sendAction" | "actions"
      >;
    } = {},
): Promise<number | null> {
  const { api = networkApi, sign = SIGN, pause = wait } = deps;
  const [current, nodes] = await Promise.all([api.current(), api.nodes()]);
  if (!current) throw new Error("There is no private network.");
  const member = current.document.members.find((one) => one.node === node);
  if (!member) throw new Error("That machine is not in the private network.");
  if (member.kind === "laptop") {
    throw new Error(
      `${member.name} is a laptop. Only a server makes new keys here.`,
    );
  }
  if (!nodes.find((one) => one.id === node)?.online) {
    throw new Error(`${member.name} is offline.`);
  }
  const access = signers(nodes, current.document.members);
  const store = await anchored(current, deps);
  const made = await rekeyAnswer(
    await commander(
      api,
      sign,
      () => sign.openSession(access),
      pause,
    )(member, "rekey", "Make New Network Keys"),
    member.name,
    member.sealKey,
  );
  const document = withNewKey(nextOf(current), node, made.key, made.signer);
  if (!(await confirm({ fingerprint: made.fingerprint, line: made.line }))) {
    return null;
  }
  const { version } = await api.postDocument({
    signed: await signLast(
      sign,
      access,
      document,
      `${member.name} made new keys, but the network document was not signed. Open New Keys again to finish.`,
    ),
    change: `Use new keys for ${member.name}`,
    detail: null,
  });
  remember(store, [{ node, fingerprint: made.fingerprint }], {
    version: document.version,
    hash: await hashOf(document),
  });
  return version;
}

export async function changeNetwork(
  edit: (next: NetworkDocument) => NetworkDocument,
  change: string,
  deps: Pick<ApproveDeps, "sign"> &
    Anchored & {
      api?: Pick<Api, "current" | "nodes" | "postDocument">;
      detail?: string | null;
    } = {},
): Promise<number> {
  const { api = networkApi, sign = SIGN, detail = null } = deps;
  const [current, nodes] = await Promise.all([api.current(), api.nodes()]);
  if (!current) throw new Error("There is no private network.");
  const document = edit(nextOf(current));
  const trusted = new Set(
    nodes.filter((node) => node.trust).map((node) => node.id),
  );
  const access = signers(
    nodes,
    document.deleted
      ? current.document.members.filter((member) => trusted.has(member.node))
      : document.members,
  );
  const store = await anchored(current, deps);
  const session = await sign.openSession(access);
  const { version } = await api.postDocument({
    signed: await sign.signDocument(session, document),
    change,
    detail,
  });
  remember(store, [], {
    version: document.version,
    hash: await hashOf(document),
  });
  return version;
}

export async function approve(
  request: JoinRequest,
  expected: string,
  deps: ApproveDeps,
): Promise<number> {
  const {
    onStep,
    api = networkApi,
    sign = SIGN,
    random = randomUnit,
    pause = wait,
    changes = onNetworkChange,
  } = deps;
  const { name } = request;
  const different = () =>
    new Error(`${name} reported different keys; nothing was changed`);
  if ((await fingerprintOf(request)).fingerprint !== expected) {
    throw different();
  }
  const sealKey = request.sealKey!;
  if (!request.ready) {
    throw new Error(
      request.reason
        ? `${name} cannot join: ${request.reason}`
        : `${name} is not ready to join the private network.`,
    );
  }
  const [nodes, view] = await Promise.all([api.nodes(), api.network()]);
  const creating = !view.network || view.network.deleted;
  const laptop = request.kind === "laptop";
  if (creating && laptop) {
    throw new Error(
      "A private network starts with a server. Approve a server first.",
    );
  }
  const current = creating ? null : await api.current();
  if (!creating && !current) throw changedMeanwhile();
  const access = signers(nodes, [
    request,
    ...(current?.document.members ?? []),
  ]);
  const store = current ? await anchored(current, deps) : storeOf(deps);
  const open = () => sign.openSession(access);
  await open();
  onStep({ kind: "session" });

  const command = commander(api, sign, open, pause);
  const joiner = { node: request.node, name };
  const unreadable = () =>
    new Error(`${name} sent an answer Krynodes cannot read.`);
  const same = async (key: string, signer: string) => {
    if ((await joinFingerprint(key, signer, sealKey)) !== expected) {
      throw different();
    }
  };

  let range = current?.document.range ?? "";
  let port = current?.document.port ?? NETWORK.port;
  let mtu = current?.document.mtu ?? 1420;
  let keys: { key: string; signer: string; port: number } | null = null;
  let endpoint: string | null = null;
  let inspected: NetworkInspect | null = null;
  if (!laptop) {
    onStep({ kind: "inspect" });
    const read = networkInspectSchema.safeParse(
      await command(joiner, "inspect", `Check ${name} for the private network`),
    );
    if (!read.success) throw unreadable();
    inspected = read.data;
    if (creating) {
      range = rangeFor(inspected.used, random);
      port = inspected.port ?? NETWORK.port;
      mtu = pickMtu([inspected.mtu]);
    }
  }

  const next = await api.next([request.node], creating ? range : undefined);
  const previous =
    next.document && next.hash
      ? { document: next.document, hash: next.hash }
      : null;
  if (creating && previous) checkBase(previous, store);
  const parent = current?.hash ?? previous?.hash;

  if (inspected) {
    onStep({ kind: "prepare" });
    const prepared = networkPreparedSchema.safeParse(
      await command(
        joiner,
        "prepare",
        `Prepare ${name} for the private network`,
        {
          range,
          port: String(port),
          ...(parent ? { parent } : {}),
        },
      ),
    );
    if (!prepared.success) throw unreadable();
    keys = prepared.data;
    await same(keys.key, keys.signer);

    const found = inspected.public ?? next.seen?.[request.node] ?? null;
    const online = new Set(
      nodes.filter((node) => node.online).map((node) => node.id),
    );
    const heard = current ? listeners(current.document, online) : [];
    let reached = heard.length === 0;
    if (found && heard.length > 0) {
      onStep({ kind: "probe" });
      const names = new Map(heard.map((member) => [member.node, member.name]));
      const plan = probePlan(
        { node: request.node, port: keys.port, public: found },
        heard,
      );
      await open();
      const [own] = await Promise.allSettled(
        plan.map((entry) =>
          command(
            { node: entry.node, name: names.get(entry.node) ?? name },
            "probe",
            `Check that ${name} can be reached`,
            entry.args,
          ),
        ),
      );
      const probe =
        own?.status === "fulfilled"
          ? networkProbeSchema.safeParse(own.value)
          : null;
      reached =
        probe?.success === true && probeArrived(heard, probe.data.arrived);
    }
    endpoint = found && reached ? `${found}:${keys.port}` : null;
  }

  const reported = next.prepared[request.node];
  if (!keys && reported?.key && reported.signer && reported.port !== null) {
    keys = { key: reported.key, signer: reported.signer, port: reported.port };
  }
  if (!keys) throw different();
  await same(keys.key, keys.signer);
  const document = await withJoiner(
    current ? nextOf(current) : newDocument(range, port, mtu, previous),
    {
      node: request.node,
      name,
      key: keys.key,
      signer: keys.signer,
      sealKey,
      port: keys.port,
      endpoint,
      nat: endpoint === null,
      ...(laptop ? { kind: "laptop" as const } : {}),
    },
    next.addresses[request.node] ?? "",
  );

  onStep({ kind: "sign" });
  const { version } = await api.postDocument({
    signed: await signLast(
      sign,
      access,
      document,
      laptop
        ? "The network document was not signed. Nothing was changed."
        : `${name} is prepared, but the network document was not signed. Approve it again.`,
    ),
    change: creating
      ? `Create the private network with ${name}`
      : laptop
        ? `Add the laptop ${name} to the private network`
        : `Add ${name} to the private network`,
    detail: null,
  });
  remember(store, [{ node: request.node, fingerprint: expected }], {
    version: document.version,
    hash: await hashOf(document),
  });

  const deadline = Date.now() + NETWORK.answerSeconds * 1000;
  for (;;) {
    const latest = await api.applied();
    const rows = latest.members
      .filter((member) => member.online)
      .map((member) => ({
        name: member.name,
        state: appliedText(member, version),
      }));
    onStep({ kind: "applied", members: rows });
    const left = deadline - Date.now();
    if (rows.every((row) => row.state !== "Applying…") || left <= 0) {
      return version;
    }
    await new Promise<void>((resolve) => {
      const wake = () => {
        clearTimeout(timer);
        off();
        resolve();
      };
      const timer = setTimeout(wake, Math.min(APPLIED_MS, left));
      const off = changes(wake);
    });
  }
}
