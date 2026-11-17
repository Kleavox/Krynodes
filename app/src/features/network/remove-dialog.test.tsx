import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DeleteNodeDialog } from "@/features/nodes/delete-node-dialog";
import { queryKeys } from "@/lib/query-client";
import type {
  DeviceRecord,
  NetworkServer,
  NetworkView,
  NodeRecord,
  ServicesResponse,
} from "@/types";

import { DeleteDialog } from "./delete-dialog";
import { RemoveDialog } from "./remove-dialog";
import type { Change } from "./use-network-sign";

const seen = vi.hoisted(() => ({
  presses: [] as (() => void)[],
  signed: [] as unknown[],
}));

vi.mock("@/components/ui/button", () => ({
  Button: ({
    onClick,
    children,
  }: {
    onClick?: () => void;
    children?: ReactNode;
  }) => {
    if (onClick) seen.presses.push(onClick);
    return <button>{children}</button>;
  },
}));

vi.mock("@/components/ui/dialog", async (original) => {
  const pass = ({ children }: { children?: ReactNode }) => <>{children}</>;
  return {
    ...(await original<typeof import("@/components/ui/dialog")>()),
    Dialog: pass,
    DialogClose: pass,
    DialogContent: pass,
    DialogDescription: pass,
    DialogFooter: pass,
    DialogHeader: pass,
    DialogTitle: pass,
  };
});

vi.mock("@/components/ui/alert-dialog", async (original) => {
  const pass = ({ children }: { children?: ReactNode }) => <>{children}</>;
  return {
    ...(await original<typeof import("@/components/ui/alert-dialog")>()),
    AlertDialog: pass,
    AlertDialogCancel: pass,
    AlertDialogContent: pass,
    AlertDialogDescription: pass,
    AlertDialogFooter: pass,
    AlertDialogHeader: pass,
    AlertDialogTitle: pass,
  };
});

vi.mock("./use-network-sign", async (original) => ({
  ...(await original<typeof import("./use-network-sign")>()),
  useSignChange: () => ({
    mutate: (input: unknown) => seen.signed.push(input),
    reset: () => undefined,
    isPending: false,
    error: null,
  }),
}));

const LEAVING = "11111111-1111-4111-8111-111111111111";
const STAYING = "22222222-2222-4222-8222-222222222222";
const OTHER = "33333333-3333-4333-8333-333333333333";

const server = (nodeId: string, name: string, address: string) =>
  ({
    nodeId,
    name,
    state: "in",
    address,
    port: 51820,
    mtu: null,
    key: "k",
    signer: "s",
    endpoint: "203.0.113.10:51820",
    nat: false,
    announced: null,
    since: "2026-11-16T10:00:00Z",
    joinedAt: "2026-11-16T10:00:00Z",
    points: [],
  }) satisfies NetworkServer;

const members = [
  server(LEAVING, "server-1", "10.88.0.1"),
  server(STAYING, "server-2", "10.88.0.2"),
  server(OTHER, "server-3", "10.88.0.3"),
];

const view = {
  network: null,
  version: 3,
  document: null,
  body: null,
  quarantined: [],
  wrongPorts: [],
  members,
  waiting: [],
  links: [],
  laptops: [],
} as unknown as NetworkView;

const report = (id: string, access: string[]) =>
  ({
    id,
    sealKey: null,
    trust: { version: 1, core: access, access },
  }) as unknown as ServicesResponse["nodes"][number];

const node = {
  id: LEAVING,
  name: "server-1",
} as unknown as NodeRecord;

const TOLD =
  "server-1 does not trust this passkey and will not take down its own network. Every other server drops it at once.";

function pressed(child: ReactNode, access: Record<string, string[]>) {
  const client = new QueryClient();
  client.setQueryData(queryKeys.devices, {
    devices: [
      { id: "phone", fingerprint: "p", mine: true } as DeviceRecord,
      { id: "key", fingerprint: "q", mine: true } as DeviceRecord,
    ],
  });
  client.setQueryData(queryKeys.services, {
    nodes: Object.entries(access).map(([id, prints]) => report(id, prints)),
    actions: [],
  });
  client.setQueryData(queryKeys.network, view);
  seen.presses = [];
  seen.signed = [];
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <QueryClientProvider client={client}>{child}</QueryClientProvider>
    </MemoryRouter>,
  );
  for (const press of seen.presses) press();
  return { html, signed: seen.signed as Change[] };
}

const lying = { [LEAVING]: [], [STAYING]: ["p", "q"], [OTHER]: ["p"] };
const honest = {
  [LEAVING]: ["q"],
  [STAYING]: ["p", "q"],
  [OTHER]: ["p", "q"],
};

const removeDialog = (
  <RemoveDialog
    server={members[0]!}
    view={view}
    nodes={[node]}
    onClose={() => undefined}
  />
);
const deleteNode = (
  <DeleteNodeDialog node={node} open onOpenChange={() => undefined} />
);

describe("Remove Server picks signers from the servers that stay", () => {
  beforeEach(() => {
    seen.signed = [];
  });

  for (const [title, dialog] of [
    ["Remove", removeDialog],
    ["Delete Node", deleteNode],
  ] as const) {
    it(`${title}: signs with the others' passkeys when the leaving server reports an empty access list, and says so`, () => {
      const { html, signed } = pressed(dialog, lying);
      expect(signed).toHaveLength(1);
      expect(signed[0]).toMatchObject({
        change: { kind: "remove", nodeId: LEAVING },
        signers: ["phone"],
      });
      expect(html).toContain(TOLD);
    });

    it(`${title}: prefers a passkey the leaving server trusts too, so it leaves cleanly`, () => {
      const { html, signed } = pressed(dialog, honest);
      expect(signed).toHaveLength(1);
      expect(signed[0]).toMatchObject({
        change: { kind: "remove", nodeId: LEAVING },
        signers: ["key"],
      });
      expect(html).not.toContain(TOLD);
    });
  }
});

describe("Delete Network", () => {
  it("names the server whose removal opens the way when no passkey reaches every server", () => {
    const { signed } = pressed(
      <DeleteDialog
        view={view}
        presence={{}}
        checks={[]}
        nodes={[]}
        onClose={() => undefined}
      />,
      lying,
    );
    expect(signed).toHaveLength(1);
    expect(signed[0]).toMatchObject({
      change: { kind: "delete" },
      signers: [],
      refusal:
        "server-1 trusts none of the passkeys the others trust. Remove it from the network first, then delete the network.",
    });
  });
});
