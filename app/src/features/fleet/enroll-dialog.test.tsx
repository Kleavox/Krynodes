import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import type { Device, Enrollment, JoinRequest } from "@/types";

import {
  Arrived,
  chosenPasskeys,
  EnrollForm,
  enrollStep,
  Install,
} from "./enroll-dialog";

const none = () => {};

const enrollment: Enrollment = {
  id: "enrollment-1",
  command: "curl -fsSL https://kry.example.test/i/token-1 | sudo sh",
  expiresAt: "2026-11-22T11:00:00Z",
};

const device = (id: string, name: string): Device => ({
  id,
  name,
  alg: -7,
  publicKey: `${id}-key`,
  synced: false,
  createdAt: "2026-11-01T00:00:00Z",
  trusted: false,
});

const devices = [device("key-1", "Laptop"), device("key-2", "Security Key")];

const form = (list: Device[], error: Error | null = null) =>
  renderToStaticMarkup(
    <MemoryRouter>
      <EnrollForm
        devices={list}
        pending={false}
        error={error}
        onCancel={none}
        onCreate={none}
      />
    </MemoryRouter>,
  );

describe("which step the enroll dialog shows", () => {
  it("asks first, shows the command until the server arrives, then moves on", () => {
    expect(enrollStep(undefined, undefined)).toBe("form");
    expect(enrollStep(enrollment, undefined)).toBe("waiting");
    expect(enrollStep(enrollment, null)).toBe("waiting");
    expect(enrollStep(enrollment, "node-1")).toBe("enrolled");
  });
});

describe("the install step", () => {
  it("enroll shows the command and waits for the server", () => {
    const html = renderToStaticMarkup(
      <Install enrollment={enrollment} onClose={none} />,
    );
    expect(html).toContain(enrollment.command);
    expect(html).toContain("Copy Command");
    expect(html).toContain("Waiting for the server to enroll");
  });
});

const asked: JoinRequest = {
  node: "node-2",
  name: "server-2",
  kind: "server",
  hostname: null,
  os: null,
  key: null,
  signer: null,
  sealKey: null,
  ready: true,
  reason: null,
  since: "2026-11-22T10:00:00Z",
};

const arrived = (
  network: boolean | undefined,
  request: JoinRequest | undefined,
) =>
  renderToStaticMarkup(
    <MemoryRouter>
      <Arrived
        name="server-2"
        nodeId="node-2"
        network={network}
        request={request}
        onApprove={none}
        onClose={none}
      />
    </MemoryRouter>,
  );

describe("the arrival step", () => {
  it("links to the server that enrolled", () => {
    const html = arrived(false, undefined);
    expect(html).toContain('href="#server-node-2"');
    expect(html).toContain("Show server-2");
  });

  it("Approve is offered only when a network exists", () => {
    const joining = arrived(true, asked);
    expect(joining).toContain("server-2 asked to join the private network.");
    expect(joining).toMatch(/<button[^>]*>Approve<\/button>/u);
    expect(joining).toContain("Not Now");
    const alone = arrived(false, asked);
    expect(alone.replace(/<[^>]+>/gu, "")).toContain(
      "Create a private network on the Network page to connect your servers.",
    );
    expect(alone).toContain('href="/network"');
    expect(alone).not.toContain("Approve");
    expect(arrived(true, undefined)).toMatch(
      /<button[^>]*disabled=""[^>]*>Approve<\/button>/u,
    );
  });

  it("says why Approve waits, and nothing about creating a network while it loads", () => {
    const unlisted = arrived(true, undefined);
    expect(unlisted).toContain("Waiting for server-2 to ask to join.");
    expect(unlisted).not.toContain("asked to join the private network");
    const blocked = arrived(true, {
      ...asked,
      ready: false,
      reason: "WireGuard is not installed.",
    });
    expect(blocked).toContain(
      "server-2 cannot join yet: WireGuard is not installed.",
    );
    expect(blocked).toMatch(/<button[^>]*disabled=""[^>]*>Approve<\/button>/u);
    expect(arrived(true, { ...asked, ready: false })).toContain(
      "server-2 is not ready to join yet.",
    );
    const loading = arrived(undefined, asked);
    expect(loading).not.toContain("Create a private network");
    expect(loading).not.toContain("Approve");
    expect(loading).toContain("Show server-2");
  });
});

describe("the enroll form", () => {
  it("asks for a name and trusts every passkey until one is unticked", () => {
    const html = form(devices);
    expect(html).toContain("Server Name");
    expect(html).toContain("Laptop");
    expect(html).toContain("Security Key");
    expect(html.match(/type="checkbox"[^>]*checked=""/gu)).toHaveLength(2);
    expect(html).toMatch(
      /<button[^>]*disabled=""[^>]*>Create Install Command/u,
    );
  });

  it("trusts only the passkeys left ticked", () => {
    expect(chosenPasskeys(devices, new Set())).toEqual(["key-1", "key-2"]);
    expect(chosenPasskeys(devices, new Set(["key-1"]))).toEqual(["key-2"]);
    expect(chosenPasskeys(devices, new Set(["key-1", "key-2"]))).toEqual([]);
  });

  it("asks for a passkey first when none is registered", () => {
    const html = form([]);
    expect(html).toContain("Register a passkey first.");
    expect(html).toContain('href="/passkeys"');
    expect(html).not.toContain("Create Install Command");
  });

  it("says why the command could not be made", () => {
    const html = form(devices, new Error("server-1 is already a server."));
    expect(html).toMatch(/role="alert"[^>]*>server-1 is already a server\./u);
  });
});
