import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import type { Device, Enrollment } from "@/types";

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

describe("the arrival step", () => {
  it("links to the server that enrolled", () => {
    const html = renderToStaticMarkup(
      <Arrived name="server-1" nodeId="node-1" onClose={none} />,
    );
    expect(html).toContain('href="#server-node-1"');
    expect(html).toContain("Show server-1");
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
