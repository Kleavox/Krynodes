import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { KeyRows } from "@/features/settings/enroll-defaults-settings";

import { AdminCommandView, AdminUserForm } from "./admin-user-dialog";
import { SetupOptions } from "./setup-options";

const none = () => {};

const admin = {
  name: "musyaf",
  keys: [
    {
      line: "ssh-ed25519 AAAA laptop",
      type: "ssh-ed25519",
      fingerprint: "SHA256:3fQkYk",
      label: "laptop",
    },
    {
      line: "ssh-ed25519 BBBB phone",
      type: "ssh-ed25519",
      fingerprint: "SHA256:9aZrQe",
      label: "phone",
    },
  ],
};

const text = (html: string) =>
  html
    .replace(/<[^>]+>/gu, " ")
    .replace(/&#x27;/gu, "'")
    .replace(/\s+/gu, " ")
    .trim();

const getButton = (html: string) =>
  html
    .split("<button")
    .find((part) => part.includes("Get Command"))!
    .split(">")[0]!;

const form = (blocker: string | null, name = "musyaf") =>
  renderToStaticMarkup(
    <AdminUserForm
      admin={admin}
      name={name}
      onName={none}
      blocker={blocker}
      pending={false}
      error={null}
      onGet={none}
      onCancel={none}
      onUpdate={blocker?.startsWith("Needs agent") ? none : undefined}
    />,
  );

const withQueries = (node: ReactNode) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      {node}
    </QueryClientProvider>,
  );

describe("Add Admin User on a server", () => {
  it("lists the keys from Enroll Defaults and gets the command with the Fingerprint", () => {
    const html = form(null);
    expect(text(html)).toContain("ED25519 SHA256:3fQkYk laptop");
    expect(text(html)).toContain("ED25519 SHA256:9aZrQe phone");
    expect(getButton(html)).not.toContain('disabled=""');
    expect(html).toContain("<svg");
  });

  it("shows the gate on an older agent with Update Agent", () => {
    const html = form("Needs agent 0.7.1 · io runs 0.7.0");
    expect(text(html)).toContain("Needs agent 0.7.1 · io runs 0.7.0");
    expect(text(html)).toContain("Update Agent");
    expect(getButton(html)).toContain('disabled=""');
  });

  it("keeps Get Command off for root", () => {
    const html = form(null, "root");
    expect(text(html)).toContain(
      "Lowercase letters, digits, dashes and underscores. Not root.",
    );
    expect(getButton(html)).toContain('disabled=""');
  });

  it("gives the command to run on the server", () => {
    const html = renderToStaticMarkup(
      <AdminCommandView nodeName="io" name="musyaf" />,
    );
    expect(text(html)).toContain("sudo kry admin-user musyaf");
    expect(text(html)).toContain("asks for musyaf's password on io's screen");
  });
});

describe("Add Admin User when a server enrolls", () => {
  const setup = {
    recommended: true,
    docker: true,
    hour: 3,
    network: false,
    adminUser: true,
  };

  it("is off without an admin in Enroll Defaults", () => {
    const html = withQueries(
      <SetupOptions value={setup} onChange={none} admin={null} />,
    );
    expect(text(html)).toContain(
      "Add Admin User Set an admin user in Enroll Defaults first.",
    );
    const box = html.split("<label").at(-1)!;
    expect(box).toContain('disabled=""');
    expect(box).not.toContain('checked=""');
  });

  it("names the admin user and its keys when it is set", () => {
    const html = withQueries(
      <SetupOptions value={setup} onChange={none} admin={admin} />,
    );
    expect(text(html)).toContain(
      "musyaf, with sudo and 2 SSH keys from Enroll Defaults.",
    );
    expect(html.split("<label").at(-1)).toContain('checked=""');
  });

  it("is not offered in Enroll Defaults itself", () => {
    const html = withQueries(<SetupOptions value={setup} onChange={none} />);
    expect(text(html)).not.toContain("Add Admin User");
  });
});

describe("SSH public keys in Enroll Defaults", () => {
  it("shows each key as its fingerprint with Remove", () => {
    const html = renderToStaticMarkup(
      <KeyRows keys={admin.keys} onRemove={none} />,
    );
    expect(text(html)).toBe(
      "ED25519 SHA256:3fQkYk laptop Remove ED25519 SHA256:9aZrQe phone Remove",
    );
  });
});
