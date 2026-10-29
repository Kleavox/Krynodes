import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  KeyRows,
  KeysField,
  ProtectionOptions,
} from "@/features/settings/enroll-defaults-settings";

import { AdminCommandView, AdminUserForm } from "./admin-user-dialog";
import { SetupOptions } from "./setup-options";

const none = () => {};

const keys = [
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
];

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
      keys={keys}
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

  it("starts with an empty name and keeps Get Command off until one is typed", () => {
    expect(getButton(form(null, ""))).toContain('disabled=""');
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

describe("Enroll a Server", () => {
  const setup = {
    recommended: true,
    docker: true,
    hour: 3,
    network: false,
    adminUser: true,
    adminName: "",
  };
  const nameField = (html: string) =>
    html
      .split("<input")
      .find((part) => part.includes('id="enroll-admin-name"'));

  it("offers Docker and Add Admin User, not the protections", () => {
    const html = withQueries(
      <SetupOptions value={setup} onChange={none} keys={keys} />,
    );
    expect(text(html)).toContain("Install Docker");
    expect(text(html)).toContain("Add Admin User");
    expect(text(html)).not.toContain("Recommended Protections");
    expect(text(html)).not.toContain("Restart Hour");
  });

  it("is off without keys in Enroll Defaults", () => {
    const html = withQueries(
      <SetupOptions value={setup} onChange={none} keys={[]} />,
    );
    expect(text(html)).toContain(
      "Add Admin User Add your SSH public keys in Enroll Defaults first.",
    );
    const box = html.split("<label").at(-1)!;
    expect(box).toContain('disabled=""');
    expect(box).not.toContain('checked=""');
    expect(nameField(html)).toBeUndefined();
  });

  it("asks for this server's user name once Add Admin User is ticked", () => {
    const html = withQueries(
      <SetupOptions
        value={{ ...setup, adminName: "musyaf" }}
        onChange={none}
        keys={keys}
      />,
    );
    expect(text(html)).toContain(
      "A sudo user that logs in with your 2 SSH keys from Enroll Defaults.",
    );
    expect(text(html)).toContain("User Name");
    expect(nameField(html)).toContain('value="musyaf"');
    expect(nameField(html)).not.toContain('disabled=""');
    const unticked = withQueries(
      <SetupOptions
        value={{ ...setup, adminUser: false }}
        onChange={none}
        keys={keys}
      />,
    );
    expect(nameField(unticked)).toBeUndefined();
  });

  it("says a name that will not work", () => {
    const html = withQueries(
      <SetupOptions
        value={{ ...setup, adminName: "root" }}
        onChange={none}
        keys={keys}
      />,
    );
    expect(nameField(html)).toContain('aria-invalid="true"');
  });

  it("keeps the admin user as it was once the command is made", () => {
    const html = withQueries(
      <SetupOptions
        value={{ ...setup, adminName: "musyaf" }}
        onChange={none}
        keys={keys}
        adminLocked
      />,
    );
    expect(nameField(html)).toContain('disabled=""');
    expect(text(html)).toContain("Set when the command is made.");
  });
});

describe("Enroll Defaults", () => {
  it("holds the protections with their restart hour", () => {
    const html = withQueries(
      <ProtectionOptions
        value={{ recommended: true, docker: true, hour: 3, network: false }}
        onChange={none}
      />,
    );
    expect(text(html)).toContain("Apply Recommended Protections");
    expect(text(html)).toContain("Restart Hour (Your Time)");
  });

  it("does not offer Add Admin User itself", () => {
    const html = withQueries(
      <SetupOptions
        value={{ recommended: true, docker: true, hour: 3, network: false }}
        onChange={none}
      />,
    );
    expect(text(html)).not.toContain("Add Admin User");
  });

  it("shows each key as its fingerprint with Remove", () => {
    const html = renderToStaticMarkup(<KeyRows keys={keys} onRemove={none} />);
    expect(text(html)).toBe(
      "ED25519 SHA256:3fQkYk laptop Remove ED25519 SHA256:9aZrQe phone Remove",
    );
  });

  it("takes several keys at once, pasted or from a file", () => {
    const html = renderToStaticMarkup(<KeysField keys={keys} onKeys={none} />);
    expect(html).toContain("<textarea");
    expect(html).toContain('type="file"');
    expect(text(html)).toContain("Browse");
    expect(text(html)).toContain(
      "Paste one or more public keys, or browse for a .pub or authorized_keys file.",
    );
  });
});
