import { describe, expect, it } from "vitest";

import {
  adminArgs,
  adminBlocker,
  adminChanged,
  adminCommand,
  adminDigest,
  adminNameProblem,
  adminOption,
  adminProblem,
  keyRow,
  keyText,
  loginLine,
} from "./admin-user";

const LAPTOP =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN+aw2ekALRgy/qt38BoTs6eGn55s71g0oi0WM0vVl+z j5mus@laptop";
const PHONE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPO5YBCY7BQSSM4XGAM/HxWEZPe5+h2n+txzD81ovRiq phone";

const key = (line: string, label: string, fingerprint = "SHA256:x") => ({
  line,
  type: "ssh-ed25519",
  fingerprint,
  label,
});

const admin = {
  name: "musyaf",
  keys: [key(LAPTOP, "j5mus-laptop"), key(PHONE, "phone")],
};

describe("the admin user in Enroll Defaults", () => {
  it("shows a pasted key as a fingerprint row", async () => {
    const row = await keyRow(LAPTOP, 0);
    expect(row).toEqual({
      line: LAPTOP,
      type: "ssh-ed25519",
      fingerprint: "SHA256:rtAbBHSVw2EvT29V7SS2PB/KPD+MzZoKzqJRYZDabDw",
      label: "j5mus-laptop",
    });
    expect(keyText(row!)).toBe(
      "ED25519 SHA256:rtAbBHSVw2EvT29V7SS2PB/KPD+MzZoKzqJRYZDabDw j5mus-laptop",
    );
    expect(
      (await keyRow("ssh-ed25519 " + LAPTOP.split(" ")[1], 2))?.label,
    ).toBe("key3");
    expect(await keyRow(`ssh-rsa ${LAPTOP.split(" ")[1]} x`, 0)).toBeNull();
    expect(await keyRow("not a key", 0)).toBeNull();
  });

  it("asks for the fingerprint only when the admin user or its keys change", () => {
    expect(adminChanged(admin, { ...admin })).toBe(false);
    expect(adminChanged(admin, { ...admin, name: "deploy" })).toBe(true);
    expect(adminChanged(admin, { ...admin, keys: [admin.keys[0]!] })).toBe(
      true,
    );
    expect(adminChanged(null, null)).toBe(false);
    expect(adminChanged(null, admin)).toBe(true);
  });

  it("needs both a name and a key, or neither", () => {
    expect(adminProblem("", [])).toBeNull();
    expect(adminProblem("musyaf", admin.keys)).toBeNull();
    expect(adminProblem("musyaf", [])).toBe("Add at least one SSH public key.");
    expect(adminProblem("", admin.keys)).toBe("Type the admin user's name.");
    expect(adminProblem("root", admin.keys)).toBe(
      "Lowercase letters, digits, dashes and underscores. Not root.",
    );
  });

  it("takes a lowercase user name that is not root", () => {
    expect(adminNameProblem("musyaf")).toBeNull();
    expect(adminNameProblem("")).toBeNull();
    for (const name of ["root", "Musyaf", "1abc", "a b"]) {
      expect(adminNameProblem(name)).toBe(
        "Lowercase letters, digits, dashes and underscores. Not root.",
      );
    }
  });

  it("confirms the same digest the Worker checks", async () => {
    expect(await adminDigest(null)).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(await adminDigest({ name: "musyaf", keys: [LAPTOP] })).toMatch(
      /^[0-9a-f]{64}$/u,
    );
    expect(await adminDigest({ name: "musyaf", keys: [LAPTOP] })).not.toBe(
      await adminDigest({ name: "musyaf", keys: [PHONE] }),
    );
  });
});

describe("Add Admin User at enroll and on a server", () => {
  it("is offered at enroll only with an admin in Enroll Defaults", () => {
    expect(adminOption(admin)).toEqual({
      available: true,
      text: "musyaf, with sudo and 2 SSH keys from Enroll Defaults. The server asks for its password on its own screen, then turns root login off.",
    });
    expect(adminOption({ ...admin, keys: [admin.keys[0]!] }).text).toContain(
      "with sudo and 1 SSH key from",
    );
    expect(adminOption(null)).toEqual({
      available: false,
      text: "Set an admin user in Enroll Defaults first.",
    });
  });

  it("signs the name and the keys as blob:label", () => {
    expect(adminArgs("musyaf", admin.keys)).toEqual({
      name: "musyaf",
      keys: "AAAAC3NzaC1lZDI1NTE5AAAAIN+aw2ekALRgy/qt38BoTs6eGn55s71g0oi0WM0vVl+z:j5mus-laptop,AAAAC3NzaC1lZDI1NTE5AAAAIPO5YBCY7BQSSM4XGAM/HxWEZPe5+h2n+txzD81ovRiq:phone",
    });
    expect(adminCommand("musyaf")).toBe("sudo kry admin-user musyaf");
  });

  it("says why Add Admin User cannot run", () => {
    const node = { name: "io", agent_version: "0.7.1" };
    expect(adminBlocker(node, admin)).toBeNull();
    expect(adminBlocker({ ...node, agent_version: "0.7.0" }, admin)).toBe(
      "Needs agent 0.7.1 · io runs 0.7.0",
    );
    expect(adminBlocker({ ...node, agent_version: null }, admin)).toBe(
      "Waiting for First Report",
    );
    expect(adminBlocker(node, null)).toBe(
      "Add your SSH public keys in Enroll Defaults first.",
    );
  });

  it("tells the owner how to log in once root cannot", () => {
    expect(loginLine("musyaf", "139.99.0.40")).toBe("ssh musyaf@139.99.0.40");
    expect(loginLine("musyaf", null)).toBeNull();
  });
});
