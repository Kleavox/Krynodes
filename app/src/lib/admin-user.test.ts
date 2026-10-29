import { describe, expect, it } from "vitest";

import {
  addKeys,
  adminArgs,
  adminBlocker,
  adminCommand,
  adminNameProblem,
  adminOption,
  keyRow,
  keysChanged,
  keysDigest,
  keyText,
  loginLine,
} from "./admin-user";

const LAPTOP =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN+aw2ekALRgy/qt38BoTs6eGn55s71g0oi0WM0vVl+z j5mus@laptop";
const PHONE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPO5YBCY7BQSSM4XGAM/HxWEZPe5+h2n+txzD81ovRiq phone";
const variant = (end: string) =>
  `ssh-ed25519 ${LAPTOP.split(" ")[1]!.slice(0, -1)}${end} spare-${end}`;

const key = (line: string, label: string, fingerprint = "SHA256:x") => ({
  line,
  type: "ssh-ed25519",
  fingerprint,
  label,
});

const keys = [key(LAPTOP, "j5mus-laptop"), key(PHONE, "phone")];

describe("the SSH keys in Enroll Defaults", () => {
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

  it("adds every key in a pasted block or a file at once", async () => {
    const added = await addKeys(
      [LAPTOP, "", "# my phone", `${PHONE}\r`, ""].join("\n"),
      [],
    );
    expect(added.keys.map((row) => row.label)).toEqual([
      "j5mus-laptop",
      "phone",
    ]);
    expect(added.rest).toBe("");
    expect(added.note).toBeNull();
  });

  it("keeps the lines that are not keys and says how many", async () => {
    const added = await addKeys(
      [LAPTOP, "not a key", "ssh-ed25519 AAAA x"].join("\n"),
      [],
    );
    expect(added.keys).toHaveLength(1);
    expect(added.rest).toBe(["not a key", "ssh-ed25519 AAAA x"].join("\n"));
    expect(added.note).toBe("2 lines are not public keys.");
    expect((await addKeys("nope", [])).note).toBe(
      "1 line is not a public key.",
    );
  });

  it("skips a key that is already here", async () => {
    const laptop = (await keyRow(LAPTOP, 0))!;
    const again = await addKeys(LAPTOP, [laptop]);
    expect(again.keys).toEqual([laptop]);
    expect(again.note).toBe("That key is already here.");
    const both = await addKeys([LAPTOP, PHONE].join("\n"), [laptop]);
    expect(both.keys.map((row) => row.label)).toEqual([
      "j5mus-laptop",
      "phone",
    ]);
    expect(both.note).toBeNull();
  });

  it("stops at four keys and says how many were left out", async () => {
    const three = (await addKeys([LAPTOP, PHONE, variant("y")].join("\n"), []))
      .keys;
    expect(three).toHaveLength(3);
    const full = await addKeys([variant("x"), variant("w")].join("\n"), three);
    expect(full.keys.map((row) => row.label)).toEqual([
      "j5mus-laptop",
      "phone",
      "spare-y",
      "spare-x",
    ]);
    expect(full.note).toBe("Up to 4 keys: 1 left out.");
  });

  it("asks for the fingerprint only when the keys change", () => {
    expect(keysChanged(keys, [...keys])).toBe(false);
    expect(keysChanged(keys, [keys[0]!])).toBe(true);
    expect(keysChanged([], [])).toBe(false);
    expect(keysChanged([], keys)).toBe(true);
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
    expect(await keysDigest([])).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(await keysDigest([LAPTOP])).toBe(
      "614dceec4a297a7a784834b36017af9a73b26a0c154422cf03c1e89f4260a932",
    );
    expect(await keysDigest([LAPTOP, PHONE])).not.toBe(
      await keysDigest([PHONE, LAPTOP]),
    );
  });
});

describe("Add Admin User at enroll and on a server", () => {
  it("is offered at enroll only with keys in Enroll Defaults", () => {
    expect(adminOption(keys)).toEqual({
      available: true,
      text: "A sudo user that logs in with your 2 SSH keys from Enroll Defaults. The server asks for its password on its own screen, then turns root login off.",
    });
    expect(adminOption([keys[0]!]).text).toContain("with your 1 SSH key from");
    expect(adminOption([])).toEqual({
      available: false,
      text: "Add your SSH public keys in Enroll Defaults first.",
    });
  });

  it("signs the name and the keys as blob:label", () => {
    expect(adminArgs("musyaf", keys)).toEqual({
      name: "musyaf",
      keys: "AAAAC3NzaC1lZDI1NTE5AAAAIN+aw2ekALRgy/qt38BoTs6eGn55s71g0oi0WM0vVl+z:j5mus-laptop,AAAAC3NzaC1lZDI1NTE5AAAAIPO5YBCY7BQSSM4XGAM/HxWEZPe5+h2n+txzD81ovRiq:phone",
    });
    expect(adminCommand("musyaf")).toBe("sudo kry admin-user musyaf");
  });

  it("says why Add Admin User cannot run", () => {
    const node = { name: "io", agent_version: "0.7.1" };
    expect(adminBlocker(node, keys)).toBeNull();
    expect(adminBlocker({ ...node, agent_version: "0.7.0" }, keys)).toBe(
      "Needs agent 0.7.1 · io runs 0.7.0",
    );
    expect(adminBlocker({ ...node, agent_version: null }, keys)).toBe(
      "Waiting for First Report",
    );
    expect(adminBlocker(node, [])).toBe(
      "Add your SSH public keys in Enroll Defaults first.",
    );
  });

  it("tells the owner how to log in once root cannot", () => {
    expect(loginLine("musyaf", "139.99.0.40")).toBe("ssh musyaf@139.99.0.40");
    expect(loginLine("musyaf", null)).toBeNull();
  });
});
