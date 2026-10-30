import { describe, expect, it } from "vitest";

import { LAPTOP, LAPTOP_PRINT, PHONE } from "../test/keys";
import { fingerprint, keyLabel, parseKeyLine } from "./ssh";

const ECDSA =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKZ73LgBb1WzkdeAUNujmw5h2nUqruXE3/uq+OGIEtih9YgaOZqm/DW6h9gXiNTld1ZJ0EKgkqhsB6YB+DCr/90=";

describe("SSH public keys", () => {
  it("reads a key line's type, blob and a label made safe for the install command", () => {
    expect(parseKeyLine(LAPTOP)).toEqual({
      type: "ssh-ed25519",
      blob: "AAAAC3NzaC1lZDI1NTE5AAAAIJQIdIFdIOrfxkgPwGXPHesM4bMreTr2K6zwvH2eRuGK",
      label: "user1-laptop",
    });
    expect(parseKeyLine(`  ${PHONE}  `)?.label).toBe("phone");
    expect(parseKeyLine(ECDSA, 2)).toMatchObject({
      type: "ecdsa-sha2-nistp256",
      label: "key3",
    });
  });

  it("refuses a key whose blob names another type, an unknown type or no blob", () => {
    const blob = LAPTOP.split(" ")[1];
    expect(parseKeyLine(`ssh-rsa ${blob} laptop`)).toBeNull();
    expect(parseKeyLine(`ssh-dss ${blob} laptop`)).toBeNull();
    expect(parseKeyLine("ssh-ed25519")).toBeNull();
    expect(parseKeyLine("ssh-ed25519 not*base64 laptop")).toBeNull();
    expect(parseKeyLine(`ssh-ed25519 ${"A".repeat(16400)}`)).toBeNull();
  });

  it("prints fingerprints exactly as ssh-keygen -lf does", async () => {
    expect(await fingerprint(parseKeyLine(LAPTOP)!.blob)).toBe(LAPTOP_PRINT);
    expect(await fingerprint(parseKeyLine(PHONE)!.blob)).toBe(
      "SHA256:8N+1D7dUMegVjJ9iFeI8fD+W16LUuALxq/zyJv66bQk",
    );
    expect(await fingerprint(parseKeyLine(ECDSA)!.blob)).toBe(
      "SHA256:mkwBqZbS0p8pCcjS7vA5Yo6EhaY0hwYWteQO/rIpih4",
    );
  });

  it("keeps labels to 32 safe characters", () => {
    expect(keyLabel("me@work laptop", 0)).toBe("me-work-laptop");
    expect(keyLabel("x".repeat(40), 0)).toBe("x".repeat(32));
    expect(keyLabel("", 3)).toBe("key4");
  });
});
