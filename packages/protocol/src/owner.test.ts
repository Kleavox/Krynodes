import { describe, expect, it } from "vitest";

import {
  isWork,
  ownerOf,
  touches,
  workTouches,
  type OwnerServer,
} from "./owner";

const pivox: OwnerServer = {
  stacks: [{ project: "pihole", containers: ["pihole-pihole-1"] }],
  services: [
    { kind: "docker", name: "pihole-pihole-1" },
    { kind: "docker", name: "portainer" },
    { kind: "systemd", name: "ssh.service" },
  ],
};

const io: OwnerServer = {
  stacks: [
    { project: "umami", containers: ["umami-db-1", "umami-umami-1"] },
    { project: "blog", containers: ["blog-web-1"] },
  ],
  services: [
    { kind: "docker", name: "umami-db-1" },
    { kind: "docker", name: "umami-umami-1" },
    { kind: "docker", name: "blog-web-1" },
  ],
  webAddresses: [
    { hostname: "umami.kleavox.xyz", project: "umami" },
    { hostname: "blog.kleavox.xyz", project: "blog" },
  ],
};

describe("ownerOf", () => {
  it("a container check belongs to the stack that lists it", () => {
    expect(
      ownerOf({ kind: "CONTAINER", target: "pihole-pihole-1" }, pivox),
    ).toEqual({ kind: "stack", project: "pihole" });
  });

  it("a container outside every stack is its own owner", () => {
    expect(ownerOf({ kind: "CONTAINER", target: "portainer" }, pivox)).toEqual({
      kind: "container",
      name: "portainer",
    });
  });

  it("a stack without a container list claims nothing", () => {
    expect(
      ownerOf(
        { kind: "CONTAINER", target: "pihole-pihole-1" },
        { ...pivox, stacks: [{ project: "pihole" }] },
      ),
    ).toEqual({ kind: "container", name: "pihole-pihole-1" });
  });

  it("a container the server does not list has no owner", () => {
    expect(ownerOf({ kind: "CONTAINER", target: "gone-1" }, pivox)).toBeNull();
  });

  it("ssh and ssh.service are the same unit", () => {
    const owner = { kind: "systemd", unit: "ssh.service" };
    expect(ownerOf({ kind: "SERVICE", target: "ssh" }, pivox)).toEqual(owner);
    expect(ownerOf({ kind: "SERVICE", target: "ssh.service" }, pivox)).toEqual(
      owner,
    );
    expect(ownerOf({ kind: "SERVICE", target: "smbd" }, pivox)).toBeNull();
  });

  it("an HTTP check belongs to the stack serving its hostname", () => {
    expect(
      ownerOf({ kind: "HTTP", target: "https://umami.kleavox.xyz/login" }, io),
    ).toEqual({ kind: "stack", project: "umami" });
    expect(
      ownerOf({ kind: "HTTP", target: "https://UMAMI.kleavox.xyz" }, io),
    ).toEqual({ kind: "stack", project: "umami" });
    expect(
      ownerOf(
        { kind: "HTTP", target: "https://umami.kleavox.xyz.evil.test" },
        io,
      ),
    ).toBeNull();
  });

  it("a TCP check has no owner", () => {
    expect(ownerOf({ kind: "TCP", target: "51.79.0.10:22" }, io)).toBeNull();
  });

  it("a malformed HTTP target has no owner", () => {
    expect(ownerOf({ kind: "HTTP", target: "not a url" }, io)).toBeNull();
  });
});

describe("touches", () => {
  const umami = { kind: "stack", project: "umami" } as const;

  it("a stack is touched by its compose actions and its containers' actions", () => {
    expect(touches(umami, { kind: "compose", name: "umami" }, io)).toBe(true);
    expect(touches(umami, { kind: "docker", name: "umami-db-1" }, io)).toBe(
      true,
    );
    expect(touches(umami, { kind: "compose", name: "blog" }, io)).toBe(false);
    expect(touches(umami, { kind: "docker", name: "blog-web-1" }, io)).toBe(
      false,
    );
  });

  it("a unit is touched by actions on the same unit", () => {
    const ssh = { kind: "systemd", unit: "ssh.service" } as const;
    expect(touches(ssh, { kind: "systemd", name: "ssh.service" }, pivox)).toBe(
      true,
    );
    expect(touches(ssh, { kind: "systemd", name: "ssh" }, pivox)).toBe(true);
    expect(touches(ssh, { kind: "docker", name: "ssh" }, pivox)).toBe(false);
  });

  it("a container is touched by actions on that container", () => {
    const portainer = { kind: "container", name: "portainer" } as const;
    expect(
      touches(portainer, { kind: "docker", name: "portainer" }, pivox),
    ).toBe(true);
    expect(
      touches(portainer, { kind: "compose", name: "portainer" }, pivox),
    ).toBe(false);
  });
});

describe("work by you", () => {
  it("counts what changes something, not reads, settings or Krynodes' own restarts", () => {
    for (const action of ["restart", "deploy", "stop", "reboot", "lockdown"]) {
      expect(isWork({ action })).toBe(true);
    }
    for (const action of [
      "logs",
      "read",
      "export",
      "scan",
      "autorestart",
      "manual",
      "heal",
      "trust",
      "store",
      "release",
      "reshare",
      "forget",
    ]) {
      expect(isWork({ action })).toBe(false);
    }
  });

  it("touches only the checks on what it changes, and every check for host work", () => {
    const umami = { kind: "HTTP", target: "https://umami.kleavox.xyz" };
    const ssh = { kind: "TCP", target: "51.79.0.10:22" };
    const deploy = { kind: "compose", name: "umami", action: "deploy" };
    expect(workTouches(umami, deploy, io)).toBe(true);
    expect(workTouches(ssh, deploy, io)).toBe(false);
    expect(
      workTouches(
        umami,
        { kind: "compose", name: "blog", action: "deploy" },
        io,
      ),
    ).toBe(false);
    expect(
      workTouches(ssh, { kind: "host", name: "server", action: "reboot" }, io),
    ).toBe(true);
    expect(
      workTouches(ssh, { kind: "host", name: "server", action: "scan" }, io),
    ).toBe(false);
    expect(
      workTouches(
        { kind: "SERVICE", target: "ssh" },
        { kind: "systemd", name: "ssh.service", action: "heal" },
        pivox,
      ),
    ).toBe(false);
  });
});
