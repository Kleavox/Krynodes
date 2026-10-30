import { describe, expect, it } from "vitest";

import {
  isWork,
  ownerOf,
  touches,
  workTouches,
  type OwnerServer,
} from "./owner";

const serverOne: OwnerServer = {
  stacks: [{ project: "pihole", containers: ["pihole-pihole-1"] }],
  services: [
    { kind: "docker", name: "pihole-pihole-1" },
    { kind: "docker", name: "portainer" },
    { kind: "systemd", name: "ssh.service" },
  ],
};

const serverTwo: OwnerServer = {
  stacks: [
    { project: "tracker", containers: ["tracker-db-1", "tracker-tracker-1"] },
    { project: "blog", containers: ["blog-web-1"] },
  ],
  services: [
    { kind: "docker", name: "tracker-db-1" },
    { kind: "docker", name: "tracker-tracker-1" },
    { kind: "docker", name: "blog-web-1" },
  ],
  webAddresses: [
    { hostname: "tracker.example.org", project: "tracker" },
    { hostname: "blog.example.org", project: "blog" },
  ],
};

describe("ownerOf", () => {
  it("a container check belongs to the stack that lists it", () => {
    expect(
      ownerOf({ kind: "CONTAINER", target: "pihole-pihole-1" }, serverOne),
    ).toEqual({ kind: "stack", project: "pihole" });
  });

  it("a container outside every stack is its own owner", () => {
    expect(
      ownerOf({ kind: "CONTAINER", target: "portainer" }, serverOne),
    ).toEqual({
      kind: "container",
      name: "portainer",
    });
  });

  it("a stack without a container list claims nothing", () => {
    expect(
      ownerOf(
        { kind: "CONTAINER", target: "pihole-pihole-1" },
        { ...serverOne, stacks: [{ project: "pihole" }] },
      ),
    ).toEqual({ kind: "container", name: "pihole-pihole-1" });
  });

  it("a container the server does not list has no owner", () => {
    expect(
      ownerOf({ kind: "CONTAINER", target: "gone-1" }, serverOne),
    ).toBeNull();
  });

  it("ssh and ssh.service are the same unit", () => {
    const owner = { kind: "systemd", unit: "ssh.service" };
    expect(ownerOf({ kind: "SERVICE", target: "ssh" }, serverOne)).toEqual(
      owner,
    );
    expect(
      ownerOf({ kind: "SERVICE", target: "ssh.service" }, serverOne),
    ).toEqual(owner);
    expect(ownerOf({ kind: "SERVICE", target: "smbd" }, serverOne)).toBeNull();
  });

  it("an HTTP check belongs to the stack serving its hostname", () => {
    expect(
      ownerOf(
        { kind: "HTTP", target: "https://tracker.example.org/login" },
        serverTwo,
      ),
    ).toEqual({ kind: "stack", project: "tracker" });
    expect(
      ownerOf(
        { kind: "HTTP", target: "https://TRACKER.example.org" },
        serverTwo,
      ),
    ).toEqual({ kind: "stack", project: "tracker" });
    expect(
      ownerOf(
        { kind: "HTTP", target: "https://tracker.example.org.evil.test" },
        serverTwo,
      ),
    ).toBeNull();
  });

  it("a TCP check has no owner", () => {
    expect(
      ownerOf({ kind: "TCP", target: "198.51.100.10:22" }, serverTwo),
    ).toBeNull();
  });

  it("a malformed HTTP target has no owner", () => {
    expect(
      ownerOf({ kind: "HTTP", target: "not a url" }, serverTwo),
    ).toBeNull();
  });
});

describe("touches", () => {
  const tracker = { kind: "stack", project: "tracker" } as const;

  it("a stack is touched by its compose actions and its containers' actions", () => {
    expect(
      touches(tracker, { kind: "compose", name: "tracker" }, serverTwo),
    ).toBe(true);
    expect(
      touches(tracker, { kind: "docker", name: "tracker-db-1" }, serverTwo),
    ).toBe(true);
    expect(touches(tracker, { kind: "compose", name: "blog" }, serverTwo)).toBe(
      false,
    );
    expect(
      touches(tracker, { kind: "docker", name: "blog-web-1" }, serverTwo),
    ).toBe(false);
  });

  it("a unit is touched by actions on the same unit", () => {
    const ssh = { kind: "systemd", unit: "ssh.service" } as const;
    expect(
      touches(ssh, { kind: "systemd", name: "ssh.service" }, serverOne),
    ).toBe(true);
    expect(touches(ssh, { kind: "systemd", name: "ssh" }, serverOne)).toBe(
      true,
    );
    expect(touches(ssh, { kind: "docker", name: "ssh" }, serverOne)).toBe(
      false,
    );
  });

  it("a container is touched by actions on that container", () => {
    const portainer = { kind: "container", name: "portainer" } as const;
    expect(
      touches(portainer, { kind: "docker", name: "portainer" }, serverOne),
    ).toBe(true);
    expect(
      touches(portainer, { kind: "compose", name: "portainer" }, serverOne),
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
    const tracker = { kind: "HTTP", target: "https://tracker.example.org" };
    const ssh = { kind: "TCP", target: "198.51.100.10:22" };
    const deploy = { kind: "compose", name: "tracker", action: "deploy" };
    expect(workTouches(tracker, deploy, serverTwo)).toBe(true);
    expect(workTouches(ssh, deploy, serverTwo)).toBe(false);
    expect(
      workTouches(
        tracker,
        { kind: "compose", name: "blog", action: "deploy" },
        serverTwo,
      ),
    ).toBe(false);
    expect(
      workTouches(
        ssh,
        { kind: "host", name: "server", action: "reboot" },
        serverTwo,
      ),
    ).toBe(true);
    expect(
      workTouches(
        ssh,
        { kind: "host", name: "server", action: "scan" },
        serverTwo,
      ),
    ).toBe(false);
    expect(
      workTouches(
        { kind: "SERVICE", target: "ssh" },
        { kind: "systemd", name: "ssh.service", action: "heal" },
        serverOne,
      ),
    ).toBe(false);
  });
});
