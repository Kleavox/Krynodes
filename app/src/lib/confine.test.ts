import { describe, expect, it } from "vitest";

import type { Confinement } from "../types";

import {
  confinementActionText,
  confinementNote,
  confinementRow,
  confineText,
  denialLines,
} from "./confine";
import { unconfinedServices } from "./compose";

const selinux = (change: Partial<Confinement> = {}): Confinement => ({
  system: "selinux",
  mode: "enforcing",
  enforced: null,
  complain: null,
  managed: false,
  restart: false,
  docker: null,
  ...change,
});

const apparmor = (change: Partial<Confinement> = {}): Confinement => ({
  system: "apparmor",
  mode: "on",
  enforced: 12,
  complain: 0,
  managed: false,
  restart: false,
  docker: null,
  ...change,
});

describe("the SELinux or AppArmor row", () => {
  it("names what the server has and offers what fits it", () => {
    expect(confinementRow(selinux())).toEqual({
      title: "SELinux",
      text: "Enforcing",
      actions: ["denials", "manage"],
    });
    expect(confinementRow(selinux({ mode: "permissive" }))).toMatchObject({
      text: "Permissive",
      actions: ["denials", "on"],
    });
    expect(confinementRow(selinux({ mode: "disabled" }))).toMatchObject({
      text: "Off",
      actions: ["denials", "on"],
    });
    expect(confinementRow(selinux({ managed: true }))).toEqual({
      title: "SELinux",
      text: "Enforcing · managed by Krynodes",
      actions: ["denials", "undo"],
    });
    expect(
      confinementRow(
        selinux({ mode: "disabled", managed: true, restart: true }),
      ),
    ).toMatchObject({ text: "Off · restart to finish · managed by Krynodes" });
    expect(confinementRow(apparmor())).toEqual({
      title: "AppArmor",
      text: "On · 12 profiles enforced",
      actions: ["denials", "manage"],
    });
    expect(confinementRow(apparmor({ enforced: 1 }))).toMatchObject({
      text: "On · 1 profile enforced",
    });
    expect(confinementRow(apparmor({ complain: 3 }))).toMatchObject({
      text: "On · 12 enforced, 3 in complain",
      actions: ["denials", "on"],
    });
    expect(
      confinementRow(apparmor({ enforced: null, complain: null })),
    ).toMatchObject({ text: "On · -- profiles enforced" });
    expect(
      confinementRow(apparmor({ mode: "off", enforced: 0 })),
    ).toMatchObject({ text: "Off", actions: ["denials", "on"] });
    expect(confinementRow(apparmor({ mode: "kernel-off" }))).toMatchObject({
      text: "Off · needs a restart",
      actions: ["denials", "on"],
    });
    expect(
      confinementRow(
        apparmor({ mode: "kernel-off", managed: true, restart: true }),
      ),
    ).toMatchObject({
      text: "Off · restart to finish · managed by Krynodes",
      actions: ["denials", "undo"],
    });
    expect(
      confinementRow(
        selinux({
          system: null,
          mode: null,
          managed: false,
        }),
      ),
    ).toEqual({
      title: "SELinux or AppArmor",
      text: "Not available",
      actions: [],
    });
    expect(confinementRow(undefined)).toEqual({
      title: "SELinux or AppArmor",
      text: "Needs agent 0.7.4 or newer",
      actions: [],
    });
  });

  it("confines containers only where Krynodes manages SELinux and Docker runs", () => {
    expect(
      confinementRow(selinux({ managed: true, docker: false })).actions,
    ).toEqual(["denials", "containers", "undo"]);
    expect(
      confinementRow(selinux({ managed: true, docker: true })).actions,
    ).toEqual(["denials", "uncontain", "undo"]);
    expect(confinementRow(selinux({ docker: false })).actions).toEqual([
      "denials",
      "manage",
    ]);
    expect(
      confinementRow(apparmor({ managed: true, docker: true })).actions,
    ).toEqual(["denials", "undo"]);
  });
});

describe("the grey note on Security", () => {
  it("says only when it is permissive or off", () => {
    expect(confinementNote(selinux({ mode: "permissive" }))).toBe(
      "SELinux is permissive",
    );
    expect(confinementNote(selinux({ mode: "disabled" }))).toBe(
      "SELinux is off",
    );
    expect(confinementNote(apparmor({ mode: "off" }))).toBe("AppArmor is off");
    expect(confinementNote(apparmor({ mode: "kernel-off" }))).toBe(
      "AppArmor is off",
    );
    expect(confinementNote(selinux())).toBeNull();
    expect(confinementNote(apparmor({ complain: 2 }))).toBeNull();
    expect(confinementNote(undefined)).toBeNull();
  });
});

describe("what each step says before it runs", () => {
  const none = { count: 0, lines: [] };

  it("turns SELinux on, says what may stop, and that Undo is one click", () => {
    const text = confineText(
      "on",
      selinux({ mode: "permissive", docker: false }),
      "server-1",
      {
        count: 2,
        lines: [
          {
            at: "2026-10-29T09:58:00Z",
            program: "cat",
            wanted: "read shadow",
            stack: "panel",
          },
        ],
      },
      [],
    );
    expect(text.title).toBe("Turn on SELinux on server-1?");
    expect(text.button).toBe("Turn On");
    expect(text.lines).toEqual([
      "SELinux starts enforcing now. Krynodes first labels the SSH port and the home folders of users who log in with a key, so SSH keeps working.",
      "From then on a denied container stops its stack, and SELinux switched off outside Krynodes quarantines the server.",
      "2 denials in the last 24 hours. What was denied stops working once SELinux enforces.",
      "Containers are not confined until you choose Confine Containers on this row.",
      "Undo is one click and stops SELinux enforcing.",
    ]);
    expect(
      confineText("on", selinux({ mode: "disabled" }), "server-1", none, [])
        .lines,
    ).toEqual([
      "SELinux is set to enforcing and finishes when you restart the server. The first boot labels every file and restarts once more. Krynodes first labels the SSH port and the home folders of users who log in with a key, so SSH keeps working.",
      "From then on a denied container stops its stack, and SELinux switched off outside Krynodes quarantines the server.",
      "No denials in the last 24 hours.",
      "Undo is one click and stops SELinux enforcing.",
    ]);
    expect(
      confineText(
        "on",
        selinux({ mode: "permissive" }),
        "server-1",
        { count: null, lines: [] },
        [],
      ).lines[2],
    ).toBe("Denials in the last 24 hours: --");
  });

  it("turns AppArmor on for each way it can be off", () => {
    expect(
      confineText("on", apparmor({ complain: 3 }), "server-1", none, [])
        .lines[0],
    ).toBe("The 3 profiles in complain mode start enforcing now.");
    expect(
      confineText(
        "on",
        apparmor({ complain: 3 }),
        "server-1",
        none,
        [],
      ).lines.at(-1),
    ).toBe("Undo is one click and puts them back in complain mode.");
    expect(
      confineText("on", apparmor({ mode: "off" }), "server-1", none, [])
        .lines[0],
    ).toBe("Krynodes installs AppArmor if it is missing and turns it on now.");
    expect(
      confineText("on", apparmor({ mode: "kernel-off" }), "server-1", none, [])
        .lines[0],
    ).toBe(
      "AppArmor is off when the server boots. Krynodes turns it on in the boot settings, and it starts when you restart the server.",
    );
    expect(
      confineText(
        "on",
        apparmor({ mode: "off" }),
        "server-1",
        none,
        [],
      ).lines.at(-1),
    ).toBe(
      "Undo is one click and stops Krynodes managing it; AppArmor stays on.",
    );
  });

  it("lets Krynodes manage what is already enforcing", () => {
    expect(
      confineText("manage", selinux({ docker: false }), "server-1", none, []),
    ).toEqual({
      title: "Let Krynodes manage SELinux on server-1?",
      button: "Let Krynodes Manage",
      destructive: false,
      lines: [
        "SELinux stays as it is.",
        "From then on a denied container stops its stack, and SELinux switched off outside Krynodes quarantines the server.",
        "Containers are not confined until you choose Confine Containers on this row.",
        "Undo is one click and only stops Krynodes managing it.",
      ],
    });
  });

  it("undoes, and confines containers naming every stack that restarts", () => {
    expect(
      confineText("undo", selinux({ managed: true }), "server-1", none, []),
    ).toEqual({
      title: "Undo SELinux on server-1?",
      button: "Undo",
      destructive: true,
      lines: [
        "SELinux goes back to how Krynodes found it: permissive if it was permissive or off, enforcing if it already was. Krynodes stops acting on its denials.",
      ],
    });
    expect(
      confineText("undo", apparmor({ managed: true }), "server-1", none, [])
        .lines,
    ).toEqual([
      "Profiles Krynodes moved to enforce go back to complain mode; AppArmor stays on. Krynodes stops acting on its denials.",
    ]);
    expect(
      confineText(
        "containers",
        selinux({ managed: true, docker: false }),
        "server-1",
        none,
        ["panel", "web"],
      ),
    ).toEqual({
      title: "Confine containers on server-1?",
      button: "Confine Containers",
      destructive: false,
      lines: [
        "Docker restarts with SELinux on, and every stack starts again with its own label: panel and web.",
        "Undo is one click: Stop Confining Containers restarts Docker without it.",
      ],
    });
    expect(
      confineText(
        "uncontain",
        selinux({ managed: true, docker: true }),
        "server-1",
        none,
        [],
      ),
    ).toEqual({
      title: "Stop confining containers on server-1?",
      button: "Stop Confining",
      destructive: true,
      lines: ["Docker restarts without SELinux. No stacks run on this server."],
    });
  });
});

describe("the Denials dialog", () => {
  it("shows each line with its time, program, what it wanted and its stack", () => {
    expect(
      denialLines({
        count: 3,
        lines: [
          {
            at: "2026-10-29T09:58:00Z",
            program: "cat",
            wanted: "read shadow",
            stack: "panel",
          },
          {
            at: "2026-10-29T09:40:00Z",
            program: "sshd",
            wanted: "bind 2222/tcp",
          },
        ],
      }),
    ).toEqual({
      summary: "3 in the last 24 hours",
      rows: [
        {
          at: "2026-10-29T09:58:00Z",
          program: "cat",
          wanted: "read shadow",
          stack: "panel",
        },
        {
          at: "2026-10-29T09:40:00Z",
          program: "sshd",
          wanted: "bind 2222/tcp",
          stack: "--",
        },
      ],
    });
    expect(denialLines({ count: null, lines: [] }).summary).toBe(
      "-- in the last 24 hours",
    );
    expect(denialLines({ count: 0, lines: [] }).summary).toBe(
      "None in the last 24 hours",
    );
  });
});

describe("services SELinux does not confine", () => {
  it("lists the services that need the server, as the agent labels them", () => {
    expect(
      unconfinedServices(`services:
  app:
    image: nginx
    volumes:
      - ./data:/data
      - data:/cache
  backup:
    image: restic
    volumes:
      - /srv:/srv:ro
  agent:
    image: agent
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
  vpn:
    image: vpn
    network_mode: host
  gpu:
    image: gpu
    devices:
      - /dev/dri
  top:
    image: top
    pid: host
  root:
    image: root
    privileged: true
volumes:
  data: {}
`),
    ).toEqual(["backup", "agent", "vpn", "gpu", "top", "root"]);
    expect(unconfinedServices("services: [")).toEqual([]);
  });
});

describe("what the history says", () => {
  it("names each confinement step", () => {
    const step = (action: "apply" | "undo" | "containers") =>
      confinementActionText({ kind: "host", name: "confinement", action });
    expect(step("apply")).toBe("Turn on SELinux or AppArmor");
    expect(step("undo")).toBe("Undo SELinux or AppArmor");
    expect(step("containers")).toBe(
      "Change whether SELinux confines containers",
    );
    expect(
      confinementActionText({
        kind: "host",
        name: "firewall",
        action: "apply",
      }),
    ).toBeNull();
  });
});
