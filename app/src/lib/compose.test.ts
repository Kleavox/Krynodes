import { describe, expect, it } from "vitest";

import { moveCompose, portsOf, servicesOf, summarize } from "./compose";

const adguard = `services:
  adguard:
    image: adguard/adguardhome:v0.107
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "127.0.0.1:3000:3000"
      - target: 853
        published: 853
        protocol: tcp
    volumes:
      - ./work:/opt/adguardhome/work
      - /srv/adguard/conf:/opt/adguardhome/conf
      - type: bind
        source: /etc/localtime
        target: /etc/localtime
  dhcp:
    image: busybox
    network_mode: host
    privileged: true
    devices:
      - /dev/dri:/dev/dri
  app:
    build: .
    expose: ["8080"]
`;

describe("reading a compose file", () => {
  it("names what a Full access stack opens", () => {
    expect(summarize(adguard)).toEqual({
      services: ["adguard", "dhcp", "app"],
      internet: ["53/udp", "53/tcp", "853/tcp"],
      folders: ["/srv/adguard/conf", "/etc/localtime"],
      hostNetwork: ["dhcp"],
      devices: ["dhcp"],
      privileged: ["dhcp"],
      builds: ["app"],
      docker: [],
      error: null,
    });
  });

  it("names a service that controls Docker, which is root on the server", () => {
    const text = `services:
  agent:
    image: portainer/agent
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  helper:
    image: docker/helper
    use_api_socket: true
  web:
    image: nginx
`;
    expect(summarize(text).docker).toEqual(["agent", "helper"]);
  });

  it("says when the text is not a compose file", () => {
    expect(summarize("services: [").error).toMatch(/line 1/u);
    expect(summarize("just: text").error).toBe(
      "A compose file needs a services section.",
    );
  });

  it("lists services and the ports each one listens on", () => {
    expect(servicesOf(adguard)).toEqual(["adguard", "dhcp", "app"]);
    expect(portsOf(adguard, "adguard")).toEqual([53, 3000, 853]);
    expect(portsOf(adguard, "app")).toEqual([8080]);
    expect(portsOf(adguard, "missing")).toEqual([]);
  });
});

const listmonk = `# listmonk with a test mail catcher
services:
  app:
    image: listmonk/listmonk:v5
    depends_on:
      - db
      - mailpit
    environment:
      LISTMONK_app__smtp_host: mailpit
      TZ: Asia/Jakarta
  db:
    image: postgres:17
    depends_on:
      mailpit:
        condition: service_started
    environment:
      - POSTGRES_HOST=mailpit-free-name
  mailpit:
    image: axllent/mailpit
`;

describe("moving a compose file", () => {
  it("drops unticked services, their links and pins the tested images", () => {
    const moved = moveCompose(listmonk, ["app", "db"], {
      app: "listmonk/listmonk:v5@sha256:aaa",
    });
    expect(moved.text).toContain("# listmonk with a test mail catcher");
    expect(moved.text).not.toContain("axllent/mailpit");
    expect(moved.text).toContain("image: listmonk/listmonk:v5@sha256:aaa");
    expect(moved.text).toContain("image: postgres:17");
    expect(servicesOf(moved.text)).toEqual(["app", "db"]);
    expect(moved.text).not.toMatch(/- mailpit|mailpit:\n\s+condition/u);
    expect(moved.flagged).toEqual([
      "app: LISTMONK_app__smtp_host still names mailpit",
    ]);
  });
});
