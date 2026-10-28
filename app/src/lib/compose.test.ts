import { describe, expect, it } from "vitest";

import {
  moveCompose,
  portsOf,
  publishedPorts,
  publishedRanges,
  servicesOf,
  sharedNetworksOf,
  summarize,
  usePrivateAddress,
  usesPrivateIp,
} from "./compose";

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
      private: [],
      error: null,
    });
  });

  it("tells ports on the private address from ports on the internet", () => {
    const text = `services:
  grafana:
    image: grafana/grafana:11.3.0
    ports:
      - "\${KRY_PRIVATE_IP}:3000:3000"
      - "8080:80"
      - target: 9090
        published: 9090
        host_ip: \${KRY_PRIVATE_IP}
`;
    const summary = summarize(text);
    expect(summary.internet).toEqual(["8080/tcp"]);
    expect(summary.private).toEqual(["3000/tcp", "9090/tcp"]);
    expect(usesPrivateIp(text)).toBe(true);
    expect(usesPrivateIp(adguard)).toBe(false);
  });

  it("lists the ports a file publishes with the service that publishes each", () => {
    expect(publishedPorts(adguard)).toEqual([
      { port: "53/udp", service: "adguard" },
      { port: "53/tcp", service: "adguard" },
      { port: "3000/tcp", service: "adguard" },
      { port: "853/tcp", service: "adguard" },
    ]);
    expect(publishedPorts("services:\n  web:\n    ports: ['80']\n")).toEqual(
      [],
    );
  });

  it("lists published port ranges apart, since only single ports are served", () => {
    const text = `services:
  rtp:
    ports:
      - "10000-10010:10000-10010/udp"
      - target: 8000
        published: "8000-8002"
      - "3000:3000"
`;
    expect(publishedRanges(text)).toEqual([
      { port: "10000-10010/udp", service: "rtp" },
      { port: "8000-8002/tcp", service: "rtp" },
    ]);
    expect(publishedPorts(text)).toEqual([
      { port: "3000/tcp", service: "rtp" },
    ]);
  });

  it("moves only ports with no host address to the private address", () => {
    const text = `services:
  grafana:
    image: grafana/grafana:11.3.0
    restart: unless-stopped
    ports:
      - "3000:3000"
      - 5353:5353/udp
      - "127.0.0.1:9000:9000"
      - "8080"
    volumes:
      - ./data:/var/lib/grafana
`;
    expect(usePrivateAddress(text)).toBe(`services:
  grafana:
    image: grafana/grafana:11.3.0
    restart: unless-stopped
    ports:
      - "\${KRY_PRIVATE_IP}:3000:3000"
      - \${KRY_PRIVATE_IP}:5353:5353/udp
      - "127.0.0.1:9000:9000"
      - "8080"
    volumes:
      - ./data:/var/lib/grafana
`);
    expect(usePrivateAddress(usePrivateAddress(text))).toBe(
      usePrivateAddress(text),
    );
    expect(usePrivateAddress("services: [")).toBe("services: [");
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

describe("networks a stack shares", () => {
  it("lists only external networks, by Docker name, with the services on each", () => {
    expect(
      sharedNetworksOf(`services:
  web:
    image: x
    networks: [inner, default]
  worker:
    image: y
    networks:
      inner:
        aliases: [jobs]
  cache:
    image: z
networks:
  inner:
    name: apps-inner
    external: true
  public:
    external: true
  default: {}
`),
    ).toEqual([
      { key: "inner", name: "apps-inner", services: ["web", "worker"] },
      { key: "public", name: "public", services: [] },
    ]);
    expect(sharedNetworksOf("services: [")).toEqual([]);
  });
});
