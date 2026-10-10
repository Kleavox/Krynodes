import { describe, expect, it } from "vitest";

import type { ServiceEntry } from "../types";
import {
  checkTargetProblem,
  containerChecksReady,
  pickedKind,
  targetOptions,
} from "./checks";

const service = (kind: ServiceEntry["kind"], name: string): ServiceEntry => ({
  kind,
  name,
  state: "running",
  since: null,
  system: false,
});

describe("picked targets", () => {
  const services = [
    service("systemd", "tailscaled.service"),
    service("docker", "adguard-adguard-1"),
    service("systemd", "nginx.service"),
    service("docker", "web-1"),
    service("systemd", "nginx.service"),
  ];

  it("lists only the chosen kind, sorted and once each", () => {
    expect(targetOptions(services, "SERVICE", "")).toEqual([
      { name: "nginx.service", seen: true },
      { name: "tailscaled.service", seen: true },
    ]);
    expect(targetOptions(services, "CONTAINER", "")).toEqual([
      { name: "adguard-adguard-1", seen: true },
      { name: "web-1", seen: true },
    ]);
    expect(targetOptions(services, "HTTP", "")).toEqual([]);
    expect(targetOptions(undefined, "CONTAINER", "")).toEqual([]);
  });

  it("keeps a current target the server no longer shows", () => {
    expect(targetOptions(services, "CONTAINER", "old-db")).toEqual([
      { name: "old-db", seen: false },
      { name: "adguard-adguard-1", seen: true },
      { name: "web-1", seen: true },
    ]);
    expect(targetOptions(services, "CONTAINER", "web-1")).toHaveLength(2);
  });

  it("knows which kinds are picked rather than typed", () => {
    expect(pickedKind("SERVICE")).toBe(true);
    expect(pickedKind("CONTAINER")).toBe(true);
    expect(pickedKind("HTTP")).toBe(false);
    expect(pickedKind("TCP")).toBe(false);
  });

  it("asks for a pick instead of a typed name", () => {
    expect(checkTargetProblem("CONTAINER", "")).toBe("Choose a container.");
    expect(checkTargetProblem("SERVICE", "")).toBe("Choose a service.");
    expect(checkTargetProblem("CONTAINER", "adguard-adguard-1")).toBeNull();
  });

  it("offers container checks from agent 0.6.3", () => {
    expect(containerChecksReady("0.6.3")).toBe(true);
    expect(containerChecksReady("0.7.0")).toBe(true);
    expect(containerChecksReady("0.6.2")).toBe(false);
    expect(containerChecksReady(null)).toBe(false);
    expect(containerChecksReady("dev")).toBe(false);
  });
});

describe("check targets", () => {
  it("accepts what the Worker accepts", () => {
    expect(checkTargetProblem("HTTP", "https://example.com/health")).toBeNull();
    expect(checkTargetProblem("HTTP", " http://10.0.0.2:8080 ")).toBeNull();
    expect(checkTargetProblem("TCP", "db.internal:5432")).toBeNull();
    expect(checkTargetProblem("SERVICE", "nginx.service")).toBeNull();
    expect(checkTargetProblem("SERVICE", "getty@tty1.service")).toBeNull();
  });

  it("says what is wrong for each kind", () => {
    expect(checkTargetProblem("HTTP", "")).toBe("Enter a target.");
    expect(checkTargetProblem("HTTP", "example.com")).toBe(
      "Use a full URL starting with http:// or https://.",
    );
    expect(checkTargetProblem("HTTP", "ftp://example.com")).toBe(
      "Use a full URL starting with http:// or https://.",
    );
    expect(checkTargetProblem("TCP", "example.com")).toBe(
      "Use host:port, such as 127.0.0.1:5432.",
    );
    expect(checkTargetProblem("TCP", "example.com:70000")).toBe(
      "The port must be between 1 and 65535.",
    );
    expect(checkTargetProblem("SERVICE", "nginx service")).toBe(
      "Use a systemd unit name, such as nginx.service.",
    );
  });
});
