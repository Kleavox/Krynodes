import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  Incident,
  Overview,
  ServicesResponse,
} from "../types";
import { alsoActive, navCounts, PAGES, SECTIONS } from "./nav";

const incident = (status: Incident["status"]) => ({ status }) as Incident;
const action = (status: ActionRecord["status"]) => ({ status }) as ActionRecord;
const overviewWith = (incidents: Incident[]) =>
  ({ incidents }) as unknown as Overview;
const servicesWith = (actions: ActionRecord[]) =>
  ({ actions }) as unknown as ServicesResponse;

describe("the menu", () => {
  it("is Fleet, Services, Network, Checks, with History only among the pages", () => {
    expect(SECTIONS.map((section) => section.label)).toEqual([
      "Fleet",
      "Services",
      "Network",
      "Checks",
    ]);
    expect(PAGES.map((section) => section.to)).toEqual([
      "/",
      "/services",
      "/network",
      "/checks",
      "/history",
    ]);
  });

  it("puts the open incidents on Checks and the broken links on Network", () => {
    const counts = navCounts(
      overviewWith([incident("OPEN"), incident("OPEN"), incident("RESOLVED")]),
      servicesWith([action("queued"), action("done")]),
      1,
    );
    expect(counts).toEqual({ "/checks": 2, "/services": 1, "/network": 1 });
  });

  it("marks Checks while an incident is open on screen", () => {
    expect(alsoActive("/checks", "/incidents/i1")).toBe(true);
    expect(alsoActive("/checks", "/history")).toBe(false);
    expect(alsoActive("/", "/incidents/i1")).toBe(false);
  });

  it("counts nothing before the data arrives", () => {
    expect(navCounts(undefined, undefined)).toEqual({
      "/checks": 0,
      "/services": 0,
      "/network": 0,
    });
  });
});
