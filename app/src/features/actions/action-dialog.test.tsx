import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ActionRow } from "@/types";

import { ActionBody, type RunState } from "./action-dialog";

const row = (patch: Partial<ActionRow>): ActionRow => ({
  id: "a1",
  nodeId: "node-1",
  kind: "agent",
  name: "server-1",
  action: "update",
  title: "Update Agent to 0.8.1",
  status: "done",
  message: null,
  output: null,
  createdAt: "2026-11-22T10:00:00.000Z",
  finishedAt: null,
  ...patch,
});

const text = (state: RunState) =>
  renderToStaticMarkup(<ActionBody state={state} name="server-1" />).replace(
    /<[^>]+>/gu,
    " ",
  );

describe("the action dialog", () => {
  it("shows the progress lines in the order they came", () => {
    const shown = text({
      phase: "sending",
      lines: ["Downloading 0.8.1", "Verifying", "Restarting the agent"],
    });
    expect(shown).toMatch(
      /Downloading 0\.8\.1.*Verifying.*Restarting the agent/su,
    );
    expect(shown).toContain("Waiting for server-1");
  });

  it("shows the node's failure text as it came", () => {
    const shown = text({
      phase: "result",
      lines: [],
      row: row({
        status: "failed",
        message: "this server already runs 0.8.1",
      }),
    });
    expect(shown).toContain("this server already runs 0.8.1");
  });

  it("shows the node's answer when it is done", () => {
    expect(
      text({
        phase: "result",
        lines: [],
        row: row({ message: "Updated to 0.8.1." }),
      }),
    ).toContain("Updated to 0.8.1.");
  });

  it("shows a refusal from before the server was reached", () => {
    expect(
      text({ phase: "result", lines: [], error: "server-1 is offline." }),
    ).toContain("server-1 is offline.");
  });

  it("shows the opened logs as text", () => {
    const shown = renderToStaticMarkup(
      <ActionBody
        state={{
          phase: "result",
          lines: [],
          row: row({
            action: "logs",
            message: "The last 200 lines of web.",
            output: "web-1  ready\n",
          }),
        }}
        name="server-1"
      />,
    );
    expect(shown).toContain("<pre");
    expect(shown).toContain("web-1  ready");
  });

  it("shows a failure's opened detail under its fixed message", () => {
    const shown = renderToStaticMarkup(
      <ActionBody
        state={{
          phase: "result",
          lines: [],
          row: row({
            kind: "stack",
            action: "deploy",
            status: "failed",
            message: "Deploy of web failed.",
            output: "pull failed: denied",
          }),
        }}
        name="server-1"
      />,
    );
    expect(shown).toMatch(
      /role="alert"[^>]*>Deploy of web failed\.<\/p><pre[^>]*>pull failed: denied<\/pre>/u,
    );
  });

  it("shows a failure whose detail did not open as its message alone", () => {
    const shown = renderToStaticMarkup(
      <ActionBody
        state={{
          phase: "result",
          lines: [],
          row: row({
            kind: "stack",
            action: "deploy",
            status: "failed",
            message: "Deploy of web failed. The details could not be opened.",
            output: null,
          }),
        }}
        name="server-1"
      />,
    );
    expect(shown).toContain(
      "Deploy of web failed. The details could not be opened.",
    );
    expect(shown).not.toContain("<pre");
  });

  it("shows an answer that could not be opened as an error with no text", () => {
    const shown = renderToStaticMarkup(
      <ActionBody
        state={{
          phase: "result",
          lines: [],
          error: "The server's answer could not be opened.",
        }}
        name="server-1"
      />,
    );
    expect(shown).toContain('role="alert"');
    expect(shown).toContain("could not be opened");
    expect(shown).not.toContain("<pre");
  });
});
