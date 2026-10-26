import { useState } from "react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { errorMessage } from "@/lib/http";
import { parseVendorPaste, repoLines, type RepoPreview } from "@/lib/packages";
import type { AptReport, NodeRecord } from "@/types";

import { Lines, Said, SHEET, SignButton } from "./lines";
import { useQuestion } from "./use-question";

interface Fields {
  name: string;
  release: string;
  components: string;
  uri: string;
  key: string;
  list: string;
}

export function RepoDialog({
  node,
  report,
  onClose,
  onStarted,
}: {
  node: NodeRecord;
  report: AptReport;
  onClose: () => void;
  onStarted: (id: string) => void;
}) {
  const [paste, setPaste] = useState("");
  const [fields, setFields] = useState<Fields>({
    name: "",
    release: report.codename,
    components: "main",
    uri: "",
    key: "",
    list: "",
  });
  const [checked, setChecked] = useState<string | null>(null);
  const preview = useQuestion<RepoPreview>();
  const run = useSignedAction(false);
  const current = JSON.stringify(fields);
  const set = (key: keyof Fields, value: string) =>
    setFields({ ...fields, [key]: value });
  const read = (text: string) => {
    setPaste(text);
    const found = parseVendorPaste(text);
    setFields({
      name: found.name ?? fields.name,
      release: found.release ?? fields.release,
      components: found.components ?? fields.components,
      uri: found.uri ?? fields.uri,
      key: found.key ?? fields.key,
      list: found.list ?? "",
    });
  };
  const complete =
    fields.name.trim() !== "" &&
    fields.key.trim() !== "" &&
    (fields.list !== "" ||
      (fields.uri.trim() !== "" &&
        fields.release.trim() !== "" &&
        fields.components.trim() !== ""));
  const check = () => {
    setChecked(current);
    preview.ask({
      nodeId: node.id,
      action: "preview",
      name: fields.name.trim(),
      args: {
        what: "addrepo",
        uri: fields.uri.trim(),
        suites: fields.release.trim(),
        components: fields.components.trim(),
        key: fields.key.trim(),
        ...(fields.list ? { list: fields.list } : {}),
      },
    });
  };
  const ready =
    checked === current &&
    !preview.waiting &&
    preview.value !== null &&
    preview.value.refused === null &&
    preview.value.key !== null;
  const add = () => {
    const tried = preview.value!;
    run.mutate(
      {
        action: "addrepo",
        mode: "parallel",
        targets: [
          {
            nodeId: node.id,
            kind: "apt",
            name: tried.name,
            args: {
              uri: tried.uri,
              suites: tried.suites.join(" "),
              components: tried.components.join(" "),
              key: fields.key.trim(),
              fingerprint: tried.key!.fingerprint,
            },
          },
        ],
      },
      { onSuccess: (sent) => onStarted(sent.actions[0]!.id) },
    );
  };
  const field = (key: keyof Fields, label: string, hint?: string) => (
    <div className="space-y-1.5">
      <Label htmlFor={`repo-${key}`}>
        {label}
        {hint && (
          <span className="font-normal text-muted-foreground"> · {hint}</span>
        )}
      </Label>
      <Input
        id={`repo-${key}`}
        value={fields[key]}
        onChange={(event) => set(key, event.target.value)}
        className="font-mono text-xs"
        spellCheck={false}
      />
    </div>
  );

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>Add Repository · {node.name}</DialogTitle>
          <DialogDescription>
            Paste the vendor's instructions, or fill in the fields yourself.
          </DialogDescription>
        </DialogHeader>
        <textarea
          value={paste}
          onChange={(event) => read(event.target.value)}
          aria-label="The vendor's instructions"
          placeholder="curl -fsSL https://… | sudo tee …"
          rows={3}
          spellCheck={false}
          className="w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
        />
        <p className="-mt-2 text-xs text-muted-foreground">
          Krynodes reads only the addresses in it and never runs any of it.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {field("name", "Name")}
          {field(
            "release",
            "Release",
            fields.release === report.codename ? "this server's" : undefined,
          )}
          <div className="sm:col-span-2">{field("uri", "Address")}</div>
          {field("components", "Components")}
          {field("key", "Key")}
        </div>
        {fields.list && (
          <p className="text-xs break-all text-muted-foreground">
            The address, release and components come from {fields.list}.
          </p>
        )}
        <div>
          <Button
            variant="outline"
            size="sm"
            disabled={!complete || preview.waiting}
            onClick={check}
          >
            {preview.waiting ? "Checking…" : "Check"}
          </Button>
        </div>
        {checked === current && !preview.waiting && (
          <>
            <Said text={preview.error} />
            {preview.value && (
              <Lines lines={repoLines(preview.value, report.system)} />
            )}
          </>
        )}
        <Said text={run.error ? errorMessage(run.error) : null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label="Add Repository"
            pending={run.isPending}
            disabled={!ready}
            onClick={add}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function DropRepoDialog({
  node,
  name,
  label,
  onClose,
}: {
  node: NodeRecord;
  name: string;
  label: string;
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  return (
    <ConfirmDialog
      open
      onOpenChange={(open) => !open && onClose()}
      title={`Remove the ${label} repository?`}
      description={`Its file and its key leave ${node.name}. Packages installed from it stay, and get no more updates from it.`}
      confirmLabel="Remove"
      guarded
      mutation={run}
      variables={{
        action: "droprepo",
        mode: "parallel",
        targets: [{ nodeId: node.id, kind: "apt", name }],
      }}
    />
  );
}
