import type { NetworkDocument, NetworkRule } from "@krynodes/protocol";
import { useState } from "react";

import { Waiting } from "@/components/busy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { changeNetwork } from "@/lib/approve";
import { networkFailure } from "@/lib/network";
import {
  applyLines,
  blankForm,
  canSave,
  changeFrom,
  describeRule,
  failuresOf,
  formOf,
  fromOptions,
  namesOf,
  openWarning,
  portsError,
  ruleChange,
  ruleOf,
  saveRule,
  targetsOf,
  toOptions,
  type RuleForm,
  type RuleOption,
} from "@/lib/rules";

import { useOneTimeCheck } from "./one-time-check";
import { useNetworkView, useRefreshNetwork } from "./use-network";

const PORT_MODES: RuleOption[] = [
  { value: "all", label: "All Ports" },
  { value: "specific", label: "Specific Ports" },
];

function Choice({
  id,
  label,
  value,
  options,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  options: RuleOption[];
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value} disabled={disabled} onValueChange={onChange}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export function RuleFields({
  document,
  form,
  touched,
  disabled,
  onTouch,
  onChange,
}: {
  document: NetworkDocument;
  form: RuleForm;
  touched: boolean;
  disabled: boolean;
  onTouch: () => void;
  onChange: (form: RuleForm) => void;
}) {
  const built = ruleOf(form);
  const rule = "rule" in built ? built.rule : null;
  const warning = rule ? openWarning(rule, document) : null;
  const wrong = touched ? portsError(form) : null;
  return (
    <div className="space-y-4">
      <Choice
        id="rule-from"
        label="From"
        value={form.from}
        options={fromOptions(document)}
        disabled={disabled}
        onChange={(from) => onChange(changeFrom(document, form, from))}
      />
      <Choice
        id="rule-to"
        label="To"
        value={form.to}
        options={toOptions(document, form.from)}
        disabled={disabled}
        onChange={(to) => onChange({ ...form, to })}
      />
      <Choice
        id="rule-port-mode"
        label="Ports"
        value={form.ports}
        options={PORT_MODES}
        disabled={disabled}
        onChange={(ports) =>
          onChange({ ...form, ports: ports === "all" ? "all" : "specific" })
        }
      />
      {form.ports === "specific" && (
        <div className="space-y-2">
          <Label htmlFor="rule-ports">Port List</Label>
          <Input
            id="rule-ports"
            value={form.text}
            spellCheck={false}
            className="font-mono"
            placeholder="22/tcp, 80,443/tcp, 8000-8100/udp"
            disabled={disabled}
            aria-invalid={wrong !== null}
            aria-describedby="rule-ports-note"
            onBlur={onTouch}
            onChange={(event) => {
              onTouch();
              onChange({ ...form, text: event.target.value });
            }}
          />
          <p
            id="rule-ports-note"
            className={
              wrong
                ? "text-sm text-destructive"
                : "text-xs text-muted-foreground"
            }
          >
            {wrong ??
              "Each port needs /tcp or /udp. Ranges look like 8000-8100/tcp."}
          </p>
        </div>
      )}
      {rule && (
        <p className="rounded-md border bg-muted/30 px-3 py-2 text-sm">
          {describeRule(rule, namesOf(document))}
        </p>
      )}
      {warning && (
        <p
          role="note"
          className="rounded-md border border-warning px-3 py-2 text-sm"
        >
          {warning}
        </p>
      )}
    </div>
  );
}

type Phase =
  | { phase: "form" }
  | { phase: "running" }
  | {
      phase: "sent";
      version: number;
      nodes: string[];
      before: Record<string, string | null>;
    };

export function RuleDialog({
  document,
  editing,
  onClose,
}: {
  document: NetworkDocument;
  editing: { index: number; rule: NetworkRule } | null;
  onClose: () => void;
}) {
  const refresh = useRefreshNetwork();
  const { check, panel } = useOneTimeCheck();
  const view = useNetworkView();
  const [form, setForm] = useState(() =>
    editing ? formOf(editing.rule) : blankForm(document),
  );
  const [state, setState] = useState<Phase>({ phase: "form" });
  const [failed, setFailed] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const built = ruleOf(form);
  const running = state.phase === "running";
  const save = () => {
    if (!("rule" in built)) return;
    const { rule } = built;
    const nodes = targetsOf(document, editing ? [editing.rule, rule] : [rule]);
    const before = failuresOf(view.data ?? { members: [] });
    const { change, detail } = ruleChange(rule, editing, namesOf(document));
    setState({ phase: "running" });
    setFailed(null);
    void changeNetwork((next) => saveRule(next, rule, editing), change, {
      detail,
      check,
    })
      .then(
        (version) => setState({ phase: "sent", version, nodes, before }),
        (error: unknown) => {
          setFailed(networkFailure(error));
          setState({ phase: "form" });
        },
      )
      .finally(refresh);
  };
  return (
    <Dialog open onOpenChange={(open) => !open && !running && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{editing ? "Edit Rule" : "Add Rule"}</DialogTitle>
          <DialogDescription>
            Choose who can connect, to which server and on which ports.
            Everything else stays blocked. Saving takes your passkey.
          </DialogDescription>
        </DialogHeader>
        {state.phase === "sent" ? (
          <div className="space-y-2 text-sm">
            <p role="status">{`Signed and sent as version ${state.version}.`}</p>
            <ul aria-label="Applying" className="space-y-1">
              {applyLines(
                view.data ?? { members: [] },
                state.nodes,
                state.version,
                state.before,
              ).map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
            <p className="text-xs text-muted-foreground">
              You can close this. Each server shows its state in Members.
            </p>
          </div>
        ) : (
          <RuleFields
            document={document}
            form={form}
            touched={touched}
            disabled={running}
            onTouch={() => setTouched(true)}
            onChange={setForm}
          />
        )}
        {failed && (
          <p role="alert" className="text-sm text-destructive">
            {failed}
          </p>
        )}
        {panel}
        <DialogFooter>
          <Button variant="ghost" disabled={running} onClick={onClose}>
            {state.phase === "sent" ? "Done" : "Cancel"}
          </Button>
          {state.phase !== "sent" && (
            <Button
              disabled={running || !canSave(form, editing)}
              onClick={save}
            >
              {running ? <Waiting /> : "Save"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
