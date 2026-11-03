import { cn } from "@/lib/utils";

export type ServerTab = "overview" | "security";

const TABS: { key: ServerTab; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "security", label: "Security" },
];

export const serverTab = (value: string | null): ServerTab =>
  value === "security" ? "security" : "overview";

export const tabPanel = "server-tab-panel";

export function ServerTabs({
  tab,
  onTab,
}: {
  tab: ServerTab;
  onTab: (tab: ServerTab) => void;
}) {
  return (
    <div
      role="tablist"
      aria-label="Server"
      className="mb-5 flex gap-1 border-b"
    >
      {TABS.map((entry) => (
        <button
          key={entry.key}
          id={`server-tab-${entry.key}`}
          type="button"
          role="tab"
          aria-selected={tab === entry.key}
          aria-controls={tabPanel}
          onClick={() => onTab(entry.key)}
          className={cn(
            "-mb-px h-10 border-b-2 border-transparent px-3 text-sm text-muted-foreground hover:text-foreground md:h-9",
            tab === entry.key && "border-primary font-medium text-foreground",
          )}
        >
          {entry.label}
        </button>
      ))}
    </div>
  );
}
