import { Check, ChevronsUpDown } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";

export function TargetPicker({
  id,
  options,
  value,
  onChange,
  placeholder,
  empty,
  search,
  invalid,
  describedBy,
}: {
  id: string;
  options: { name: string; seen: boolean }[];
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  empty: string;
  search: string;
  invalid: boolean;
  describedBy: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-invalid={invalid}
          aria-describedby={describedBy}
          className="w-full justify-between font-mono font-normal"
        >
          <span className={cn("truncate", !value && "text-muted-foreground")}>
            {value || placeholder}
          </span>
          <ChevronsUpDown aria-hidden="true" className="opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-(--radix-popover-trigger-width) max-w-[calc(100vw-2rem)] p-0"
      >
        <Command>
          <CommandInput placeholder={search} />
          <CommandList>
            <CommandEmpty>{empty}</CommandEmpty>
            {options.map((option) => (
              <CommandItem
                key={option.name}
                value={option.name}
                onSelect={() => {
                  onChange(option.name);
                  setOpen(false);
                }}
                className="font-mono"
              >
                <Check
                  aria-hidden="true"
                  className={cn(
                    "shrink-0",
                    option.name === value ? "opacity-100" : "opacity-0",
                  )}
                />
                <span className="min-w-0 flex-1 truncate">{option.name}</span>
                {!option.seen && (
                  <span className="shrink-0 font-sans text-xs text-muted-foreground">
                    Not seen on this server
                  </span>
                )}
              </CommandItem>
            ))}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
