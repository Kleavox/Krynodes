import { useEffect, useState } from "react";

import { fingerprint, formatPrint } from "@/lib/devices";
import { clockTime, shortDate } from "@/lib/format";
import { cn } from "@/lib/utils";

export const when = (value: string | number) =>
  `${shortDate(value)} ${clockTime(value)}`;

export const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

function useLocalPrint(publicKey: string | undefined): string | null {
  const [print, setPrint] = useState<{ key: string; value: string } | null>(
    null,
  );
  useEffect(() => {
    if (!publicKey) return;
    let current = true;
    fingerprint(publicKey).then(
      (value) => {
        if (current) setPrint({ key: publicKey, value });
      },
      () => {
        if (current) setPrint({ key: publicKey, value: "" });
      },
    );
    return () => {
      current = false;
    };
  }, [publicKey]);
  return print && print.key === publicKey ? print.value : null;
}

export function BigPrint({
  publicKey,
  className,
}: {
  publicKey: string;
  className?: string;
}) {
  const print = useLocalPrint(publicKey);
  return (
    <p
      className={cn(
        "font-mono text-xl font-semibold tracking-wider break-all sm:text-2xl",
        className,
      )}
      aria-label={print ? `Fingerprint ${formatPrint(print)}` : "Fingerprint"}
    >
      {print === null ? "…" : print ? formatPrint(print) : "Unreadable Key"}
    </p>
  );
}
