export function Busy({
  children,
  label,
}: {
  children: string;
  label?: string;
}) {
  const word = children.replace(/…$/u, "");
  return (
    <span>
      {label ? (
        <>
          <span aria-hidden="true">{word}</span>
          <span className="sr-only">{label}</span>
        </>
      ) : (
        word
      )}
      <span aria-hidden="true" className="inline-block w-[1em] text-left">
        <span className="animate-busy-1">.</span>
        <span className="animate-busy-2">.</span>
        <span className="animate-busy-3">.</span>
      </span>
    </span>
  );
}

export const Waiting = () => (
  <Busy label="Waiting for your passkey">Waiting</Busy>
);
