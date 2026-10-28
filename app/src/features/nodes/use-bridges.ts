import { useNetwork, useServices } from "@/lib/api";
import type { NodeRecord } from "@/types";

export function useBridges(node: Pick<NodeRecord, "id" | "name">) {
  const entry = useServices().data?.nodes.find((item) => item.id === node.id);
  const privateRange = useNetwork().data?.network?.range ?? null;
  return {
    server: {
      name: node.name,
      bridges: entry?.bridges ?? null,
      stacks: entry?.stacks ?? [],
    },
    privateRange,
  };
}
