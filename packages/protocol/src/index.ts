import { z } from "zod";

export {
  CONTAINER_NAME,
  isProtected,
  isValidTarget,
  parseStackNames,
  RECIPES,
  SELINUX_BOOLEAN,
  stackNamesValid,
  stackTitleValid,
} from "./targets";
export {
  DEFAULT_RULE,
  dnsName,
  DOCUMENT_TAG,
  documentHash,
  joinFingerprint,
  laptopAddress6,
  laptopEnrollSchema,
  links,
  NETWORK,
  IPV4,
  networkArgsValid,
  networkDocumentSchema,
  networkInspectSchema,
  networkInventorySchema,
  networkLinkSchema,
  networkPreparedSchema,
  networkProbeSchema,
  networkRekeySchema,
  networkTestSchema,
  pickAddresses,
  pickRange,
  placeSchema,
  stackNetworkSchema,
  type NetworkDocument,
  type NetworkInspect,
  type NetworkInventory,
  type NetworkLink,
  type NetworkMember,
  type NetworkRule,
  type NetworkTest,
  type StackNetwork,
} from "./network";
export {
  checkSchema,
  checksSchema,
  containerEntrySchema,
  inventorySchema,
  removedEntrySchema,
  STACK_ACTIONS,
  stackArgsValid,
  stackEntrySchema,
  unitEntrySchema,
  type ContainerCheck,
  type ContainerEntry,
  type Inventory,
  type RemovedEntry,
  type StackEntry,
  type StackKind,
  type UnitEntry,
} from "./stacks";
export { agentSupported, compareVersions, MIN_AGENT } from "./versions";
export {
  agentMessageSchema,
  COMMAND_ACTIONS,
  COMMAND_KINDS,
  hubMessageSchema,
  networkHelloSchema,
  parseAgentMessage,
  parseHubMessage,
  trustReportSchema,
  WIRE_VERSION,
  type AgentMessage,
  type CommandKind,
  type HubMessage,
  type NetworkHello,
  type TrustReport,
} from "./wire";

export const SESSION_MS = 15 * 60_000;
export const COMMAND_GRACE_MS = 60 * 60_000;
export const TRUST_CHANGE_MS = 10 * 60_000;

const b64url = z
  .string()
  .min(1)
  .max(4096)
  .regex(/^[A-Za-z0-9_-]+$/u);

export const assertionSchema = z.strictObject({
  credentialId: b64url,
  authenticatorData: b64url,
  clientDataJSON: b64url,
  signature: b64url,
});

export const signedCommandSchema = z.strictObject({
  grant: assertionSchema.extend({ grant: b64url }),
  command: z
    .string()
    .min(1)
    .max(147456)
    .regex(/^[A-Za-z0-9_-]+$/u),
  signature: b64url,
});

export const signedTrustSchema = z.strictObject({
  change: z
    .string()
    .min(1)
    .max(65536)
    .regex(/^[A-Za-z0-9_-]+$/u),
  approvals: z.array(assertionSchema).max(20),
});

export type Assertion = z.infer<typeof assertionSchema>;
export type SignedCommand = z.infer<typeof signedCommandSchema>;
export type SignedTrust = z.infer<typeof signedTrustSchema>;
