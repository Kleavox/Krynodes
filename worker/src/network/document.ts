import {
  assertionSchema,
  networkDocumentSchema,
  type NetworkDocument,
} from "@krynodes/protocol";
import { z } from "zod";

import { fromB64url } from "../lib/b64url";

export const MAX_SIGNED = 524288;

const b64url = z.string().regex(/^[A-Za-z0-9_-]+$/u);

const signedDocumentSchema = z.strictObject({
  grant: assertionSchema.extend({ grant: b64url.max(4096) }),
  document: b64url.max(MAX_SIGNED),
  signature: b64url.max(4096),
});

type SignedDocument = z.infer<typeof signedDocumentSchema>;

export interface ReadDocument {
  signed: SignedDocument;
  body: Uint8Array<ArrayBuffer>;
  document: NetworkDocument;
}

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function readSigned(text: string): ReadDocument | null {
  try {
    const signed = signedDocumentSchema.safeParse(JSON.parse(text));
    if (
      !signed.success ||
      fromB64url(signed.data.grant.authenticatorData).length < 37
    ) {
      return null;
    }
    const body = fromB64url(signed.data.document);
    const document = networkDocumentSchema.safeParse(
      JSON.parse(decoder.decode(body)),
    );
    return document.success
      ? { signed: signed.data, body, document: document.data }
      : null;
  } catch {
    return null;
  }
}
