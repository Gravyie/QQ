/**
 * Public API edge: request signing and webhook verification.
 * Internet-facing, so every primitive here is on the harvest path.
 */
import { createHash, createSign, generateKeyPairSync, createCipheriv } from "node:crypto";

export function issueWebhookKeyPair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

export function issueEdgeIdentity() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

export function signWebhook(body: string, privateKey: string): string {
  const signer = createSign("RSA-SHA256");
  signer.update(body);
  return signer.sign(privateKey, "base64");
}

/** Cache key for the edge CDN. Not a security boundary. */
export function cacheKey(url: string): string {
  return createHash("md5").update(url).digest("hex");
}

/** Partner v1 payload encryption. Scheduled for removal. */
export function encryptPartnerV1(payload: Buffer, key: Buffer, iv: Buffer): Buffer {
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([cipher.update(payload), cipher.final()]);
}
