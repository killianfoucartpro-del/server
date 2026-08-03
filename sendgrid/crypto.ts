import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export type EncryptedSecret = {
  cipher: string;
  iv: string;
  tag: string;
};

function encryptionKey() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is required to encrypt provider credentials");
  }

  return createHash("sha256").update(secret).digest();
}

export function encryptSecret(value: string): EncryptedSecret {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);

  return {
    cipher: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

export function decryptSecret(secret: EncryptedSecret): string {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(secret.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(secret.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(secret.cipher, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

export function maskApiKey(value: string): string {
  if (value.length <= 12) return `${value.slice(0, 3)}••••${value.slice(-2)}`;
  return `${value.slice(0, 7)}••••••••${value.slice(-4)}`;
}

export function maskProxy(value: string): string {
  const at = value.lastIndexOf("@");
  const endpoint = at >= 0 ? value.slice(at + 1) : value;
  const username = at >= 0 ? value.slice(0, at).split(":", 1)[0] : "proxy";
  return `${username}:••••@${endpoint}`;
}
