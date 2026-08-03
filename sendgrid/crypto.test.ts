import { beforeAll, describe, expect, it } from "vitest";
import { decryptSecret, encryptSecret, maskApiKey, maskProxy } from "./crypto";

describe("credential protection", () => {
  beforeAll(() => {
    process.env.JWT_SECRET = "unit-test-secret-that-is-not-used-in-production";
  });

  it("encrypts with authenticated encryption and decrypts losslessly", () => {
    const plaintext = "SG.example_secret_value_1234567890";
    const encrypted = encryptSecret(plaintext);

    expect(encrypted.cipher).not.toContain(plaintext);
    expect(encrypted.iv).not.toHaveLength(0);
    expect(encrypted.tag).not.toHaveLength(0);
    expect(decryptSecret(encrypted)).toBe(plaintext);
  });

  it("masks keys and proxy credentials before presentation", () => {
    expect(maskApiKey("SG.long_secret_value_1234567890")).toMatch(/^SG\.long.*7890$/);
    expect(maskApiKey("SG.long_secret_value_1234567890")).not.toContain("secret_value");
    expect(maskProxy("alice:super-secret@proxy.example:8080")).toBe("alice:••••@proxy.example:8080");
  });
});
