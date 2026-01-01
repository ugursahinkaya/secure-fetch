import { CryptoLib } from "@ugursahinkaya/crypto-lib";
import type { Logger } from "@ugursahinkaya/logger";

export class CryptoManager {
  private crypto: CryptoLib;
  private logger: Logger;

  constructor(logger: Logger) {
    this.crypto = new CryptoLib();
    this.logger = logger;
  }

  async generateServerKey(): Promise<string> {
    await this.crypto.generateKey("server");
    const clientPublicKeyBytes = await this.crypto.exportKey("server");
    return this.crypto.arrayBufferToBase64(clientPublicKeyBytes);
  }

  async importServerPublicKey(base64Key: string): Promise<void> {
    try {
      const publicKey = this.crypto.base64ToArrayBuffer(base64Key);
      const secret = await this.crypto.importPublicKey(
        publicKey as BufferSource,
        "server"
      );
      this.crypto.keyMap.set("serverSCR", secret);
      this.logger.debug("Server public key imported", "CryptoManager");
    } catch (error) {
      this.logger.error(error as string, ["CryptoManager", "importServerPublicKey"]);
      throw error;
    }
  }

  async encrypt(data: string): Promise<[ArrayBuffer, Uint8Array]> {
    return this.crypto.encrypt(data, "server");
  }

  async decrypt(buffer: ArrayBufferLike): Promise<any> {
    const [data, tag, nonce] = this.crypto.prepareBuffer(buffer);
    const rawPayload = await this.crypto.decrypt(data, tag, nonce, "server");
    try {
      return JSON.parse(rawPayload);
    } catch (error) {
      this.logger.error("JSON parse failed", ["CryptoManager", "decrypt"]);
      throw new Error("Invalid JSON response from server");
    }
  }

  hasSecret(key: string): boolean {
    return this.crypto.hasSecret(key);
  }
}
