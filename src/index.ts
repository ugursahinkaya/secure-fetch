import { CryptoLib } from "@ugursahinkaya/crypto-lib";
import { GenericRouter } from "@ugursahinkaya/generic-router";
import type { SecureFetchApiOperations } from "@ugursahinkaya/shared-types";

export class SecureFetch<
  TOperations extends SecureFetchApiOperations,
> extends GenericRouter<TOperations> {
  protected crypto: CryptoLib;
  protected accessToken: string | undefined;
  protected refreshToken: string | undefined;
  protected expiryDate: string | undefined;
  protected queryToken: string | undefined;
  protected cookies: Record<string, any> = {};
  protected ready = false;
  protected checkStatus(response: Response) {
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} - ${response.statusText}`);
    }
  }
  protected async checkAccessToken(data: Record<string, any>) {
    console.log("checkAccessToken res", data);

    this.saveTokens(
      data as {
        refreshToken: string;
        accessToken: string;
        expiryDate: string;
      }
    );
  }
  protected checkCookies(response: Response) {
    const { headers } = response;
    const cookies = headers.get("set-cookie");
    if (cookies) {
      const cookeiList = cookies.split(",");
      cookeiList.map((keyValue) => {
        const [key, value] = keyValue
          .split("=")
          .map((v) => v.split(";")[0]?.trim());
        if (key) {
          if (key === "accessToken") {
            this.accessToken = value;
            this.cookies[key] = value;
          }
          if (key === "queryToken") {
            this.queryToken = value;
            this.cookies[key] = value;
          }
        }
      });
    }
  }
  protected async getPayload(buffer: ArrayBufferLike) {
    const [data, tag, nonce] = this.crypto.prepareBuffer(buffer);
    const rawPayload = await this.crypto.decrypt(data, tag, nonce, "server");
    return JSON.parse(rawPayload);
  }
  protected saveTokens(data: {
    refreshToken: string;
    accessToken: string;
    expiryDate: string;
  }) {
    console.log("saveTokens", data);
    const { refreshToken, accessToken, expiryDate } = data;
    if (!accessToken && !refreshToken) {
      return { error: true };
    }
    if (refreshToken) {
      void this.call("saveRefreshToken", refreshToken);
      this.refreshToken = refreshToken;
    }
    if (accessToken) {
      this.accessToken = accessToken;
      this.expiryDate = expiryDate;
    }

    return {};
  }
  protected async getQueryToken() {
    console.log("SecureFetch getQueryToken");
    await this.crypto.generateKey("server");
    const clientPublicKeyBytes = await this.crypto.exportKey("server");
    const clientPublicKey =
      this.crypto.arrayBufferToBase64(clientPublicKeyBytes);
    const path = this.serverDomain + "/getQueryToken";
    const args: RequestInit = {
      method: "POST",
      mode: "cors",
      credentials: "include",
      referrerPolicy: "same-origin",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ clientPublicKey }),
    };

    const response = await fetch(new Request(path, args));
    this.checkStatus(response);
    this.checkCookies(response);
    const data = await response.json();
    console.log("data", data);
    try {
      const publicKey = this.crypto.base64ToArrayBuffer(
        data.serverPublicKey as string
      );
      const secret = await this.crypto.importPublicKey(publicKey, "server");
      if (data.process === "refreshToken") {
        const savedRefreshToken = await this.call("getRefreshToken");
        const refreshToken = savedRefreshToken ?? this.refreshToken;
        if (!refreshToken) {
          throw new Error("refreshToken must be provided");
        }
        return this.refresh(refreshToken);
      }
      this.crypto.keyMap.set("serverSCR", secret);
      if (!this.ready) {
        void this.call("readyToFetch");
      }
      this.ready = true;
      return {};
    } catch (err) {
      console.log(err);
      return { error: true };
    }
  }
  constructor(
    public serverDomain: string,
    operations: TOperations
  ) {
    console.log("SecureFetch constructor", operations);
    super(operations);
    this.crypto = new CryptoLib();
    void this.getQueryToken();
  }
  queryTokenValue() {
    return this.queryToken;
  }
  async fetch(
    path: string,
    body: any,
    method = "POST",
    extraArgs: Partial<RequestInit> = {}
  ) {
    if (!this.crypto.hasSecret("server")) {
      await this.getQueryToken();
    }
    const [ciphertext, iv] = await this.crypto.encrypt(
      JSON.stringify(body),
      "server"
    );

    if (!extraArgs.headers) extraArgs.headers = {};
    let cookie = "";
    if (this.queryToken) {
      cookie += `queryToken=${this.queryToken}`;
    }
    if (this.accessToken) {
      if (this.queryToken !== "") {
        cookie += "; ";
      }
      cookie += `accessToken=${this.accessToken}`;
    }
    //@ts-expect-error TODO:
    extraArgs.headers["Cookie"] = cookie;

    const args: RequestInit = {
      method,
      mode: "cors",
      credentials: "include",
      referrerPolicy: "same-origin",
      headers: {
        "Content-Type": "octet-stream",
        ...extraArgs.headers,
      },
      body: new Blob([iv, ciphertext], {
        type: "text/plain",
      }),
      ...extraArgs,
    };
    const response = await fetch(new Request(path, args));
    this.checkStatus(response);
    this.checkCookies(response);
    const buffer = await response.arrayBuffer();
    const res = await this.getPayload(buffer);
    //this.checkAccessToken(res);
    return res;
  }

  async refresh(refreshToken: string) {
    const res = await this.fetch(`${this.serverDomain}/refreshToken`, {
      refreshToken,
    });
    console.log("refreshr res", res);
    return this.saveTokens(res);
  }
  async getAccessToken(username: string, password: string) {
    const res = await this.fetch(`${this.serverDomain}/getAccessToken`, {
      username,
      password,
    });
    console.log("getAccessToken res", res);

    return this.saveTokens(res);
  }
}
