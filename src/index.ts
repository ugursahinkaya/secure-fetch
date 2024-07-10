import { CryptoLib } from "@ugursahinkaya/crypto-lib";
import { GenericRouter } from "@ugursahinkaya/generic-router";
import { Logger } from "@ugursahinkaya/logger";
import { randomString } from "@ugursahinkaya/utils";
import { LogLevel } from "@ugursahinkaya/shared-types";

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
  protected deviceId: string;
  protected secureFetchLogger: Logger;

  protected checkStatus(response: Response, path: string) {
    if (!response.ok) {
      this.secureFetchLogger.error(
        `response status error: ${response.status}`,
        ["checkStatus", path]
      );
      throw new Error(`HTTP ${response.status} - ${response.statusText}`);
    }
  }
  protected async checkAccessToken(data: Record<string, any>) {
    this.secureFetchLogger.debug(data, ["checkAccessToken"]);

    this.saveTokens(
      data as {
        refreshToken: string;
        accessToken: string;
        expiryDate: string;
        queryToken: string;
      }
    );
  }
  protected checkCookies(response: Response, path: string) {
    const { headers } = response;
    const cookies = headers.get("set-cookie");
    this.secureFetchLogger.debug(cookies ?? {}, ["checkCookies", path]);
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
    queryToken: string;
    error?: string;
  }) {
    this.secureFetchLogger.debug(data, "saveTokens");

    if (data.error) {
      throw new Error(data.error);
    }
    const { refreshToken, accessToken, expiryDate, queryToken } = data;
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
      void this.call("loggedIn", queryToken);
    }

    return { queryToken, refreshToken };
  }
  async getQueryToken() {
    this.secureFetchLogger.debug("", "getQueryToken");
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
        Cookie: `deviceId=${this.deviceId};`,
      },
      body: JSON.stringify({ clientPublicKey }),
    };

    const response = await fetch(new Request(path, args));

    this.checkStatus(response, "getQueryToken");
    this.checkCookies(response, "getQueryToken");
    const data = await response.json();
    this.secureFetchLogger.debug(data, ["getQueryToken", "response"]);

    try {
      const publicKey = this.crypto.base64ToArrayBuffer(
        data.serverPublicKey as string
      );
      const secret = await this.crypto.importPublicKey(publicKey, "server");
      this.secureFetchLogger.debug(
        "secret imported for server",
        "getQueryToken"
      );
      this.secureFetchLogger.debug({ process: data.process }, "getQueryToken");
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
        if (data.process === "loggedIn") {
          void this.call("loggedIn", data.queryToken);
        } else {
          void this.call("readyToFetch");
        }
        this.ready = true;
      }

      return {};
    } catch (err) {
      return { error: true };
    }
  }
  constructor(
    public serverDomain: string,
    operations: TOperations,
    logLevel?: LogLevel
  ) {
    super(operations);
    this.secureFetchLogger = new Logger(
      "secure-fetch",
      "#8815EE",
      logLevel ?? "trace"
    );
    this.deviceId = this.getDeviceTokenFromLS();
    this.secureFetchLogger.debug(this.deviceId, ["constructor", "deviceId"]);
    this.crypto = new CryptoLib();
    void this.getQueryToken();
  }
  protected getDeviceTokenFromEnv(): string {
    const deviceId = process.env.DEVICE_TOKEN;
    if (!deviceId) {
      throw new Error("DEVICE_TOKEN must ve provided");
    }
    return deviceId;
  }
  protected getDeviceTokenFromLS(): string {
    let deviceId = localStorage.getItem("deviceId");
    if (!deviceId) {
      deviceId = randomString(40);
      localStorage.setItem("deviceId", deviceId);
    }
    return deviceId;
  }
  queryTokenValue() {
    return this.queryToken;
  }
  async fetch(
    path: string,
    body: any,
    method = "POST",
    extraArgs: Record<string, any> = {}
  ) {
    if (this.queryToken && extraArgs.cookies) {
      extraArgs.cookies.queryToken = this.queryToken;
    }

    if (!this.crypto.hasSecret("server")) {
      await this.getQueryToken();
    }
    const [ciphertext, iv] = await this.crypto.encrypt(
      JSON.stringify(body),
      "server"
    );

    if (!extraArgs.headers) extraArgs.headers = {};
    let cookie = `deviceId=${this.deviceId};`;

    if (this.queryToken) {
      cookie += `queryToken=${this.queryToken}`;
    }
    if (this.accessToken) {
      if (this.queryToken !== "") {
        cookie += "; ";
      }
      cookie += `accessToken=${this.accessToken}`;
    }
    if (extraArgs.headers?.Cookie) {
      extraArgs.headers.Cookie += `; ${cookie}`;
    } else {
      extraArgs.headers.Cookie = cookie;
    }

    const { headers, ...eArgs } = extraArgs;

    const args: RequestInit = {
      method,
      mode: "cors",
      credentials: "include",
      referrerPolicy: "same-origin",
      headers: {
        ...headers,
        "Content-Type": "application/octet-stream",
      },
      body: new Blob([iv, ciphertext], {
        type: "application/octet-stream",
      }),
      ...eArgs,
    };
    this.secureFetchLogger.debug(args, ["fetch", path, "args"]);

    const response = await fetch(new Request(path, args));
    this.checkStatus(response, path);
    this.checkCookies(response, path);
    const buffer = await response.arrayBuffer();
    const res = await this.getPayload(buffer);
    this.secureFetchLogger.debug({ response: res, path }, "fetch");
    return res;
  }

  async refresh(refreshToken: string) {
    this.secureFetchLogger.debug(refreshToken, ["refresh"]);
    const res = await this.fetch(`${this.serverDomain}/refreshToken`, {
      refreshToken,
    });
    return this.saveTokens(res);
  }
  async getAccessToken(userName: string, password: string) {
    this.secureFetchLogger.debug(userName, ["getAccessToken"]);

    const res = await this.fetch(`${this.serverDomain}/getAccessToken`, {
      userName,
      password,
    });
    return this.saveTokens(res);
  }
}
