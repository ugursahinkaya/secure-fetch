import { CryptoLib } from "@ugursahinkaya/crypto-lib";
import { GenericRouter } from "@ugursahinkaya/generic-router";
import { Logger } from "@ugursahinkaya/logger";
import { randomString } from "@ugursahinkaya/utils";

import type {
  SecureFetchApiOperations,
  LogLevel,
} from "@ugursahinkaya/shared-types";

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
  protected deviceToken: string;
  protected secureFetchLogger: Logger;
  protected serverDomain: string;
  protected initPromises: Promise<void>[] = [];
  protected onFetchError?: (error: any) => void;
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
    await Promise.all(this.initPromises);
    this.secureFetchLogger.debug("", "getQueryToken");
    if (!this.deviceToken) {
      throw new Error("deviceToken must be provided");
    }
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
        Cookie: `deviceToken=${this.deviceToken};queryToken=${this.queryToken}`,
      },
      body: JSON.stringify({ clientPublicKey, deviceToken: this.deviceToken }),
    };



    try {
      const response = await fetch(new Request(path, args));
      this.checkCookies(response, "getQueryToken");
      const data = await response.json();
      this.secureFetchLogger.debug(data, ["getQueryToken", "response"]);

      try {
        const publicKey = this.crypto.base64ToArrayBuffer(
          data.serverPublicKey as string
        );
        const secret = await this.crypto.importPublicKey(
          publicKey as BufferSource,
          "server"
        );
        this.secureFetchLogger.debug(
          "secret imported for server",
          "getQueryToken"
        );
        this.secureFetchLogger.debug({ process: data.process }, "getQueryToken");
        this.crypto.keyMap.set("serverSCR", secret);

        if (data.process === "refreshToken") {
          const savedRefreshToken = await this.call("getRefreshToken");
          const refreshToken = savedRefreshToken ?? this.refreshToken;
          if (!refreshToken) {
            throw new Error("refreshToken must be provided");
          }
          return this.refresh(refreshToken);
        }
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
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", "getAccessToken"]);
      if (this.onFetchError) {
        this.onFetchError(error);
        return {};
      }
      throw new Error(error);
    }



  }
  constructor({
    serverDomain,
    operations,
    logLevel,
    onReady,
    onFetchError,
  }: {
    serverDomain: string;
    operations: TOperations;
    logLevel?: LogLevel;
    onReady?: () => void;
    onFetchError?: (error: any) => void;
  }) {
    super(operations);
    this.serverDomain = serverDomain;
    this.onFetchError = onFetchError;
    this.secureFetchLogger = new Logger(
      "secure-fetch",
      "#8815EE",
      logLevel ?? "trace"
    );
    this.deviceToken = this.getDeviceTokenFromLS();
    this.secureFetchLogger.debug(this.deviceToken, [
      "constructor",
      "deviceToken",
    ]);
    this.crypto = new CryptoLib();
    this.initPromises.push(
      new Promise<void>((resolve) => {
        void this.getQueryToken().then(() => {
          if (onReady) {
            onReady();
          }
          resolve();
        });
      })
    );
  }
  protected getDeviceTokenFromEnv(): string {
    const deviceToken = process.env.DEVICE_TOKEN;
    if (!deviceToken) {
      throw new Error("DEVICE_TOKEN must ve provided");
    }
    return deviceToken;
  }
  protected getDeviceTokenFromLS(): string {
    let deviceToken = localStorage.getItem("deviceToken");
    if (!deviceToken) {
      deviceToken = randomString(40);
      localStorage.setItem("deviceToken", deviceToken);
    }
    return deviceToken;
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
    await Promise.all(this.initPromises);
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
    let cookie = "";
    if (!extraArgs.headers) extraArgs.headers = {};
    cookie = `deviceToken=${this.deviceToken};`;

    if (this.queryToken) {
      cookie += `queryToken=${this.queryToken};`;
    }
    if (this.accessToken) {
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
    try {
      const response = await fetch(new Request(path, args))
      this.checkCookies(response, path);
      const buffer = await response.arrayBuffer();
      const res = await this.getPayload(buffer);
      this.secureFetchLogger.debug({ response: res, path }, "fetch");
      if (response.status === 202 || response.status === 403) {
        await this.getQueryToken();
      }
      return res;
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", path]);
      if (this.onFetchError) {
        this.onFetchError(error);
        return {};
      }
      throw new Error(error);
    }
  }

  async refresh(refreshToken: string) {
    this.secureFetchLogger.debug(refreshToken, ["refresh"]);
    try {
      const res = await this.fetch(`${this.serverDomain}/refreshToken`, {
        refreshToken,
      });
      return this.saveTokens(res);
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", "refresh"]);
      if (this.onFetchError) {
        this.onFetchError(error);
        return {};
      }
      throw new Error(error);
    }
  }
  async getAccessToken(userName: string, password: string) {
    this.secureFetchLogger.debug(userName, ["getAccessToken"]);

    try {
      const res = await this.fetch(`${this.serverDomain}/getAccessToken`, {
        userName,
        password,
      });
      return this.saveTokens(res);
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", "getAccessToken"]);
      if (this.onFetchError) {
        this.onFetchError(error);
        return {};
      }
      throw new Error(error);
    }
  }
}
