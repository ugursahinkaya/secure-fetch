import { GenericRouter } from "@ugursahinkaya/generic-router";
import { Logger } from "@ugursahinkaya/logger";
import { randomString } from "@ugursahinkaya/utils";

import type { SecureFetchApiOperations } from "@ugursahinkaya/shared-types";
import type { SecureFetchConfig, TokenData, FetchOptions } from "./types";

import { CryptoManager } from "./crypto-manager";
import { TokenManager } from "./token-manager";
import { CookieManager } from "./cookie-manager";
import { ApiEndpoints, ProcessTypes } from "./constants";

export class SecureFetch<
  TOperations extends SecureFetchApiOperations,
> extends GenericRouter<TOperations> {
  private cryptoManager: CryptoManager;
  private tokenManager: TokenManager;
  private cookieManager: CookieManager;
  private secureFetchLogger: Logger;
  private serverDomain: string;
  private appToken?: string;
  private initPromise: Promise<void> | null = null;
  private refreshPromise: Promise<void> | null = null;
  private onFetchError?: (error: any) => void;
  private queryTokenRetryCount = 0;
  private readonly MAX_QUERY_TOKEN_RETRIES = 3;

  constructor(config: SecureFetchConfig<TOperations>) {
    super(config.operations);

    this.serverDomain = config.serverDomain;
    this.appToken = config.appToken;
    this.onFetchError = config.onFetchError;

    this.secureFetchLogger = new Logger(
      "secure-fetch",
      "#8815EE",
      config.logLevel ?? "error"
    );

    const deviceToken = getDeviceToken();
    this.secureFetchLogger.debug(deviceToken, ["constructor", "deviceToken"]);

    this.tokenManager = new TokenManager(deviceToken);
    this.cookieManager = new CookieManager();
    this.cryptoManager = new CryptoManager(this.secureFetchLogger);

    this.initPromise = this.getQueryToken().then(() => {
      if (config.onReady) {
        config.onReady();
      }
    });
  }

  /**
   * Get current query token value
   */
  queryTokenValue(): string | undefined {
    return this.tokenManager.getQueryToken();
  }

  /**
   * Primary encrypted fetch method
   */
  async fetch(
    path: string,
    body: any,
    method = "POST",
    options: FetchOptions = {}
  ): Promise<any> {
    // Check if access token expired
    if (this.tokenManager.isAccessTokenExpired()) {
      const refreshToken = this.tokenManager.getRefreshToken();
      if (refreshToken) {
        // Prevent multiple simultaneous refresh calls
        if (!this.refreshPromise) {
          this.refreshPromise = this.refresh(refreshToken).finally(() => {
            this.refreshPromise = null;
          });
        }
        await this.refreshPromise;
      }
    }

    if (!this.cryptoManager.hasSecret("server")) {
      await this.getQueryToken();
    }

    // Add timestamp for replay protection
    const bodyWithTimestamp = { ...body, _ts: Date.now() };
    const [ciphertext, iv] = await this.cryptoManager.encrypt(JSON.stringify(bodyWithTimestamp));

    const cookieData: Record<string, string> = {
      deviceToken: this.tokenManager.getDeviceToken(),
    };

    const queryToken = this.tokenManager.getQueryToken();
    if (queryToken) {
      cookieData.queryToken = queryToken;
    }

    const accessToken = this.tokenManager.getAccessToken();
    if (accessToken) {
      cookieData.accessToken = accessToken;
    }

    const cookieHeader = this.cookieManager.buildCookieHeader(cookieData);

    const { headers = {}, ...restOptions } = options;
    const existingCookie = (headers as Record<string, string>).Cookie;
    const finalCookie = existingCookie ? `${existingCookie}; ${cookieHeader}` : cookieHeader;

    const mergedHeaders: HeadersInit = {
      ...headers,
      "Content-Type": "application/octet-stream",
      Cookie: finalCookie,
    };

    const args: RequestInit = {
      method,
      mode: "cors",
      credentials: "include",
      referrerPolicy: "same-origin",
      headers: mergedHeaders,
      body: new Blob([new Uint8Array(iv), new Uint8Array(ciphertext)], {
        type: "application/octet-stream",
      }),
      ...restOptions,
    };

    this.secureFetchLogger.debug(args, ["fetch", path, "args"]);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

    try {
      const response = await fetch(new Request(path, { ...args, signal: controller.signal }));
      clearTimeout(timeoutId);
      this.cookieManager.parseCookies(response);

      // Validate response
      if (!response.ok && response.status !== 202 && response.status !== 403) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const buffer = await response.arrayBuffer();
      if (buffer.byteLength === 0) {
        throw new Error("Empty response from server");
      }

      const result = await this.cryptoManager.decrypt(buffer);

      this.secureFetchLogger.debug({ response: result, path }, "fetch");

      if (response.status === 202 || response.status === 403) {
        await this.getQueryToken();
      }

      return result;
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", path]);
      const sanitizedError = new Error("Fetch operation failed");
      if (this.onFetchError) {
        this.onFetchError(sanitizedError);
        return {};
      }
      throw sanitizedError;
    }
  }

  /**
   * Login with username and password
   */
  async getAccessToken(userName: string, password: string): Promise<any> {
    this.secureFetchLogger.debug(userName, ["getAccessToken"]);

    try {
      const res = await this.fetch(
        `${this.serverDomain}${ApiEndpoints.GET_ACCESS_TOKEN}`,
        { userName, password }
      );
      return this.saveTokens(res);
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", "getAccessToken"]);
      const sanitizedError = new Error("Authentication failed");
      if (this.onFetchError) {
        this.onFetchError(sanitizedError);
        return {};
      }
      throw sanitizedError;
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refresh(refreshToken: string): Promise<void> {
    this.secureFetchLogger.debug(refreshToken, ["refresh"]);

    try {
      const res = await this.fetch(
        `${this.serverDomain}${ApiEndpoints.REFRESH_TOKEN}`,
        { refreshToken }
      );
      this.saveTokens(res);
      void this.call("welcome", res);
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", "refresh"]);
      const sanitizedError = new Error("Token refresh failed");
      if (this.onFetchError) {
        this.onFetchError(sanitizedError);
        return;
      }
      throw sanitizedError;
    }
  }

  /**
   * Initialize encryption and get query token
   */
  private async getQueryToken(): Promise<void> {
    if (this.initPromise) {
      await this.initPromise;
      return;
    }

    this.secureFetchLogger.debug("", "getQueryToken");

    const clientPublicKey = await this.cryptoManager.generateServerKey();
    const path = this.serverDomain + ApiEndpoints.GET_QUERY_TOKEN;

    const deviceToken = this.tokenManager.getDeviceToken();
    const queryToken = this.tokenManager.getQueryToken();

    const cookieParts = [`deviceToken=${deviceToken}`];
    if (queryToken) {
      cookieParts.push(`queryToken=${queryToken}`);
    }

    const args: RequestInit = {
      method: "POST",
      mode: "cors",
      credentials: "include",
      referrerPolicy: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookieParts.join(";"),
      },
      body: JSON.stringify({ clientPublicKey, deviceToken }),
    };

    if (this.appToken) {
      (args.headers as Record<string, string>).Authorization = `Bearer ${this.appToken}`;
    }

    try {
      const response = await fetch(new Request(path, args));
      this.cookieManager.parseCookies(response);

      const data = await response.json();
      this.secureFetchLogger.debug(data, ["getQueryToken", "response"]);

      try {
        await this.cryptoManager.importServerPublicKey(data.serverPublicKey as string);
        this.secureFetchLogger.debug({ process: data.process }, "getQueryToken");

        if (data.process === ProcessTypes.REFRESH_TOKEN) {
          const savedRefreshToken = await this.call("getRefreshToken");
          const refreshToken = savedRefreshToken ?? this.tokenManager.getRefreshToken();

          if (!refreshToken) {
            this.queryTokenRetryCount++;
            if (this.queryTokenRetryCount >= this.MAX_QUERY_TOKEN_RETRIES) {
              throw new Error("Max retry attempts reached - no refresh token available");
            }
            return await this.getQueryToken();
          }
          this.queryTokenRetryCount = 0;
          await this.refresh(refreshToken);
          return;
        }

        if (data.process === ProcessTypes.WELCOME) {
          void this.call("welcome", data.queryToken);
          return;
        }

        void this.call("readyToFetch");
        return;
      } catch (error) {
        this.secureFetchLogger.error(error as string, ["fetch", "getQueryToken"]);
        return;
      }
    } catch (error: any) {
      this.secureFetchLogger.error(error, ["fetch", "getQueryToken"]);
      const sanitizedError = new Error("Query token initialization failed");
      if (this.onFetchError) {
        this.onFetchError(sanitizedError);
        return;
      }
      throw sanitizedError;
    }
  }

  /**
   * Save authentication tokens
   */
  private saveTokens(data: TokenData & { error?: string }): any {
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
      this.tokenManager.setTokens({ refreshToken });
    }

    if (accessToken) {
      this.tokenManager.setTokens({ accessToken, expiryDate, queryToken });
      void this.call("loggedIn", queryToken);
    }

    return { queryToken, refreshToken };
  }
}


function getDeviceToken(): string {
  if (typeof window === "undefined" || typeof localStorage === "undefined") {
    return getDeviceTokenFromEnv()
  }

  let deviceToken = localStorage.getItem("deviceToken");
  if (!deviceToken) {
    deviceToken = randomString(40);
    localStorage.setItem("deviceToken", deviceToken);
  }
  return deviceToken;
}


function getDeviceTokenFromEnv(): string {
  const deviceToken = process.env.DEVICE_TOKEN;
  if (!deviceToken) {
    throw new Error("DEVICE_TOKEN environment variable must be provided");
  }
  return deviceToken;
}