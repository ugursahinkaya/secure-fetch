import type { SecureFetchApiOperations } from "@ugursahinkaya/shared-types";

export type { SecureFetchApiOperations };

export interface TokenData {
  accessToken: string;
  refreshToken: string;
  expiryDate: string;
  queryToken: string;
}

export interface SecureFetchConfig<TOperations extends SecureFetchApiOperations> {
  serverDomain: string;
  operations: TOperations;
  appToken?: string;
  logLevel?: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
  onReady?: () => void;
  onFetchError?: (error: any) => void;
}

export interface FetchOptions extends Omit<RequestInit, "body" | "method"> {
  cookies?: Record<string, string>;
}
