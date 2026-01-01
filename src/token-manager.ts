import type { TokenData } from "./types";

export class TokenManager {
  private accessToken?: string;
  private refreshToken?: string;
  private expiryDate?: string;
  private queryToken?: string;
  private deviceToken: string;

  constructor(deviceToken: string) {
    this.deviceToken = deviceToken;
  }

  getAccessToken(): string | undefined {
    return this.accessToken;
  }

  getRefreshToken(): string | undefined {
    return this.refreshToken;
  }

  getQueryToken(): string | undefined {
    return this.queryToken;
  }

  getDeviceToken(): string {
    return this.deviceToken;
  }

  getExpiryDate(): string | undefined {
    return this.expiryDate;
  }

  setTokens(data: Partial<TokenData>): void {
    if (data.accessToken) this.accessToken = data.accessToken;
    if (data.refreshToken) this.refreshToken = data.refreshToken;
    if (data.expiryDate) this.expiryDate = data.expiryDate;
    if (data.queryToken) this.queryToken = data.queryToken;
  }

  clearTokens(): void {
    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.expiryDate = undefined;
    this.queryToken = undefined;
  }

  hasAccessToken(): boolean {
    return !!this.accessToken;
  }

  hasQueryToken(): boolean {
    return !!this.queryToken;
  }

  isAccessTokenExpired(): boolean {
    if (!this.expiryDate) return true;
    // Add 5 minute safety margin
    const expiryTime = new Date(this.expiryDate).getTime();
    const currentTime = Date.now();
    const fiveMinutes = 5 * 60 * 1000;
    return expiryTime - currentTime <= fiveMinutes;
  }
}
