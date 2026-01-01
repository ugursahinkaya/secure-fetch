import { randomString } from "@ugursahinkaya/utils";

/**
 * Get device token from localStorage (browser environment)
 * Creates a new random token if none exists
 */
export function getDeviceTokenFromLS(): string {
  if (typeof window === "undefined" || typeof localStorage === "undefined") {
    throw new Error("localStorage is not available (SSR/Node.js environment)");
  }

  let deviceToken = localStorage.getItem("deviceToken");
  if (!deviceToken) {
    deviceToken = randomString(40);
    localStorage.setItem("deviceToken", deviceToken);
  }
  return deviceToken;
}

/**
 * Get device token from environment variable (Node.js environment)
 */
export function getDeviceTokenFromEnv(): string {
  const deviceToken = process.env.DEVICE_TOKEN;
  if (!deviceToken) {
    throw new Error("DEVICE_TOKEN environment variable must be provided");
  }
  return deviceToken;
}
