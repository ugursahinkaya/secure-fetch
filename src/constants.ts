export const ErrorMessages = {
  NO_DEVICE_TOKEN: "deviceToken must be provided",
  NO_REFRESH_TOKEN: "refreshToken must be provided",
  NO_ACCESS_TOKEN: "accessToken and refreshToken not found",
  INVALID_RESPONSE: "Invalid server response",
  FETCH_FAILED: "Network request failed",
} as const;

export const ApiEndpoints = {
  GET_QUERY_TOKEN: "/getQueryToken",
  REFRESH_TOKEN: "/refreshToken",
  GET_ACCESS_TOKEN: "/getAccessToken",
} as const;

export const ProcessTypes = {
  REFRESH_TOKEN: "refreshToken",
  WELCOME: "welcome",
  READY: "readyToFetch",
} as const;
