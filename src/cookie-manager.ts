export class CookieManager {
  private cookies: Record<string, string> = {};

  parseCookies(response: Response): void {
    const cookieHeader = response.headers.get("set-cookie");
    if (!cookieHeader) return;

    const cookieList = cookieHeader.split(",");
    cookieList.forEach((keyValue) => {
      const parts = keyValue.split("=");
      if (parts.length < 2) return;
      
      const key = parts[0]?.split(";")[0]?.trim();
      const value = parts.slice(1).join("=").split(";")[0]?.trim();
      
      if (key && value) {
        this.cookies[key] = value;
      }
    });
  }

  getCookie(key: string): string | undefined {
    return this.cookies[key];
  }

  setCookie(key: string, value: string): void {
    this.cookies[key] = value;
  }

  buildCookieHeader(additionalCookies: Record<string, string> = {}): string {
    const allCookies = { ...this.cookies, ...additionalCookies };
    return Object.entries(allCookies)
      .map(([key, value]) => `${key}=${value}`)
      .join("; ");
  }

  clear(): void {
    this.cookies = {};
  }
}
