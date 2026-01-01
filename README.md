# @ugursahinkaya/secure-fetch

> End-to-end encrypted HTTP client with automatic token management

[![npm version](https://img.shields.io/npm/v/@ugursahinkaya/secure-fetch.svg)](https://www.npmjs.com/package/@ugursahinkaya/secure-fetch)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

**Production-grade E2E encrypted fetch client** with automatic key exchange, token lifecycle management, and type-safe operations.

---

## ✨ Features

- 🔒 **E2E Encryption**: All requests/responses encrypted with Diffie-Hellman key exchange
- 🎯 **Type-safe**: Full TypeScript support with operation contracts
- 🔄 **Auto Token Management**: Handles access, refresh, query tokens automatically
- 🍪 **Cookie Handling**: Automatic cookie parsing and management
- 🎭 **Modular Architecture**: Clean separation of concerns (crypto, tokens, cookies)
- 🛡️ **SSR-safe**: Built-in guards for server-side rendering
- 📊 **Logger Integration**: Comprehensive logging with @ugursahinkaya/logger
- ⚡ **Generic Router**: Extends GenericRouter for operation-based architecture

---

## 📦 Installation

```bash
npm install @ugursahinkaya/secure-fetch
# or
pnpm add @ugursahinkaya/secure-fetch
# or
yarn add @ugursahinkaya/secure-fetch
```

---

## 🚀 Quick Start

```typescript
import { SecureFetch } from '@ugursahinkaya/secure-fetch';

// Define your API operations
type ApiOperations = {
  getUser: (userId: string) => Promise<{ id: string; name: string }>;
  updateProfile: (data: { name: string; email: string }) => Promise<{ success: boolean }>;
  deleteAccount: () => Promise<void>;
};

const client = new SecureFetch<ApiOperations>({
  serverDomain: 'https://api.example.com',
  operations: {
    getUser: async (userId) => ({ id: userId, name: 'John' }),
    updateProfile: async (data) => ({ success: true }),
    deleteAccount: async () => {},
  },
  logLevel: 'debug',
  onReady: () => {
    console.log('Client ready - encryption established');
  },
  onFetchError: (error) => {
    console.error('Fetch error:', error);
  },
});

// Type-safe API calls
const user = await client.call('getUser', '123');
const result = await client.call('updateProfile', { name: 'Alice', email: 'alice@example.com' });
```

---

## 📖 API Reference

### Constructor Options

```typescript
interface SecureFetchConfig<TOperations> {
  serverDomain: string;           // API base URL
  operations: TOperations;         // Operation definitions
  appToken?: string;               // Optional Bearer token
  logLevel?: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  onReady?: () => void;            // Called when encryption is established
  onFetchError?: (error: any) => void; // Global error handler
}
```

### Methods

#### `fetch(path, body, method?, options?)`

Primary encrypted fetch method.

```typescript
const response = await client.fetch('/api/users', 
  { name: 'Alice' }, 
  'POST',
  { 
    credentials: 'include',
    cookies: { customCookie: 'value' }
  }
);
```

#### `getAccessToken(userName, password)`

Login with credentials.

```typescript
const tokens = await client.getAccessToken('alice', 'password123');
// Returns: { queryToken: string, refreshToken: string }
```

#### `refresh(refreshToken)`

Refresh access token.

```typescript
await client.refresh(storedRefreshToken);
```

#### `queryTokenValue()`

Get current query token.

```typescript
const token = client.queryTokenValue();
```

#### `call(operation, payload?)`

Type-safe operation call (inherited from GenericRouter).

```typescript
// Autocomplete and type checking
const user = await client.call('getUser', '123');
```

---

## 🔧 Advanced Usage

### React Integration

```typescript
import { useEffect, useState } from 'react';
import { SecureFetch } from '@ugursahinkaya/secure-fetch';

function useSecureFetch() {
  const [client, setClient] = useState<SecureFetch<ApiOperations>>();

  useEffect(() => {
    const secureFetch = new SecureFetch<ApiOperations>({
      serverDomain: process.env.REACT_APP_API_URL!,
      operations: apiOperations,
      onReady: () => console.log('Ready'),
    });

    setClient(secureFetch);
  }, []);

  return client;
}

function App() {
  const client = useSecureFetch();

  const handleLogin = async () => {
    if (!client) return;
    await client.getAccessToken('username', 'password');
  };

  return <button onClick={handleLogin}>Login</button>;
}
```

### Custom Error Handling

```typescript
const client = new SecureFetch({
  serverDomain: 'https://api.example.com',
  operations: apiOps,
  onFetchError: (error) => {
    // Log to Sentry, show toast, etc.
    if (error.message.includes('401')) {
      // Handle unauthorized
      window.location.href = '/login';
    }
  },
});
```

### Token Persistence

```typescript
// Save refresh token
const operations = {
  saveRefreshToken: async (token: string) => {
    localStorage.setItem('refreshToken', token);
  },
  getRefreshToken: async () => {
    return localStorage.getItem('refreshToken');
  },
  loggedIn: async (queryToken: string) => {
    console.log('Logged in with queryToken:', queryToken);
  },
  welcome: async (data: any) => {
    console.log('Welcome back:', data);
  },
  readyToFetch: async () => {
    console.log('Ready to make API calls');
  },
};

const client = new SecureFetch({
  serverDomain: 'https://api.example.com',
  operations,
});
```

---

## 🏗️ Architecture

### Modular Structure

```
secure-fetch/
├── types.ts              # TypeScript interfaces
├── constants.ts          # Error messages, endpoints, process types
├── crypto-manager.ts     # Encryption/decryption logic
├── token-manager.ts      # Token lifecycle management
├── cookie-manager.ts     # Cookie parsing and building
├── device-utils.ts       # Device token utilities
├── secure-fetch.ts       # Main class
└── index.ts              # Public exports
```

### Request Flow

1. **Initialization**: Generate client keys, exchange with server
2. **Authentication**: Login with credentials or refresh token
3. **Encrypted Request**: 
   - Encrypt payload with shared secret
   - Attach tokens via cookies
   - Send as `application/octet-stream`
4. **Encrypted Response**: 
   - Decrypt response buffer
   - Parse JSON payload
   - Update tokens if refreshed

---

## 🛠️ Server-Side Requirements

Your server must implement:

### 1. Key Exchange Endpoint

```http
POST /getQueryToken
Content-Type: application/json

{
  "clientPublicKey": "base64-encoded-public-key",
  "deviceToken": "unique-device-id"
}
```

**Response:**
```json
{
  "serverPublicKey": "base64-encoded-public-key",
  "process": "welcome" | "refreshToken" | "readyToFetch",
  "queryToken": "optional-query-token"
}
```

### 2. Authentication Endpoint

```http
POST /getAccessToken
Content-Type: application/octet-stream
Cookie: deviceToken=xxx; queryToken=yyy

[Encrypted payload: { userName, password }]
```

**Response:** Encrypted JSON
```json
{
  "accessToken": "jwt-token",
  "refreshToken": "refresh-token",
  "expiryDate": "2024-12-31T23:59:59Z",
  "queryToken": "query-token"
}
```

### 3. Refresh Token Endpoint

```http
POST /refreshToken
Content-Type: application/octet-stream
Cookie: deviceToken=xxx; queryToken=yyy

[Encrypted payload: { refreshToken }]
```

---

## 🐛 Troubleshooting

### localStorage Not Available (SSR)

**Problem**: `localStorage is not available (SSR/Node.js environment)`

**Solution**: Wrap initialization in client-side check:

```typescript
// Next.js
if (typeof window !== 'undefined') {
  const client = new SecureFetch({ ... });
}

// Or use dynamic import
const client = await import('./client').then(m => m.initClient());
```

### Encryption Key Mismatch

**Problem**: Requests fail after page reload

**Solution**: Call `getQueryToken()` to re-establish encryption:

```typescript
// Client auto-calls getQueryToken on init
// Manual re-init:
await client.fetch('/api/endpoint', {}, 'POST');
// Will auto-refresh keys if expired
```

### Token Expiry Handling

**Problem**: Access token expires during session

**Solution**: Server should return `202` or `403` status:

```typescript
// Client automatically detects and refreshes
if (response.status === 202 || response.status === 403) {
  await this.getQueryToken();
}
```

---

## 📊 Performance

- **Bundle size**: ~15KB minified (excluding dependencies)
- **Encryption**: Diffie-Hellman + AES-GCM via WebCrypto API
- **Token storage**: localStorage for device token, memory for session tokens
- **Auto-retry**: Transparent token refresh on expiry

---

## 🔒 Security Considerations

- **Device Token**: Unique 40-character random string stored in localStorage
- **Transport**: All sensitive data encrypted before transmission
- **Cookies**: Used for auth tokens (httpOnly recommended on server)
- **CORS**: Requires proper CORS headers from server
- **Key Exchange**: Happens on every session (no key persistence)

---

## License

### Commercial License

If you intend to use this software for a commercial project or commercial purposes, you need to obtain a commercial license.

The commercial license covers the commercial use, integration, and distribution of the software. It grants the user the right to use the software in commercial projects and includes additional support and services.

For more information on commercial license fees and conditions, please contact us at: [ugur@sahinkaya.xyz](mailto:ugur@sahinkaya.xyz)

### Open Source License

This software is available for free under the GNU General Public License version 3 (GPLv3).

This license allows the software to be used, modified, and distributed under open source terms. However, when using the software under the GPLv3 license, any project that uses the software must also be distributed under the same license terms.

You can access the full text of the GPLv3 license [here](LICENSE-GPL.txt).
