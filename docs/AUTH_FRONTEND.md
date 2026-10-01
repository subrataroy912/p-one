# Frontend Authentication Integration

This backend uses stateless JWT authentication stored in secure cookies. The browser sends the cookies automatically; frontend code must not read, store, or attach access or refresh tokens itself.

## Configuration

Set the frontend API base URL to the backend origin, without a trailing slash. For a Vite app, for example:

```env
VITE_API_BASE_URL=http://localhost:8080
```

The backend must allow the exact frontend origin, including scheme and port. Local defaults allow `http://localhost:3000` and `http://localhost:5173`. For another port or a deployed frontend, set the backend environment variable:

```env
APP_CORS_ALLOWED_ORIGINS=https://app.example.com
```

Do not use `*` for allowed origins: credentialed CORS requires explicit origins. For a frontend and API on different sites, configure cookies for cross-site use and HTTPS:

```env
APP_COOKIE_SECURE=true
APP_COOKIE_SAME_SITE=None
```

For local HTTP development, the backend defaults are `APP_COOKIE_SECURE=false` and `APP_COOKIE_SAME_SITE=Lax`. A same-site deployment can generally use `Lax` with secure cookies enabled.

## Cookie And CSRF Behavior

- `accessToken` and `refreshToken` are `HttpOnly`; JavaScript cannot and should not read them. The access cookie applies to `/`; the refresh cookie applies to `/v1/auth`.
- Send requests with `credentials: "include"` so the browser includes cookies and accepts `Set-Cookie` responses.
- Spring Security CSRF protection applies to state-changing requests. First call `GET /v1/auth/csrf`; the response sets an `XSRF-TOKEN` cookie and returns its token as JSON. Send that value in the `X-XSRF-TOKEN` header on every `POST`, `PUT`, `PATCH`, and `DELETE` request.
- The CSRF cookie is intentionally readable by JavaScript. Keep the returned token in memory if convenient; fetch it again after a page reload. Never put auth tokens in local storage or session storage.

## Minimal Fetch Client

This plain JavaScript helper works in browser applications, including React. Adapt the API base URL expression if your frontend does not use Vite.

```js
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";
let csrfToken;

async function loadCsrfToken() {
  const response = await fetch(`${API_BASE_URL}/v1/auth/csrf`, {
    credentials: "include",
  });
  if (!response.ok) throw new Error(`CSRF bootstrap failed (${response.status})`);

  const body = await response.json();
  csrfToken = body.token;
  return csrfToken;
}

async function apiFetch(path, options = {}) {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);

  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers.set("X-XSRF-TOKEN", csrfToken ?? await loadCsrfToken());
  }

  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    method,
    headers,
    credentials: "include",
  });
}

async function postJson(path, body) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
```

Bootstrap CSRF state once when the frontend starts (or just before the first state-changing request):

```js
await loadCsrfToken();
```

## Auth Requests

Register a user. Registration also signs the user in by setting auth cookies:

```js
const response = await postJson("/v1/auth/register", {
  email: "user@example.com",
  password: "StrongPassword123",
  firstName: "Sam",
  lastName: "Lee",
});
if (!response.ok) throw new Error(`Registration failed (${response.status})`);
const result = await response.json();
```

Login:

```js
const response = await postJson("/v1/auth/login", {
  email: "user@example.com",
  password: "StrongPassword123",
});
if (!response.ok) throw new Error(`Login failed (${response.status})`);
const result = await response.json();
```

Both return a JSON object shaped like this; tokens are set only as cookies, not returned in the response:

```json
{
  "userId": "2b038217-d6b1-4cb8-9453-3ef98bd21042",
  "email": "user@example.com",
  "user": {
    "id": "2b038217-d6b1-4cb8-9453-3ef98bd21042",
    "email": "user@example.com",
    "firstName": "Sam",
    "lastName": "Lee",
    "role": "USER",
    "createdAt": "2026-10-01T12:00:00Z"
  }
}
```

## Session Lifecycle

Fetch the signed-in user; the access cookie authenticates this request:

```js
const response = await apiFetch("/v1/users/me");
if (response.status === 401) {
  // No valid access session. Attempt refresh, or show the signed-out state.
}
const user = response.ok ? await response.json() : null;
```

The default access-token lifetime is 15 minutes and the refresh-token lifetime is 7 days. When a protected request returns `401`, call refresh once, then retry the original request if refresh succeeds. The refresh cookie is sent automatically; no request body is needed:

```js
const refreshed = await apiFetch("/v1/auth/refresh", { method: "POST" });
if (refreshed.ok) {
  // Retry the original protected request. The response rotates both auth cookies.
} else {
  // Refresh failed (usually 401); clear frontend user state and show login.
}
```

Log out with a CSRF-protected request. The backend revokes the current refresh token and clears both auth cookies:

```js
const response = await apiFetch("/v1/auth/logout", { method: "POST" });
if (response.status === 204) {
  // Clear frontend user state.
}
```

Refresh tokens rotate on successful refresh. Reuse of a rotated refresh cookie is rejected, so always let the browser accept the newest `Set-Cookie` response and do not cache refresh tokens in frontend code.

## Available User Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/auth/csrf` | Get a CSRF token and set the CSRF cookie |
| `POST` | `/v1/auth/register` | Register and sign in; expects `email`, `password`, optional `firstName`, `lastName` |
| `POST` | `/v1/auth/login` | Sign in; expects `email`, `password` |
| `POST` | `/v1/auth/refresh` | Refresh and rotate auth cookies; no body |
| `POST` | `/v1/auth/logout` | Revoke refresh token and clear auth cookies; no body |
| `GET` | `/v1/users/me` | Get the current user; requires a valid access cookie |
| `PATCH` | `/v1/users/me` | Update `firstName` and/or `lastName`; requires auth cookie and CSRF header |

## Common Responses

- `400 Bad Request`: request validation failed, such as an invalid email or a password shorter than 8 characters during registration.
- `401 Unauthorized`: invalid login credentials, invalid/expired refresh token, or missing/expired access authentication for a protected route.
- `403 Forbidden`: missing or invalid CSRF token on a state-changing request. Bootstrap again with `GET /v1/auth/csrf` and retry once if appropriate.
- `409 Conflict`: registration email is already in use.
- `201 Created`: registration succeeded; `200 OK`: login, refresh, or user read/update succeeded; `204 No Content`: logout succeeded.

## Integration Checklist

- Frontend origin is listed exactly in `APP_CORS_ALLOWED_ORIGINS`.
- Every browser API request uses `credentials: "include"`.
- The frontend bootstraps CSRF and attaches `X-XSRF-TOKEN` to state-changing requests.
- Auth cookies are never read by JavaScript or copied into browser storage.
- The deployed API uses HTTPS with `APP_COOKIE_SECURE=true`; cross-site frontend/API deployments also use `APP_COOKIE_SAME_SITE=None`.
- On an authenticated request returning `401`, refresh at most once and then retry; otherwise return the user to the signed-out flow.