# Watchparty Server-Side Pre-Auth Investigation

## Goal

Replace the client-side MutationObserver login form auto-fill with a server-side
pre-auth approach that logs the user into watchparty before the browser ever loads
the page — mirroring how the Emby bridge handles Emby authentication.

## What Was Tried

The bridge was modified to:

1. Intercept the initial `/watchparty/` page load (before the bridge cookie is present)
2. POST `{"username": "...", "password": "..."}` to `POST /watchparty/api/auth/login`
   from within the bridge's Go HTTP client
3. Forward any resulting `Set-Cookie` headers verbatim to the browser
4. Set a short-lived bridge cookie (`_wp_bridge_authed`, 30s) to prevent the handler
   intercepting subsequent requests (replacing the old `?u=1` query param trick)
5. Serve the localStorage username page and redirect to `/watchparty/`

## What Was Discovered

### watchparty Uses Client-Side Signed Sessions (Flask Default)

watchparty uses Flask's default session mechanism: a **client-side signed cookie**
named `ewp_session`. The session data is encoded and signed into the cookie value
itself — there is no server-side session store.

Key behaviours:
- Flask creates an anonymous `ewp_session` cookie on the **first GET request** to
  any watchparty page (e.g. when the browser loads `/watchparty/`)
- When `POST /watchparty/api/auth/login` is called, Flask reads the existing
  `ewp_session` from the request, marks it as authenticated, and writes the updated
  session back via `Set-Cookie` on the response
- **If no `ewp_session` cookie is sent with the login POST, Flask creates a brand
  new session, marks it authenticated, and should return it via `Set-Cookie`**

### The Root Problem: `cookies=0`

Despite the login POST returning HTTP 200, the bridge's Go `http.Client` received
**zero `Set-Cookie` headers** in the response. The browser DevTools confirmed:
- Response headers for `POST /watchparty/api/auth/login`: no `Set-Cookie` present
- `vary: Cookie` is present, indicating Flask is aware of cookie state

The most likely cause is **`SESSION_COOKIE_SECURE=True`** in Flask's configuration.
When this is set, Flask will not issue a session cookie over a plain HTTP connection.
The bridge POSTs to `http://emby-watchparty:5000` (plain HTTP on the internal Docker
network) — Flask sees a non-HTTPS request and suppresses the `Set-Cookie` header.

The browser, by contrast, connects via HTTPS through Caddy/the reverse proxy, so
Flask issues the cookie normally for browser requests.

### Cookie flow when browser logs in manually

1. Browser loads `/watchparty/` → Flask creates anonymous `ewp_session` cookie,
   sends it as `Set-Cookie` on the HTML response (this goes through Caddy over HTTPS)
2. Browser sends `ewp_session` on all subsequent requests
3. Browser POSTs to `/watchparty/api/auth/login` with `ewp_session` in the `Cookie`
   header → Flask updates the in-memory session, writes new signed value back via
   `Set-Cookie` → browser now has an authenticated `ewp_session`
4. All subsequent requests include the authenticated `ewp_session` → Flask considers
   the user logged in

### Why Server-Side Pre-Auth Fails

The bridge does the login POST **without** the browser's existing `ewp_session`. One
of two things happens:
- Flask tries to issue a new authenticated session but `SESSION_COOKIE_SECURE=True`
  prevents it over plain HTTP → `cookies=0`
- Or Flask issues it but the cookie is then lost/irrelevant because the browser
  already has its own `ewp_session` from loading the page

## Potential Solutions

### Option A: Set `SESSION_COOKIE_SECURE=False` on watchparty

Add `SESSION_COOKIE_SECURE=false` to the watchparty container environment. This
allows Flask to issue session cookies over plain HTTP, enabling the bridge's
server-side POST to receive the authenticated session cookie.

This is safe and correct for a service that sits behind a TLS-terminating reverse
proxy (Caddy). The cookie is still sent over HTTPS to the browser.

**Effort**: Low — one env var change in `docker-compose.yml`.

### Option B: Bridge proxies the initial GET first, then POSTs with the cookie

The bridge could:
1. Make a GET to `http://emby-watchparty:5000/watchparty/` to obtain the initial
   `ewp_session` cookie
2. POST to the login endpoint with that cookie included
3. Receive the authenticated session cookie back
4. Forward it to the browser along with the bridge cookie

This avoids needing to change watchparty's configuration but adds complexity and
an extra round-trip.

**Effort**: Medium — requires stateful cookie jar management in the bridge.

### Option C: Keep the MutationObserver approach (current state)

The existing client-side form auto-fill works reliably. The bridge injects a script
that detects the login form via MutationObserver and submits it automatically. This
avoids all the session cookie complexity.

Downsides:
- Depends on the watchparty login form's DOM structure (fragile)
- Adds script injection to every HTML response via `ModifyResponse`
- Brief flash of the login form before auto-fill fires

**Effort**: Already implemented.

## Current State

The server-side pre-auth commits were reverted. The branch is back on the
MutationObserver approach (Option C).

To resume this work, start with **Option A** — it is the lowest-effort path and
the correct configuration for a reverse-proxied Flask service.
