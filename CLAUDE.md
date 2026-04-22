# zwolk-main

Static landing page at `zwolk.com`. Links out to the other zwolk apps.

## Site-wide password gate

Every request to any zwolk app passes through a Vercel Edge Middleware
(`middleware.js` at the repo root) before reaching the page or `/api/*`.
The middleware checks a cookie named `zwolk_auth`. Without a valid cookie
it serves an inline login page; with one it falls through.

A successful login sets the cookie with `Domain=.zwolk.com` so it is
shared across every subdomain (countdowns, wage, etc.). The same
`middleware.js` lives in every zwolk repo.

- Password is stored as a SHA-256 hash at the top of `middleware.js`.
- "Remember me" = 1 year; unchecked = 24-hour session cookie.
- Change the password: run `echo -n "<new>" | shasum -a 256` and paste
  the result into `PASSWORD_HASH` in **every** repo's `middleware.js`.
- Log out: visit `/__zwolk_logout` on any subdomain.

## When creating a new zwolk app

1. Copy `middleware.js` from any existing zwolk repo into the new repo
   root. Keep it unchanged — the hash and cookie logic are identical.
2. If the app needs persistent storage, copy the Supabase pattern from
   `zwolk-countdown` (`api/countdowns.js` + `app_state` table).
3. Deploy on Vercel and point a subdomain at it in your DNS.
