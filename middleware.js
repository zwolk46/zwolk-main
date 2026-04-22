// Vercel Edge Middleware — site-wide password gate for zwolk.com.
// Serves an inline login page for any request that lacks a valid cookie.
// On success, sets `zwolk_auth=ok` cookie scoped to .zwolk.com so every
// subdomain is unlocked from a single login.
//
// To change the password: run `echo -n "<new password>" | shasum -a 256`
// and paste the result into PASSWORD_HASH below (then commit + push).

export const config = { matcher: "/(.*)" };

const PASSWORD_HASH = "a8d3e59cbce261b29855dcd76f61995bb600572c1d37534d222c8337a7d79671";
const COOKIE_NAME = "zwolk_auth";
const COOKIE_VALUE = "ok";
const LOGIN_PATH = "/__zwolk_login";
const LOGOUT_PATH = "/__zwolk_logout";
const REMEMBER_MAX_AGE = 60 * 60 * 24 * 365;
const SESSION_MAX_AGE = 60 * 60 * 24;

async function sha256Hex(s) {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function isAuthed(request) {
  const cookie = request.headers.get("cookie") || "";
  return cookie.split(";").some(c => c.trim() === `${COOKIE_NAME}=${COOKIE_VALUE}`);
}

function buildCookie(value, maxAge, hostname) {
  const onZwolk = hostname === "zwolk.com" || hostname.endsWith(".zwolk.com");
  const domain = onZwolk ? "; Domain=.zwolk.com" : "";
  return `${COOKIE_NAME}=${value}; Path=/${domain}; Max-Age=${maxAge}; Secure; SameSite=Lax`;
}

function loginPage(error = "") {
  const errBlock = error
    ? `<div class="err">${error}</div>`
    : `<div class="err" aria-hidden="true"></div>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<meta name="robots" content="noindex" />
<title>zwolk</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  body{background:radial-gradient(ellipse at center,#1a1d24 0%,#0b0d11 100%);color:#f5f7fa;display:flex;align-items:center;justify-content:center;padding:1.5rem;-webkit-font-smoothing:antialiased}
  .card{width:100%;max-width:360px;padding:2rem 1.75rem;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:16px;backdrop-filter:blur(16px)}
  h1{font-size:1.5rem;font-weight:600;letter-spacing:-0.02em;margin-bottom:0.35rem}
  p{color:#9aa2b1;font-size:0.9rem;margin-bottom:1.5rem}
  label.key{display:block;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.12em;color:#7a828f;margin-bottom:0.4rem}
  input[type=password]{width:100%;padding:0.85rem 1rem;color:#f5f7fa;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.12);border-radius:10px;font-size:1rem;font-family:inherit;outline:none;transition:border-color .15s ease,background .15s ease}
  input[type=password]:focus{border-color:#4c8bf5;background:rgba(0,0,0,0.45)}
  .row{margin-top:1rem;display:flex;align-items:center;gap:0.55rem;font-size:0.9rem;color:#c6ccd6;cursor:pointer;user-select:none}
  input[type=checkbox]{accent-color:#4c8bf5;width:1rem;height:1rem}
  button{margin-top:1.5rem;width:100%;padding:0.9rem 1rem;border:none;border-radius:999px;background:#f5f7fa;color:#0b0d11;font-size:1rem;font-weight:600;font-family:inherit;cursor:pointer;transition:background .2s ease,transform .1s ease}
  button:hover{background:#fff}
  button:active{transform:scale(0.98)}
  .err{margin-top:1rem;color:#fca5a5;font-size:0.85rem;min-height:1em}
</style>
</head>
<body>
  <form class="card" method="POST" action="${LOGIN_PATH}">
    <h1>zwolk</h1>
    <p>Enter your password to continue.</p>
    <label class="key" for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" autofocus required />
    <label class="row">
      <input type="checkbox" name="remember" value="1" checked />
      Remember me on this device
    </label>
    <button type="submit">Sign in</button>
    ${errBlock}
  </form>
</body>
</html>`;
}

export default async function middleware(request) {
  const url = new URL(request.url);

  if (url.pathname === LOGIN_PATH && request.method === "POST") {
    const form = await request.formData();
    const password = String(form.get("password") || "");
    const remember = form.get("remember") === "1";
    const hash = await sha256Hex(password);
    if (hash === PASSWORD_HASH) {
      const maxAge = remember ? REMEMBER_MAX_AGE : SESSION_MAX_AGE;
      return new Response(null, {
        status: 303,
        headers: { Location: "/", "Set-Cookie": buildCookie(COOKIE_VALUE, maxAge, url.hostname) },
      });
    }
    return new Response(loginPage("Wrong password."), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  if (url.pathname === LOGOUT_PATH) {
    return new Response(null, {
      status: 303,
      headers: { Location: "/", "Set-Cookie": buildCookie("", 0, url.hostname) },
    });
  }

  if (isAuthed(request)) return;

  if (url.pathname.startsWith("/api/")) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }

  return new Response(loginPage(), {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}
