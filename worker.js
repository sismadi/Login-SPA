// worker.js
// SPA Login GitHub di Cloudflare Worker (Authorization Code, session via KV)

const OAUTH_SCOPE = "read:user user:email";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 hari

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;

    try {
      // Halaman SPA
      if (req.method === "GET" && (path === "/" || path === "/index.html")) {
        return htmlResponse(INDEX_HTML);
      }

      // OAuth flow
      if (req.method === "GET" && path === "/auth/login") {
        return handleLogin(req, env);
      }
      if (req.method === "GET" && path === "/auth/callback") {
        return handleCallback(req, env);
      }

      // API sesi
      if (req.method === "GET" && path === "/api/me") {
        return handleMe(req, env);
      }
      if (req.method === "POST" && path === "/auth/logout") {
        return handleLogout(req, env);
      }

      // Debug cepat
      if (req.method === "GET" && path === "/__health") {
        return json({
          ok: true,
          hasKV: !!(env.SESSIONS && env.SESSIONS.put && env.SESSIONS.get),
          hasClientId: !!env.GITHUB_CLIENT_ID,
          hasClientSecret: !!env.GITHUB_CLIENT_SECRET
        });
      }

      return new Response("Not found", { status: 404 });
    } catch (e) {
      console.error("Top-level error:", e?.stack || e);
      return htmlResponse(errorPage("Worker error (lihat logs/tail untuk detail)."));
    }
  }
};

/* ==================== Handlers ==================== */

async function handleLogin(req, env) {
  // Validasi config
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return htmlResponse(errorPage(
      "Secrets belum di-set. Tambahkan <b>GITHUB_CLIENT_ID</b> dan <b>GITHUB_CLIENT_SECRET</b> di Settings → Variables → Secrets."
    ));
  }
  if (!env.SESSIONS || !env.SESSIONS.put) {
    return htmlResponse(errorPage(
      "KV binding <b>SESSIONS</b> belum dikonfigurasi. Buka Settings → Bindings → KV → Add binding bernama <b>SESSIONS</b>."
    ));
  }

  const state = randomId(24);
  await env.SESSIONS.put(`state:${state}`, "1", { expirationTtl: 600 });

  const redirectUri = `${new URL(req.url).origin}/auth/callback`;

  const authorizeUrl = new URL("https://github.com/login/oauth/authorize");
  authorizeUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", OAUTH_SCOPE);
  authorizeUrl.searchParams.set("state", state);

  return redirect(authorizeUrl.toString());
}

async function handleCallback(req, env) {
  // Validasi config
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return htmlResponse(errorPage("Secrets belum di-set (GITHUB_CLIENT_ID/SECRET)."));
  }
  if (!env.SESSIONS || !env.SESSIONS.get) {
    return htmlResponse(errorPage("KV binding 'SESSIONS' belum dikonfigurasi."));
  }

  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return htmlResponse(errorPage("Callback kurang parameter."));

  // Verifikasi state sekali pakai
  const key = `state:${state}`;
  const existed = await env.SESSIONS.get(key);
  if (!existed) return htmlResponse(errorPage("State tidak valid / kedaluwarsa."));
  await env.SESSIONS.delete(key);

  const redirectUri = `${url.origin}/auth/callback`;

  // Tukar code -> access_token
  const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Accept": "application/json" },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri
    })
  });

  if (!tokenResp.ok) {
    const txt = await safeText(tokenResp);
    console.error("Token exchange failed:", tokenResp.status, txt);
    return htmlResponse(errorPage("Gagal mengambil access token dari GitHub."));
  }

  const tokenJson = await tokenResp.json();
  const accessToken = tokenJson.access_token;
  if (!accessToken) return htmlResponse(errorPage("Access token tidak ditemukan."));

  // Simpan sesi di KV, set cookie HttpOnly
  const sid = randomId(24);
  await env.SESSIONS.put(`sid:${sid}`, accessToken, { expirationTtl: SESSION_TTL_SECONDS });

  const cookies = [
    cookieSet("sid", sid, { maxAge: SESSION_TTL_SECONDS, httpOnly: true })
  ];
  return redirect("/", cookies);
}

async function handleMe(req, env) {
  const sid = cookieGet(req, "sid");
  if (!sid) return json({ ok: false, error: "Belum login" }, 401);

  const token = await env.SESSIONS?.get?.(`sid:${sid}`);
  if (!token) return json({ ok: false, error: "Sesi kedaluwarsa" }, 401);

  // Ambil profil GitHub
  const [userRes, emailRes] = await Promise.all([
    fetch("https://api.github.com/user", {
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${token}`,
        "User-Agent": "cf-worker-gh-login"
      }
    }),
    fetch("https://api.github.com/user/emails", {
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${token}`,
        "User-Agent": "cf-worker-gh-login"
      }
    })
  ]);

  if (!userRes.ok) return json({ ok: false, error: "Gagal mengambil profil" }, 500);
  const user = await userRes.json();

  let primaryEmail = null;
  if (emailRes.ok) {
    const emails = await emailRes.json();
    const primary = emails.find(e => e.primary) || emails[0];
    primaryEmail = primary?.email || null;
  }

  return json({
    ok: true,
    user: {
      id: user.id,
      login: user.login,
      name: user.name,
      avatar_url: user.avatar_url,
      html_url: user.html_url,
      email: primaryEmail
    }
  });
}

async function handleLogout(req, env) {
  const sid = cookieGet(req, "sid");
  if (sid) {
    await env.SESSIONS?.delete?.(`sid:${sid}`);
  }
  // Set-Cookie harus header terpisah
  const headers = new Headers();
  headers.append("Set-Cookie", cookieClear("sid"));
  return new Response(null, { status: 204, headers });
}

/* ==================== Utils ==================== */

function htmlResponse(html) {
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8" }
  });
}

// Penting: Set-Cookie harus satu header per cookie (pakai .append)
function redirect(location, cookies) {
  const headers = new Headers({ location, "cache-control": "no-store" });
  if (Array.isArray(cookies)) {
    for (const c of cookies) headers.append("Set-Cookie", c);
  } else if (typeof cookies === "string" && cookies) {
    headers.append("Set-Cookie", cookies);
  }
  return new Response(null, { status: 302, headers });
}

function b64url(uint8) {
  let str = btoa(String.fromCharCode(...uint8));
  return str.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function randomId(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}

function cookieGet(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}

function cookieSet(name, value, { maxAge, httpOnly = true } = {}) {
  const attrs = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "SameSite=Lax",
    "Secure" // wajib di https
  ];
  if (httpOnly) attrs.push("HttpOnly");
  if (maxAge !== undefined) attrs.push(`Max-Age=${maxAge}`);
  return attrs.join("; ");
}

function cookieClear(name) {
  return `${name}=; Path=/; Max-Age=0; SameSite=Lax; Secure; HttpOnly`;
}

async function safeText(res) {
  try { return await res.text(); } catch { return ""; }
}

function errorPage(msg) {
  return `<!doctype html><meta charset="utf-8">
  <title>Login Error</title>
  <style>
    body{font:14px/1.5 system-ui;margin:40px;max-width:720px}
    code{background:#f2f2f2;padding:2px 6px;border-radius:6px}
  </style>
  <h1>Login Error</h1>
  <p>${msg}</p>
  <p><a href="/">Kembali</a></p>`;
}

/* ==================== Minimal SPA ==================== */

const INDEX_HTML = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login GitHub · Cloudflare Worker (SPA)</title>
  <style>
    :root {
      --bg:#0b1220; --panel:#111a2f; --text:#e7efff; --muted:#9bb0d0;
      --accent:#61dafb; --ok:#3fb950; --err:#ff6b6b; --border:#1b2b48;
    }
    *{box-sizing:border-box}
    body{margin:0; background:var(--bg); color:var(--text); font:14px/1.5 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
    .wrap{max-width:720px; margin:40px auto; padding:0 16px}
    .card{background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:18px; box-shadow:0 8px 24px rgba(0,0,0,.25)}
    h1{margin:0 0 12px; font-size:22px}
    .muted{color:var(--muted)}
    button,a.btn{display:inline-block; padding:10px 14px; border-radius:10px; border:1px solid var(--border); background:#152446; color:var(--text); text-decoration:none; cursor:pointer}
    button:hover,a.btn:hover{filter:brightness(1.1)}
    .row{display:flex; gap:12px; align-items:center}
    img.avatar{width:64px; height:64px; border-radius:50%}
    .spacer{height:12px}
    .ok{color:var(--ok)} .err{color:var(--err)}
    code{background:#0f1b2f; padding:2px 6px; border-radius:6px; border:1px solid var(--border)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Login GitHub (SPA + Cloudflare Worker)</h1>
      <p class="muted">Contoh sederhana: Worker menyimpan <em>client secret</em> & sesi; halaman ini hanya memanggil <code>/auth/login</code>, <code>/api/me</code>, dan <code>/auth/logout</code>.</p>

      <div id="status" class="muted">Memeriksa sesi…</div>
      <div class="spacer"></div>

      <div id="view-guest" style="display:none">
        <a class="btn" href="/auth/login">Masuk dengan GitHub</a>
      </div>

      <div id="view-user" style="display:none">
        <div class="row">
          <img id="avatar" class="avatar" alt="avatar"/>
          <div>
            <div><b id="name"></b> <span class="muted">(<span id="login"></span>)</span></div>
            <div><a id="profile" target="_blank" rel="noopener">Profil GitHub</a></div>
            <div class="muted" id="email"></div>
          </div>
        </div>
        <div class="spacer"></div>
        <button id="btn-logout">Keluar</button>
      </div>
    </div>
  </div>

  <script>
  async function fetchMe() {
    try {
      const res = await fetch('/api/me', { credentials: 'include' });
      const status = document.getElementById('status');
      const vGuest = document.getElementById('view-guest');
      const vUser = document.getElementById('view-user');

      if (res.ok) {
        const j = await res.json();
        status.textContent = 'Sudah login ✔';
        vGuest.style.display = 'none';
        vUser.style.display = 'block';

        const u = j.user;
        document.getElementById('avatar').src = u.avatar_url;
        document.getElementById('name').textContent = u.name ?? '(tanpa nama)';
        document.getElementById('login').textContent = u.login;
        document.getElementById('profile').href = u.html_url;
        document.getElementById('email').textContent = u.email ? 'Email: ' + u.email : '';
      } else {
        status.textContent = 'Belum login';
        vGuest.style.display = 'block';
        vUser.style.display = 'none';
      }
    } catch (e) {
      console.error(e);
    }
  }

  document.getElementById('btn-logout')?.addEventListener('click', async () => {
    await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    location.reload();
  });

  fetchMe();
  </script>
</body>
</html>`;
