// Pluck server — zero dependencies, Node 18+ built-ins only.
// Features: email signup/login, cloud save, Sign in with Apple verify,
// Claude AI proxy, RevenueCat webhook. One file, no `npm install` needed.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || "dev-insecure-secret-change-me";
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID || "app.pluck.mobile";
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const ALLOWED = (process.env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim());
const RC_AUTH = process.env.REVENUECAT_WEBHOOK_AUTH || "";
const DATA_FILE = process.env.DATA_FILE || path.join(process.cwd(), "data.json");
const YEAR = 60 * 60 * 24 * 365;
const BREVO_API_KEY = process.env.BREVO_API_KEY || "";
const BREVO_SENDER = process.env.BREVO_SENDER || "";   // the verified "work email" Brevo sends from
const APP_NAME = process.env.APP_NAME || "Pluck";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";     // protects the broadcast endpoint
const PUBLIC_URL = process.env.APP_PUBLIC_URL || "";   // optional; otherwise derived from the request

/* ---------------- tiny JSON-file store ---------------- */
let db = { users: {}, byEmail: {}, byApple: {}, resets: {} };
try { if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); }
catch (e) { console.error("data load failed:", e.message); }
db.users ||= {}; db.byEmail ||= {}; db.byApple ||= {}; db.resets ||= {};
let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(db)); }
    catch (e) { console.error("data save failed:", e.message); }
  }, 50);
}
const newId = () => crypto.randomBytes(12).toString("hex");

/* ---------------- passwords (scrypt) ---------------- */
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(pw), salt, 64);
  return salt.toString("hex") + ":" + h.toString("hex");
}
function verifyPw(pw, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [s, h] = stored.split(":");
  const hash = Buffer.from(h, "hex");
  const calc = crypto.scryptSync(String(pw), Buffer.from(s, "hex"), 64);
  return calc.length === hash.length && crypto.timingSafeEqual(calc, hash);
}

/* ---------------- JWT (HS256) ---------------- */
const b64u = (buf) => Buffer.from(buf).toString("base64url");
function signToken(uid) {
  const header = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64u(JSON.stringify({ uid, iat: now, exp: now + YEAR }));
  const data = header + "." + payload;
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(data).digest("base64url");
  return data + "." + sig;
}
function verifyToken(tok) {
  if (!tok) return null;
  const parts = tok.split(".");
  if (parts.length !== 3) return null;
  const data = parts[0] + "." + parts[1];
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(data).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(parts[2]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    if (p.exp && p.exp < Math.floor(Date.now() / 1000)) return null;
    return p;
  } catch { return null; }
}

/* ---------------- users ---------------- */
function createUser({ email = null, pw = null, appleSub = null }) {
  const id = newId();
  const u = {
    id, email: email ? email.toLowerCase() : null,
    hash: pw ? hashPw(pw) : null, appleSub: appleSub || null,
    pro: false, save: { data: null, updatedAt: 0 }, createdAt: Date.now(),
  };
  db.users[id] = u;
  if (u.email) db.byEmail[u.email] = id;
  if (appleSub) db.byApple[appleSub] = id;
  persist();
  return u;
}
const userByEmail = (e) => (e && db.byEmail[e.toLowerCase()]) ? db.users[db.byEmail[e.toLowerCase()]] : null;
const userByApple = (s) => db.byApple[s] ? db.users[db.byApple[s]] : null;
const publicUser = (u) => ({ token: signToken(u.id), email: u.email, pro: !!u.pro });

/* ---------------- email (Brevo) ---------------- */
const FONT = "system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif";
function emailLayout(heading, bodyHtml) {
  return `<div style="background:#F4F6FB;padding:28px 0;font-family:${FONT}">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:18px;overflow:hidden;border:1px solid #E7EBF3">
    <div style="background:linear-gradient(135deg,#FFD15C,#FF6F4E);padding:22px 24px">
      <span style="font-size:22px;font-weight:800;color:#fff;letter-spacing:.5px">PLUCK</span>
    </div>
    <div style="padding:26px 24px;color:#1d2433;font-size:15px;line-height:1.55">
      <h1 style="margin:0 0 12px;font-size:20px;color:#12172a">${heading}</h1>
      ${bodyHtml}
    </div>
    <div style="padding:16px 24px;color:#8a93a6;font-size:12px;border-top:1px solid #EEF1F7">
      You're receiving this because you have a ${APP_NAME} account.
    </div>
  </div></div>`;
}
const emailButton = (href, label) =>
  `<a href="${href}" style="display:inline-block;margin:18px 0;background:linear-gradient(135deg,#FFD15C,#FF6F4E);color:#1d2433;font-weight:800;text-decoration:none;padding:13px 26px;border-radius:12px">${label}</a>`;
async function sendEmail(to, subject, html) {
  if (!BREVO_API_KEY || !BREVO_SENDER) { console.log("[email skipped — not configured] to:", to, "| subject:", subject); return false; }
  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": BREVO_API_KEY, "content-type": "application/json", "accept": "application/json" },
      body: JSON.stringify({ sender: { name: APP_NAME, email: BREVO_SENDER }, to: [{ email: to }], subject, htmlContent: html }),
    });
    if (!r.ok) { console.error("email send failed:", r.status, await r.text().catch(() => "")); return false; }
    return true;
  } catch (e) { console.error("email error:", e.message); return false; }
}
function baseUrl(req) {
  if (PUBLIC_URL) return PUBLIC_URL.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0];
  const host = req.headers["x-forwarded-host"] || req.headers["host"] || "localhost";
  return proto + "://" + host;
}
function resetPage(token) {
  return `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Reset your Pluck password</title>
  <style>body{margin:0;background:#F4F6FB;font-family:${FONT};color:#1d2433}.card{max-width:420px;margin:8vh auto;background:#fff;border:1px solid #E7EBF3;border-radius:20px;overflow:hidden}.hd{background:linear-gradient(135deg,#FFD15C,#FF6F4E);padding:20px 24px;color:#fff;font-weight:800;font-size:22px;letter-spacing:.5px}.bd{padding:24px}input{width:100%;box-sizing:border-box;padding:13px 14px;border:1px solid #D8DEEA;border-radius:12px;font-size:16px;margin-bottom:12px}button{width:100%;padding:14px;border:0;border-radius:12px;background:linear-gradient(135deg,#FFD15C,#FF6F4E);color:#1d2433;font-weight:800;font-size:16px;cursor:pointer}.msg{margin-top:14px;font-weight:700;text-align:center;min-height:20px}h1{font-size:20px;margin:0 0 6px}p{color:#5b6478;font-size:14px;margin:0 0 18px}</style></head>
  <body><div class="card"><div class="hd">PLUCK</div><div class="bd">
  <h1>Choose a new password</h1><p>Enter a new password for your account.</p>
  <input id="p1" type="password" placeholder="New password (8+ chars)"/>
  <input id="p2" type="password" placeholder="Confirm new password"/>
  <button id="go">Reset password</button>
  <div class="msg" id="m"></div>
  </div></div>
  <script>
  var TK=${JSON.stringify(token)};var m=document.getElementById('m');
  document.getElementById('go').onclick=function(){
    var a=document.getElementById('p1').value,b=document.getElementById('p2').value;
    if(a.length<8){m.style.color='#FF6F4E';m.textContent='Password must be at least 8 characters.';return;}
    if(a!==b){m.style.color='#FF6F4E';m.textContent='Passwords do not match.';return;}
    m.style.color='#5b6478';m.textContent='Saving…';
    fetch('/api/auth/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:TK,password:a})})
      .then(function(r){return r.json().then(function(j){return{s:r.status,j:j};});})
      .then(function(x){if(x.s===200){m.style.color='#1aa251';m.textContent='✓ Password reset! Open the Pluck app and sign in with your new password.';document.getElementById('go').disabled=true;}else{m.style.color='#FF6F4E';m.textContent=(x.j&&x.j.error)||'Something went wrong.';}})
      .catch(function(){m.style.color='#FF6F4E';m.textContent='Network error. Try again.';});
  };
  </script></body></html>`;
}

/* ---------------- Sign in with Apple verify (RS256 vs Apple JWKS) ---------------- */
let appleKeys = null, appleKeysAt = 0;
async function appleJWKS() {
  if (appleKeys && Date.now() - appleKeysAt < 3600e3) return appleKeys;
  const r = await fetch("https://appleid.apple.com/auth/keys");
  appleKeys = (await r.json()).keys;
  appleKeysAt = Date.now();
  return appleKeys;
}
async function verifyApple(idToken) {
  const [h, p, s] = String(idToken).split(".");
  if (!s) throw new Error("malformed token");
  const header = JSON.parse(Buffer.from(h, "base64url").toString());
  const jwk = (await appleJWKS()).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("unknown key id");
  const pub = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const ok = crypto.verify("sha256", Buffer.from(h + "." + p), pub, Buffer.from(s, "base64url"));
  if (!ok) throw new Error("bad signature");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString());
  if (payload.iss !== "https://appleid.apple.com") throw new Error("bad issuer");
  if (payload.aud !== APPLE_CLIENT_ID) throw new Error("bad audience");
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error("expired");
  return { sub: payload.sub, email: payload.email || null };
}

/* ---------------- http helpers ---------------- */
function corsHeaders(origin, extra = {}) {
  const allow = ALLOWED.includes("*") ? "*" : (ALLOWED.includes(origin) ? origin : (ALLOWED[0] || "*"));
  return Object.assign({
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Vary": "Origin",
  }, extra);
}
function send(res, status, obj, origin) {
  res.writeHead(status, corsHeaders(origin, { "Content-Type": "application/json" }));
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 2e6) req.destroy(); });
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
    req.on("error", () => resolve({}));
  });
}
const authUser = (req) => { const m = (req.headers["authorization"] || "").match(/^Bearer (.+)$/); const t = m && verifyToken(m[1]); return t ? db.users[t.uid] : null; };

/* ---------------- naive per-IP rate limit ---------------- */
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now); hits.set(ip, arr);
  return arr.length > 90;
}

/* ---------------- router ---------------- */
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || "";
  const url = new URL(req.url, "http://x");
  const route = req.method + " " + url.pathname;

  if (req.method === "OPTIONS") { res.writeHead(204, corsHeaders(origin)); return res.end(); }
  if (route === "GET /health" || route === "GET /") return send(res, 200, { ok: true, service: "pluck" }, origin);
  if (route === "GET /privacy" || route === "GET /terms") {
    const file = path.join(__dirname, route === "GET /privacy" ? "privacy.html" : "terms.html");
    try { const html = fs.readFileSync(file, "utf8"); res.writeHead(200, corsHeaders(origin, { "Content-Type": "text/html; charset=utf-8" })); return res.end(html); }
    catch (e) { return send(res, 404, { error: "Not found" }, origin); }
  }

  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "x").split(",")[0];
  if (limited(ip)) return send(res, 429, { error: "Slow down a moment." }, origin);

  try {
    /* ----- auth ----- */
    if (route === "POST /api/auth/signup") {
      const { email, password, deviceId } = await readBody(req);
      if (!email || !password) return send(res, 400, { error: "Email and password required." }, origin);
      if (String(password).length < 8) return send(res, 400, { error: "Password must be at least 8 characters." }, origin);
      if (userByEmail(email)) return send(res, 409, { error: "That email already has an account." }, origin);
      const u = createUser({ email, pw: password });
      u.devices = deviceId ? [deviceId] : [];
      persist();
      sendEmail(u.email, "Welcome to Pluck 🎉", emailLayout("Welcome to Pluck!",
        `<p>Your account is all set. Time to pluck up the courage and practice the conversations that matter — interviews, dates, raises, tough talks and more.</p><p>Your progress now syncs to every device you sign in on.</p>`)).catch(() => {});
      return send(res, 200, publicUser(u), origin);
    }
    if (route === "POST /api/auth/login") {
      const { email, password, deviceId } = await readBody(req);
      const u = userByEmail(email);
      if (!u || !verifyPw(password, u.hash)) return send(res, 401, { error: "Wrong email or password." }, origin);
      const dev = deviceId;
      if (dev) {
        if (!Array.isArray(u.devices)) u.devices = [];
        if (u.devices.length && !u.devices.includes(dev)) {
          const when = new Date().toUTCString();
          const ua = req.headers["user-agent"] || "an unknown device";
          sendEmail(u.email, "New sign-in to your Pluck account", emailLayout("New sign-in detected",
            `<p>Your Pluck account was just signed in on a new device.</p><p style="color:#5b6478;font-size:13px">When: ${when}<br>Device: ${ua}</p><p>If this was you, no action needed. If it wasn't, reset your password right away from the app's sign-in screen.</p>`)).catch(() => {});
        }
        if (!u.devices.includes(dev)) { u.devices.push(dev); persist(); }
      }
      return send(res, 200, publicUser(u), origin);
    }
    if (route === "POST /api/auth/apple") {
      const { identityToken } = await readBody(req);
      if (!identityToken) return send(res, 400, { error: "Missing Apple token." }, origin);
      let info; try { info = await verifyApple(identityToken); }
      catch (e) { return send(res, 401, { error: "Apple sign-in failed: " + e.message }, origin); }
      let u = userByApple(info.sub);
      if (!u && info.email) { const be = userByEmail(info.email); if (be) { be.appleSub = info.sub; db.byApple[info.sub] = be.id; persist(); u = be; } }
      if (!u) u = createUser({ email: info.email, appleSub: info.sub });
      return send(res, 200, publicUser(u), origin);
    }

    /* ----- password reset ----- */
    if (route === "POST /api/auth/forgot") {
      const { email } = await readBody(req);
      const u = userByEmail(email);
      if (u && u.email) {
        const tok = crypto.randomBytes(24).toString("hex");
        db.resets[tok] = { uid: u.id, exp: Date.now() + 30 * 60 * 1000 };
        persist();
        const link = baseUrl(req) + "/reset?token=" + tok;
        await sendEmail(u.email, "Reset your Pluck password", emailLayout("Reset your password",
          `<p>We got a request to reset your Pluck password. Tap the button below to choose a new one — this link expires in 30 minutes.</p>${emailButton(link, "Reset password")}<p style="color:#8a93a6;font-size:12px">If the button doesn't work, paste this into your browser:<br>${link}</p><p style="color:#8a93a6;font-size:12px">Didn't request this? You can safely ignore this email; your password won't change.</p>`));
      }
      // Always succeed — never reveal whether an email is registered.
      return send(res, 200, { ok: true }, origin);
    }
    if (route === "GET /reset") {
      res.writeHead(200, corsHeaders(origin, { "Content-Type": "text/html; charset=utf-8" }));
      return res.end(resetPage(url.searchParams.get("token") || ""));
    }
    if (route === "POST /api/auth/reset") {
      const { token, password } = await readBody(req);
      const rec = token && db.resets[token];
      if (!rec || rec.exp < Date.now()) { if (rec) { delete db.resets[token]; persist(); } return send(res, 400, { error: "This reset link is invalid or has expired." }, origin); }
      if (!password || String(password).length < 8) return send(res, 400, { error: "Password must be at least 8 characters." }, origin);
      const u = db.users[rec.uid];
      if (!u) { delete db.resets[token]; persist(); return send(res, 400, { error: "Account not found." }, origin); }
      u.hash = hashPw(password);
      delete db.resets[token];
      persist();
      sendEmail(u.email, "Your Pluck password was changed", emailLayout("Password changed",
        `<p>Your Pluck password was just changed. If this was you, you're all set. If it wasn't, reset it again immediately and contact support.</p>`)).catch(() => {});
      return send(res, 200, { ok: true }, origin);
    }

    /* ----- admin: broadcast an update email to all users ----- */
    if (route === "POST /api/admin/broadcast") {
      if (!ADMIN_TOKEN || req.headers["authorization"] !== "Bearer " + ADMIN_TOKEN) return send(res, 401, { error: "Unauthorized" }, origin);
      const { subject, heading, body } = await readBody(req);
      if (!subject || !body) return send(res, 400, { error: "subject and body are required" }, origin);
      const recipients = Object.values(db.users).map((u) => u.email).filter(Boolean);
      let sent = 0;
      for (const to of recipients) { if (await sendEmail(to, subject, emailLayout(heading || subject, body))) sent++; }
      return send(res, 200, { ok: true, recipients: recipients.length, sent }, origin);
    }

    /* ----- account (auth required) ----- */
    if (url.pathname === "/api/me" || url.pathname === "/api/save") {
      const u = authUser(req);
      if (!u) return send(res, 401, { error: "Not signed in." }, origin);
      if (route === "GET /api/me") return send(res, 200, { id: u.id, email: u.email, pro: !!u.pro }, origin);
      if (route === "DELETE /api/me") {
        if (u.email) delete db.byEmail[u.email];
        if (u.appleSub) delete db.byApple[u.appleSub];
        delete db.users[u.id]; persist();
        return send(res, 200, { ok: true, deleted: true }, origin);
      }
      if (route === "GET /api/save") return send(res, 200, u.save || { data: null, updatedAt: 0 }, origin);
      if (route === "PUT /api/save") {
        const { data } = await readBody(req);
        u.save = { data: data ?? null, updatedAt: Date.now() }; persist();
        return send(res, 200, { ok: true, updatedAt: u.save.updatedAt }, origin);
      }
    }

    /* ----- AI proxy ----- */
    if (route === "POST /api/chat") {
      if (!ANTHROPIC_API_KEY) return send(res, 503, { error: "AI not configured on server." }, origin);
      const { model, max_tokens, system, messages } = await readBody(req);
      const safeTokens = Math.min(Math.max(1, Number(max_tokens) || 700), 2000); // cap to control cost
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: model || "claude-haiku-4-5-20251001", max_tokens: safeTokens, system, messages }),
      });
      const j = await r.json();
      return send(res, r.status, j, origin);
    }

    /* ----- RevenueCat webhook ----- */
    if (route === "POST /api/webhooks/revenuecat") {
      if (RC_AUTH && req.headers["authorization"] !== RC_AUTH) return send(res, 401, { error: "bad auth" }, origin);
      const body = await readBody(req);
      const uid = body?.event?.app_user_id;
      const type = body?.event?.type || "";
      const u = uid && db.users[uid];
      if (u) { u.pro = !/EXPIRATION|CANCELLATION/i.test(type); persist(); }
      return send(res, 200, { ok: true }, origin);
    }

    return send(res, 404, { error: "Not found" }, origin);
  } catch (e) {
    console.error("server error:", e);
    return send(res, 500, { error: "Server error" }, origin);
  }
});

server.listen(PORT, () => console.log("Pluck server (zero-dep) on :" + PORT));
