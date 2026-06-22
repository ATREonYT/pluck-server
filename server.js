// Pluck server — zero dependencies, Node 18+ built-ins only.
// Features: email signup/login, cloud save, Sign in with Apple verify,
// Claude AI proxy, RevenueCat webhook. One file, no `npm install` needed.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || "dev-insecure-secret-change-me";
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID || "app.pluck.mobile";
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const ALLOWED = (process.env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim());
const RC_AUTH = process.env.REVENUECAT_WEBHOOK_AUTH || "";
const DATA_FILE = process.env.DATA_FILE || path.join(process.cwd(), "data.json");
const YEAR = 60 * 60 * 24 * 365;

/* ---------------- tiny JSON-file store ---------------- */
let db = { users: {}, byEmail: {}, byApple: {} };
try { if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); }
catch (e) { console.error("data load failed:", e.message); }
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

  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "x").split(",")[0];
  if (limited(ip)) return send(res, 429, { error: "Slow down a moment." }, origin);

  try {
    /* ----- auth ----- */
    if (route === "POST /api/auth/signup") {
      const { email, password } = await readBody(req);
      if (!email || !password) return send(res, 400, { error: "Email and password required." }, origin);
      if (String(password).length < 6) return send(res, 400, { error: "Password must be at least 6 characters." }, origin);
      if (userByEmail(email)) return send(res, 409, { error: "That email already has an account." }, origin);
      return send(res, 200, publicUser(createUser({ email, pw: password })), origin);
    }
    if (route === "POST /api/auth/login") {
      const { email, password } = await readBody(req);
      const u = userByEmail(email);
      if (!u || !verifyPw(password, u.hash)) return send(res, 401, { error: "Wrong email or password." }, origin);
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
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: model || "claude-3-5-haiku-latest", max_tokens: max_tokens || 700, system, messages }),
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
