// 账号制「激活码」服务（零依赖，仅复用 tweetnacl 验签 + Node 内置 crypto）
//
// 模型：激活码 = 给「登录账号」的一次性激活。
//   - 账号身份：邮箱(密码) 或 微信(openid)。统一存 accounts.json。
//   - 登录后拿到 token（sessions.json），激活码 redeem 时把码绑到该账号。
//   - 一码绑一个账号：别人用同码登自己的号会被拒(used)；想白嫖只能把账号交给别人。
//   - 资料 /materials 也按 token 校验账号是否已激活，服务端锁定。
//
// 部署：node server.js （PORT 可改，默认 3000；微信登录需 WX_APPID / WX_SECRET 环境变量）

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nacl = require('./nacl.js');

const PORT = process.env.PORT || 3000;
const DIR = __dirname;
const LEDGER_FILE = path.join(DIR, 'ledger.json');      // { "<codeId>": { accountId, ts } }  码→账号
const REVOKED_FILE = path.join(DIR, 'revoked.json');    // { "revoked": ["id1","id2"] }
const MATERIALS_FILE = path.join(DIR, 'materials.json');// 资料条目数组（仅激活后返回）
const ACCOUNTS_FILE = path.join(DIR, 'accounts.json');  // { "<accountId>": {...} }
const SESSIONS_FILE = path.join(DIR, 'sessions.json');  // { "<token>": { accountId, ts } }

// 与 PWA activate.js / 小程序 crypto.js 完全一致的公钥（SPKI base64url）
const PUB_SPKI_B64 = 'MCowBQYDK2VwAyEAAAzSuggAXFCVgmrEG6b0swYUdAqtgm2SabPXJyPtlvs';

// ---------------- base64url / UTF-8（与前端一致） ----------------
function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return new Uint8Array(Buffer.from(s, 'base64'));
}
function pubRaw() { return b64urlToBytes(PUB_SPKI_B64).subarray(12); } // 去 SPKI 12 字节前缀

function b64urlToBytesLocal(s) { return b64urlToBytes(s); }
function strToBytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c >= 0xd800 && c <= 0xdbff) {
      const c2 = str.charCodeAt(++i);
      const cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return new Uint8Array(out);
}
function bytesToStr(bytes) {
  let out = '', i = 0;
  while (i < bytes.length) {
    let c = bytes[i++];
    if (c < 0x80) out += String.fromCharCode(c);
    else if (c >= 0xc0 && c < 0xe0) out += String.fromCharCode(((c & 0x1f) << 6) | (bytes[i++] & 0x3f));
    else if (c >= 0xe0 && c < 0xf0) out += String.fromCharCode(((c & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f));
    else {
      const cp = ((c & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f);
      const x = cp - 0x10000;
      out += String.fromCharCode(0xd800 + ((x >> 10) & 0x3ff), 0xdc00 + (x & 0x3ff));
    }
  }
  return out;
}

// ---------------- 验签（与前端同算法） ----------------
function verifyCode(code) {
  const raw = (code || '').replace(/\s+/g, '');
  const parts = raw.split('.');
  if (parts.length !== 2) return { valid: false };
  let data, sig;
  try { data = b64urlToBytes(parts[0]); sig = b64urlToBytes(parts[1]); }
  catch (e) { return { valid: false }; }
  let ok = false;
  try { ok = nacl.sign.detached.verify(data, sig, pubRaw()); }
  catch (e) { return { valid: false }; }
  if (!ok) return { valid: false };
  let payload;
  try { payload = JSON.parse(bytesToStr(data)); }
  catch (e) { return { valid: false }; }
  if (payload.type !== 'access' && payload.type !== 'admin') return { valid: false };
  return { valid: true, type: payload.type, id: payload.id, iat: payload.iat };
}

// ---------------- 持久化 ----------------
function loadJson(p, def) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return def; } }
function saveJson(p, obj) { fs.writeFileSync(p, JSON.stringify(obj, null, 2)); }
let ledger = loadJson(LEDGER_FILE, {});
let accounts = loadJson(ACCOUNTS_FILE, {});
let sessions = loadJson(SESSIONS_FILE, {});
function saveLedger() { saveJson(LEDGER_FILE, ledger); }
function saveAccounts() { saveJson(ACCOUNTS_FILE, accounts); }
function saveSessions() { saveJson(SESSIONS_FILE, sessions); }
function readRevoked() { const j = loadJson(REVOKED_FILE, { revoked: [] }); return new Set(j.revoked || []); }

// ---------------- 账号 / 会话 ----------------
function newToken() { return crypto.randomBytes(24).toString('hex'); }
function accountIdOf(provider, providerId) { return provider + ':' + providerId; }

function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 64).toString('hex'); }

function ensureSession(provider, providerId) {
  const accountId = accountIdOf(provider, providerId);
  if (!accounts[accountId]) {
    accounts[accountId] = { provider, providerId, createdAt: Date.now() };
    saveAccounts();
  }
  const token = newToken();
  sessions[token] = { accountId, ts: Date.now() };
  saveSessions();
  return { token, accountId };
}
function accountByToken(token) {
  if (!token) return null;
  const s = sessions[token];
  if (!s) return null;
  return accounts[s.accountId] ? { accountId: s.accountId, info: accounts[s.accountId] } : null;
}

// 微信 code → openid（需 WX_APPID / WX_SECRET 环境变量）
function wxCodeToOpenid(code) {
  return new Promise((resolve, reject) => {
    const appid = process.env.WX_APPID, secret = process.env.WX_SECRET;
    if (!appid || !secret) return reject(new Error('WX_NOT_CONFIGURED'));
    const url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + encodeURIComponent(appid) +
      '&secret=' + encodeURIComponent(secret) + '&js_code=' + encodeURIComponent(code) +
      '&grant_type=authorization_code';
    https.get(url, (r) => {
      let buf = '';
      r.on('data', c => buf += c);
      r.on('end', () => {
        let j; try { j = JSON.parse(buf); } catch (e) { return reject(new Error('bad_json')); }
        if (j.errcode) return reject(new Error(j.errmsg || 'wx_error'));
        if (!j.openid) return reject(new Error('no_openid'));
        resolve(j.openid);
      });
    }).on('error', (e) => reject(e));
  });
}

// ---------------- 响应工具 ----------------
function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// ---------------- 认证 ----------------
function handleEmailRegister(body, res) {
  const email = (body && body.email || '').trim().toLowerCase();
  const pw = body && body.password || '';
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return send(res, 400, { ok: false, reason: 'bad_email' });
  if (String(pw).length < 6) return send(res, 400, { ok: false, reason: 'weak_password' });
  const accountId = accountIdOf('email', email);
  if (accounts[accountId]) return send(res, 409, { ok: false, reason: 'exists' });
  const salt = crypto.randomBytes(16).toString('hex');
  accounts[accountId] = { provider: 'email', providerId: email, email, pwHash: hashPw(pw, salt), pwSalt: salt, createdAt: Date.now() };
  saveAccounts();
  const { token } = ensureSession('email', email);
  return send(res, 200, { ok: true, token, accountId });
}
function handleEmailLogin(body, res) {
  const email = (body && body.email || '').trim().toLowerCase();
  const pw = body && body.password || '';
  const accountId = accountIdOf('email', email);
  const acc = accounts[accountId];
  if (!acc || !acc.pwHash) return send(res, 401, { ok: false, reason: 'no_account' });
  const h = hashPw(pw, acc.pwSalt);
  if (h !== acc.pwHash) return send(res, 401, { ok: false, reason: 'wrong_password' });
  const { token } = ensureSession('email', email);
  return send(res, 200, { ok: true, token, accountId });
}
function handleWechatLogin(body, res) {
  const code = body && body.code || '';
  wxCodeToOpenid(code).then(openid => {
    const { token, accountId } = ensureSession('wechat', openid);
    send(res, 200, { ok: true, token, accountId, openid });
  }).catch(e => {
    if (e.message === 'WX_NOT_CONFIGURED') return send(res, 503, { ok: false, reason: 'wx_not_configured' });
    send(res, 401, { ok: false, reason: 'wx_failed', error: e.message });
  });
}

// 返回当前账号信息 + 是否已用码激活
function handleMe(query, res) {
  const acc = accountByToken(query.get('token'));
  if (!acc) return send(res, 401, { ok: false, reason: 'unauthorized' });
  const redeemed = Object.keys(ledger).filter(k => ledger[k].accountId === acc.accountId);
  return send(res, 200, {
    ok: true, accountId: acc.accountId, provider: acc.info.provider,
    activated: redeemed.length > 0, codeIds: redeemed
  });
}

// ---------------- 业务：激活码绑账号 ----------------
// POST /redeem { code, token }
//   - 管理员码：直接放行（type=admin）
//   - 访问码：必须在登录态(token)下；首用绑该账号，异账号用同码→拒绝
function handleRedeem(body, res) {
  const code = body && body.code, token = body && body.token;
  if (!code) return send(res, 400, { ok: false, reason: 'bad_request' });
  const v = verifyCode(code);
  if (!v.valid) return send(res, 400, { ok: false, reason: 'invalid' });
  if (readRevoked().has(v.id)) return send(res, 403, { ok: false, reason: 'revoked' });

  if (v.type === 'admin') {
    return send(res, 200, { ok: true, type: 'admin' }); // 管理员码免账号绑定
  }
  const rec = ledger[v.id];
  if (rec) {
    // 已被某账号绑定
    const acc = accountByToken(token);
    if (acc && rec.accountId === acc.accountId) return send(res, 200, { ok: true, rebind: false });
    return send(res, 403, { ok: false, reason: 'used' }); // 已被其他账号使用
  }
  const acc = accountByToken(token);
  if (!acc) return send(res, 401, { ok: false, reason: 'login_required' }); // 必须先登录
  ledger[v.id] = { accountId: acc.accountId, ts: Date.now() };
  saveLedger();
  return send(res, 200, { ok: true, rebind: true });
}

function handleAdminReset(body, res) {
  const adminCode = body && body.adminCode, id = body && body.codeId;
  const v = verifyCode(adminCode);
  if (!v.valid || v.type !== 'admin') return send(res, 403, { ok: false, reason: 'unauthorized' });
  if (!id) return send(res, 400, { ok: false, reason: 'bad_request' });
  if (ledger[id]) { delete ledger[id]; saveLedger(); }
  return send(res, 200, { ok: true });
}

function handleRevoked(res) { return send(res, 200, loadJson(REVOKED_FILE, { revoked: [] })); }
function handleStats(res) {
  return send(res, 200, { redeemed: Object.keys(ledger).length, accounts: Object.keys(accounts).length });
}

// ---------------- 资料（服务端锁定：仅已激活账号/管理员可见） ----------------
// GET /materials?token=<登录token>  或  ?adminCode=<管理员码>
function handleMaterials(query, res) {
  const adminCode = query.get('adminCode');
  if (adminCode) {
    const v = verifyCode(adminCode);
    if (v.valid && v.type === 'admin') return send(res, 200, { ok: true, materials: loadJson(MATERIALS_FILE, []) });
    return send(res, 403, { ok: false, reason: 'unauthorized' });
  }
  const acc = accountByToken(query.get('token'));
  if (!acc) return send(res, 401, { ok: false, reason: 'unauthorized' });
  const mine = Object.keys(ledger).some(k => ledger[k].accountId === acc.accountId);
  if (!mine) return send(res, 403, { ok: false, reason: 'not_activated' }); // 该账号未用码激活
  return send(res, 200, { ok: true, materials: loadJson(MATERIALS_FILE, []) });
}

// POST /admin/materials  { adminCode, material:{id,title,...} }  增改一条资料
function handleAdminMaterials(body, res) {
  const v = verifyCode(body && body.adminCode);
  if (!v.valid || v.type !== 'admin') return send(res, 403, { ok: false, reason: 'unauthorized' });
  const m = body && body.material;
  if (!m || !m.id || !m.title) return send(res, 400, { ok: false, reason: 'bad_request' });
  const list = loadJson(MATERIALS_FILE, []);
  const i = list.findIndex(x => x.id === m.id);
  if (i >= 0) list[i] = Object.assign({}, list[i], m); else list.push(m);
  saveJson(MATERIALS_FILE, list);
  return send(res, 200, { ok: true, count: list.length });
}

// ---------------- 路由 ----------------
const server = http.createServer((req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  let buf = '';
  req.on('data', c => { buf += c; if (buf.length > 1e6) req.destroy(); });
  req.on('end', () => {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    let body = {};
    try { if (buf) body = JSON.parse(buf); } catch (e) { /* ignore */ }
    if (p === '/auth/email/register' && req.method === 'POST') return handleEmailRegister(body, res);
    if (p === '/auth/email/login' && req.method === 'POST') return handleEmailLogin(body, res);
    if (p === '/auth/wechat/login' && req.method === 'POST') return handleWechatLogin(body, res);
    if (p === '/me' && req.method === 'GET') return handleMe(url.searchParams, res);
    if (p === '/redeem' && req.method === 'POST') return handleRedeem(body, res);
    if (p === '/admin/reset' && req.method === 'POST') return handleAdminReset(body, res);
    if (p === '/materials' && req.method === 'GET') return handleMaterials(url.searchParams, res);
    if (p === '/admin/materials' && req.method === 'POST') return handleAdminMaterials(body, res);
    if (p === '/revoked' && req.method === 'GET') return handleRevoked(res);
    if (p === '/stats' && req.method === 'GET') return handleStats(res);
    if (p === '/' || p === '/health') return send(res, 200, { ok: true, service: 'quiz-redemption' });
    send(res, 404, { error: 'not_found' });
  });
});

server.listen(PORT, () => {
  console.log('[account-redemption] server listening on port ' + PORT);
});
