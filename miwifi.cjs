#!/usr/bin/env node
/*
 * miwifi.cjs — Xiaomi / MiWiFi router API client (standalone, no dependencies)
 *
 * Why this exists
 * ---------------
 * Talking to a Xiaomi router's web backend from a script is awkward:
 *   1. The login hash is NOT what the login page's source text suggests.
 *      The page ships `newEncryptMode = ''` (which would mean SHA1), but at
 *      RUNTIME it is set to '1', so the real formula is:
 *          password = SHA256( nonce + SHA256(plain_password + key) )
 *      Using SHA1 yields a silent `401 not auth` and wastes a lot of time.
 *      (key = "a2ffa5c9be07488bbb04a3a47d3c5f6a", hardcoded in the firmware UI)
 *   2. The router refuses back-to-back logins (second one returns
 *      `1582 Invalid nonce`), so a session cache is required.
 *
 * Usage
 * -----
 *   node miwifi.cjs login                            # verify login works
 *   node miwifi.cjs GET  <apiPath> [k=v ...]         # GET an endpoint
 *   node miwifi.cjs POST <apiPath> [k=v ...]         # POST form data
 *   node miwifi.cjs raw  <fullPath>                  # any path, stok prepended
 *   node miwifi.cjs logout                           # drop the cached session
 *
 * Configuration (environment variables)
 * -------------------------------------
 *   MIWIFI_HOST     router address            (default 192.168.1.1)
 *   MIWIFI_SECRET   file holding the password (default ~/.miwifi-password)
 *                   format: a single line `PASSWORD=your_admin_password`
 *   MIWIFI_STATE    session cache file        (default ~/.miwifi-session.json)
 *   MIWIFI_DEVID    device id used inside nonce; default = first non-internal
 *                   network interface MAC address
 *
 * Examples
 *   node miwifi.cjs GET /api/misystem/devicelist
 *   node miwifi.cjs GET /api/xqnetwork/wifi_detail_all
 *
 * Notes
 *   - Password never leaves this process; it is never printed.
 *   - Output redacts secret-looking JSON fields unless MIWIFI_SHOW_SECRETS=1.
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const http = require('http');

const HOST = process.env.MIWIFI_HOST || '192.168.1.1';
const SECRET_FILE = process.env.MIWIFI_SECRET || path.join(os.homedir(), '.miwifi-password');
const STATE_FILE = process.env.MIWIFI_STATE || path.join(os.homedir(), '.miwifi-session.json');
const AES_KEY = 'a2ffa5c9be07488bbb04a3a47d3c5f6a';
const DEBUG = process.env.MIWIFI_DEBUG === '1';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

function die(msg) { process.stderr.write('ERROR: ' + msg + '\n'); process.exit(1); }
const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const dbg = m => { if (DEBUG) process.stderr.write('[debug] ' + m + '\n'); };

/** Pick the first usable MAC address of this machine (used inside the nonce). */
function detectDeviceId() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const i of ifaces[name] || []) {
      if (!i.internal && i.mac && i.mac !== '00:00:00:00:00:00') return i.mac.toLowerCase();
    }
  }
  return '00:00:00:00:00:00';
}
const DEVICE_ID = process.env.MIWIFI_DEVID || detectDeviceId();

function readPassword() {
  let raw;
  try { raw = fs.readFileSync(SECRET_FILE, 'utf8'); }
  catch (e) { die('cannot read password file ' + SECRET_FILE + ' -> ' + e.message); }
  const line = raw.split(/\r?\n/).find(l => /^\s*PASSWORD=/.test(l));
  if (!line) die('no `PASSWORD=` line found in ' + SECRET_FILE);
  const pw = line.replace(/^\s*PASSWORD=/, '').trimEnd();
  if (!pw) die('password is empty in ' + SECRET_FILE);
  return pw;
}

function readStok() {
  try {
    const j = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (j && typeof j.stok === 'string' && j.stok) return j.stok;
  } catch (e) { }
  return null;
}
function writeStok(stok) {
  try { fs.writeFileSync(STATE_FILE, JSON.stringify({ stok, ts: Date.now() }), { mode: 0o600 }); }
  catch (e) { dbg('cannot cache session: ' + e.message); }
}

function request(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const headers = {
      'User-Agent': UA,
      'Accept': 'application/json, text/javascript, */*; q=0.01',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'http://' + HOST + '/cgi-bin/luci/web',
      'Origin': 'http://' + HOST
    };
    if (body) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = http.request({ host: HOST, port: 80, path: urlPath, method, headers }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.setTimeout(30000, () => req.destroy(new Error('request timeout')));
    if (body) req.write(body);
    req.end();
  });
}

async function login() {
  await request('GET', '/cgi-bin/luci/web');           // establishes luci cookies
  const pwd = readPassword();
  const nonce = [0, DEVICE_ID, Math.floor(Date.now() / 1000), Math.floor(Math.random() * 10000)].join('_');
  const body = 'username=admin'
    + '&password=' + sha256(nonce + sha256(pwd + AES_KEY))
    + '&logtype=2'
    + '&nonce=' + encodeURIComponent(nonce);
  const r = await request('POST', '/cgi-bin/luci/api/xqsystem/login', body);
  let j;
  try { j = JSON.parse(r.text); }
  catch (e) { die('login: non-JSON reply (http ' + r.status + '): ' + r.text.slice(0, 200)); }
  if (j.code === 1582) die('login refused (1582 Invalid nonce): the router rejects back-to-back logins; wait ~60s.');
  if (j.code !== 0) die('login failed (code=' + j.code + '): ' + String(j.msg || '').slice(0, 160));
  if (!j.token) die('login ok but no token returned');
  return j.token;
}

const redact = t => (process.env.MIWIFI_SHOW_SECRETS === '1') ? t
  : t.replace(/("(?:password|passwd|pwd|secret|key|token|stok)"\s*:\s*")([^"]*)(")/gi, '$1***$3');

(async () => {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd) die('usage: miwifi.cjs login | logout | GET <path> [k=v..] | POST <path> [k=v..] | raw <path>');

  if (cmd === 'logout') { try { fs.unlinkSync(STATE_FILE); } catch (e) { } console.log('cached session cleared'); return; }

  if (cmd === 'login') { writeStok(await login()); console.log('login OK (session cached)'); return; }

  const apiPath = argv[1];
  if (!apiPath) die('missing <path>');
  const kv = {};
  for (const a of argv.slice(2)) { const i = a.indexOf('='); if (i > 0) kv[a.slice(0, i)] = a.slice(i + 1); }

  let method = 'GET', body = null, suffix = '';
  if (cmd !== 'raw') {
    method = cmd.toUpperCase();
    if (method !== 'GET' && method !== 'POST') die('method must be GET or POST');
    if (method === 'GET' && Object.keys(kv).length) suffix = (apiPath.includes('?') ? '&' : '?') + new URLSearchParams(kv);
    if (method === 'POST') body = new URLSearchParams(kv).toString();
  } else if (Object.keys(kv).length) {
    suffix = (apiPath.includes('?') ? '&' : '?') + new URLSearchParams(kv);
  }

  let stok = readStok();
  if (!stok) { stok = await login(); writeStok(stok); }

  const build = s => '/cgi-bin/luci/;stok=' + s + apiPath + suffix;
  let r = await request(method, build(stok), body);
  const looksUnauthorized = r.status === 401 || r.status === 403 || /"code"\s*:\s*401/.test(r.text);
  if (looksUnauthorized) {
    dbg('cached session rejected, logging in again');
    stok = await login(); writeStok(stok);
    r = await request(method, build(stok), body);
  }
  process.stdout.write(redact(r.text) + '\n');
})().catch(e => die(String(e && e.message ? e.message : e)));
