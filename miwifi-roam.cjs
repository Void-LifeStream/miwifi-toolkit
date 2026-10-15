#!/usr/bin/env node
/*
 * miwifi-roam.cjs — read / write the Xiaomi router's hidden roaming thresholds
 *
 * Background
 * ----------
 * Xiaomi's web UI has no "weak signal rejection / roaming threshold" page, and
 * the official stance (see the MIUI feature request threads) is that it does not
 * exist. It does exist in the firmware — it was simply unshipped from the UI:
 *
 *   - The front-end still contains two hidden forms, `roam24` and `roam50`,
 *     plus their submit handler `roamSubmitHandler()`.
 *   - That handler posts exactly four fields to /api/xqnetwork/set_wifi:
 *         wifiIndex, weakenable, weakthreshold, kickthreshold
 *   - The firmware's own validation strings give the legal ranges:
 *         weakthreshold : -95 .. -65   (dBm)
 *         kickthreshold : -100 .. -70  (dBm)
 *   - The HTML templates for those forms were removed, so the UI can never
 *     reach them — but the endpoint still accepts the parameters.
 *
 * Verified on: Xiaomi 10G Router (RC01), MiWiFi stable 1.1.56.
 *
 * Usage
 * -----
 *   node miwifi-roam.cjs show                              # read current values
 *   node miwifi-roam.cjs backup                            # dump full Wi-Fi config
 *   node miwifi-roam.cjs set <idx> <on> <weak> <kick>      # write values
 *   node miwifi-roam.cjs restore <backup.json>             # restore from a backup
 *
 *   <idx>  1 = 2.4GHz (wl1)   2 = 5GHz (wl2)   3 = 5G-Game (wl0, see NOTE)
 *   <on>   1 = enable, 0 = disable
 *
 * NOTE on wifiIndex=3
 *   Writing to 5G-Game returns {"code":0} but the values do NOT change — the
 *   firmware only shipped roaming settings for 2.4GHz and 5GHz (there is no
 *   `roam5g2` form). On most of these routers the *mesh backhaul* rides on the
 *   5G-Game radio, so the radio that covers the whole house is the one you
 *   cannot tune. Keep that in mind before you get excited.
 *
 * SIDE EFFECTS — READ THIS
 *   - Writing makes the Wi-Fi radio restart; the firmware itself says
 *     "设置成功正在重启，需要30秒请等待". Expect ~30 seconds of downtime
 *     on that band, and clients will re-associate.
 *   - The request mirrors the band's current ssid / channel / bandwidth /
 *     encryption / password, so nothing else is altered. Verified: after a
 *     write, SSID, channel, bandwidth, encryption and password are unchanged.
 *   - Back up first (`backup`). Restoring is one command.
 *
 * Configuration (environment variables)
 *   MIWIFI_HOST     router address            (default 192.168.1.1)
 *   MIWIFI_SECRET   file with the admin password (default ~/.miwifi-password,
 *                   a single line `PASSWORD=...`)
 *   MIWIFI_STATE    session cache file        (default ~/.miwifi-session.json)
 *   MIWIFI_DEVID    device id used inside the nonce (default: auto-detected MAC)
 *
 * License: MIT. No warranty. You are poking a router your household depends on.
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

const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const BAND = { '1': 'wl1 (2.4GHz)', '2': 'wl2 (5GHz)', '3': 'wl0 (5GHz-Game)' };
const IDX_OF = { wl1: '1', wl2: '2', wl0: '3' };
const SUPPORTED = ['1', '2'];   // firmware only shipped roam24 / roam50

function die(m) { process.stderr.write('ERROR: ' + m + '\n'); process.exit(1); }

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
  catch (e) { die('cannot read ' + SECRET_FILE + ' -> ' + e.message); }
  const line = raw.split(/\r?\n/).find(l => /^\s*PASSWORD=/.test(l));
  if (!line) die('no `PASSWORD=` line in ' + SECRET_FILE);
  const pw = line.replace(/^\s*PASSWORD=/, '').trimEnd();
  if (!pw) die('empty password in ' + SECRET_FILE);
  return pw;
}

function req(method, p, body) {
  return new Promise((resolve, reject) => {
    const headers = {
      'User-Agent': 'Mozilla/5.0',
      'Accept': 'application/json, text/javascript, */*; q=0.01',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'http://' + HOST + '/cgi-bin/luci/web',
      'Origin': 'http://' + HOST
    };
    let data = null;
    if (body) {
      data = new URLSearchParams(body).toString();
      headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    const r = http.request({ host: HOST, port: 80, path: p, method, headers }, res => {
      const cs = [];
      res.on('data', c => cs.push(c));
      res.on('end', () => resolve(Buffer.concat(cs).toString('utf8')));
    });
    r.on('error', reject);
    r.setTimeout(60000, () => r.destroy(new Error('timeout')));
    if (data) r.write(data);
    r.end();
  });
}

async function login() {
  await req('GET', '/cgi-bin/luci/web');
  const nonce = [0, DEVICE_ID, Math.floor(Date.now() / 1000), Math.floor(Math.random() * 10000)].join('_');
  const t = await req('POST', '/cgi-bin/luci/api/xqsystem/login', {
    username: 'admin',
    password: sha256(nonce + sha256(readPassword() + AES_KEY)),
    logtype: '2',
    nonce: nonce
  });
  const j = JSON.parse(t);
  if (j.code !== 0) die('login failed: code=' + j.code + ' ' + (j.msg || ''));
  try { fs.writeFileSync(STATE_FILE, JSON.stringify({ stok: j.token, ts: Date.now() }), { mode: 0o600 }); } catch (e) { }
  return j.token;
}

async function stok() {
  try {
    const j = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (j && j.stok) return j.stok;
  } catch (e) { }
  return await login();
}

async function api(method, p, body) {
  let s = await stok();
  const call = tok => req(method, '/cgi-bin/luci/;stok=' + tok + p, body);
  let t = await call(s);
  try { const j = JSON.parse(t); if (j && j.code === 401) { s = await login(); t = await call(s); } } catch (e) { }
  return t;
}

const board = info => info.map(x => ({
  ifname: x.ifname, idx: IDX_OF[x.ifname] || '?', ssid: x.ssid, channel: x.channel,
  bandwidth: x.bandwidth, encryption: x.encryption, hidden: x.hidden, txpwr: x.txpwr,
  weakenable: x.weakenable, weakthreshold: x.weakthreshold, kickthreshold: x.kickthreshold,
  password: x.password
}));

(async () => {
  const argv = process.argv.slice(2);
  const cmd = argv[0] || '';
  if (!cmd) die('usage: show | backup | set <idx> <on> <weak> <kick> | restore <file>');

  if (cmd === 'show') {
    const j = JSON.parse(await api('GET', '/api/xqnetwork/wifi_detail_all'));
    console.log('idx  ifname  band                  weakenable  weakthreshold  kickthreshold');
    for (const r of board(j.info)) {
      console.log(`  ${r.idx}  ${r.ifname}    ch=${r.channel}/${r.bandwidth}    ${String(r.weakenable).padEnd(11)} ${String(r.weakthreshold).padEnd(14)} ${r.kickthreshold}`);
    }
    return;
  }

  if (cmd === 'backup') {
    const raw = await api('GET', '/api/xqnetwork/wifi_detail_all');
    const f = path.join(process.cwd(), 'miwifi-wifi-backup-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json');
    fs.writeFileSync(f, raw, { mode: 0o600 });
    console.log('backup written: ' + path.basename(f) + '  (' + raw.length + ' bytes — CONTAINS PASSWORDS, keep it private)');
    return;
  }

  if (cmd === 'set') {
    const [idx, on, weak, kick] = argv.slice(1);
    if (!idx || on === undefined || !weak || !kick) die('usage: set <idx 1|2|3> <on 0|1> <weak -95..-65> <kick -100..-70>');
    if (!(Number(weak) >= -95 && Number(weak) <= -65)) die('weakthreshold out of range (-95..-65): ' + weak);
    if (!(Number(kick) >= -100 && Number(kick) <= -70)) die('kickthreshold out of range (-100..-70): ' + kick);
    if (!SUPPORTED.includes(idx)) {
      console.log('NOTE: wifiIndex=' + idx + ' (' + BAND[idx] + ') is not supported by this firmware —');
      console.log('      the router will answer {"code":0} but the values will NOT change. Continuing anyway…');
    }

    const j = JSON.parse(await api('GET', '/api/xqnetwork/wifi_detail_all'));
    const cfg = board(j.info).find(x => x.idx === idx);
    if (!cfg) die('no band with idx=' + idx);

    const body = {
      wifiIndex: idx, on: '1', ssid: cfg.ssid, hidden: String(cfg.hidden),
      encryption: cfg.encryption, pwd: cfg.password || '',
      channel: String(cfg.channel), bandwidth: String(cfg.bandwidth), txpwr: cfg.txpwr || 'max',
      weakenable: on, weakthreshold: weak, kickthreshold: kick
    };
    console.log(`POST /api/xqnetwork/set_wifi  wifiIndex=${idx} (${BAND[idx]})  weakenable=${on} weak=${weak} kick=${kick}`);
    const t = await api('POST', '/api/xqnetwork/set_wifi', body);
    console.log('response: ' + String(t).slice(0, 200));
    console.log('(the radio restarts now — expect ~30s of downtime on that band)');
    return;
  }

  if (cmd === 'restore') {
    const f = argv[1];
    if (!f) die('usage: restore <backup.json>');
    const j = JSON.parse(fs.readFileSync(f, 'utf8'));
    for (const b of board(j.info)) {
      const body = {
        wifiIndex: b.idx, on: '1', ssid: b.ssid, hidden: String(b.hidden), encryption: b.encryption,
        pwd: b.password || '', channel: String(b.channel), bandwidth: String(b.bandwidth), txpwr: b.txpwr || 'max',
        weakenable: b.weakenable, weakthreshold: b.weakthreshold, kickthreshold: b.kickthreshold
      };
      console.log(`restoring idx=${b.idx} -> ` + String(await api('POST', '/api/xqnetwork/set_wifi', body)).slice(0, 120));
    }
    return;
  }

  die('unknown command: ' + cmd);
})().catch(e => die(String(e && e.message ? e.message : e)));
