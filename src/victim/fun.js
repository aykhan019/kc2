// Cross-platform desktop effects for the educational lab. User-controlled
// values are always passed as argv (or base64 argv for fixed PowerShell
// scripts); nothing is interpolated into a shell command.
import { execFileSync } from 'node:child_process';

export const MAX_FUN_TEXT = 200;
export const RICKROLL_URL = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ&autoplay=1';

const MAC_SOUND = '/System/Library/Sounds/Glass.aiff';
const EXEC_OPTIONS = Object.freeze({ encoding: 'utf8', stdio: 'ignore', timeout: 15_000, windowsHide: true });

const PS_DECODE_TEXT =
  '$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($args[0]));';
const PS_SAY = `${PS_DECODE_TEXT} Add-Type -AssemblyName System.Speech; ` +
  '$speaker=New-Object System.Speech.Synthesis.SpeechSynthesizer; $speaker.Speak($text);';
const PS_NOTIFY = `${PS_DECODE_TEXT} $shell=New-Object -ComObject WScript.Shell; ` +
  '$null=$shell.Popup($text,5,"KC2",64);';
const PS_BEEP =
  'Add-Type -AssemblyName System.Windows.Extensions -ErrorAction SilentlyContinue; ' +
  '[System.Media.SystemSounds]::Asterisk.Play(); Start-Sleep -Milliseconds 350;';
const PS_OPEN_MAXIMIZED = 'Start-Process -FilePath $args[0] -WindowStyle Maximized;';
const PS_BOUNCE = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LabAttention {
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
  [DllImport("user32.dll")] public static extern bool FlashWindow(IntPtr handle, bool invert);
}
'@;
$handle=[LabAttention]::GetConsoleWindow();
if ($handle -eq [IntPtr]::Zero) { throw "no interactive console window"; }
1..6 | ForEach-Object { [LabAttention]::FlashWindow($handle,$true) | Out-Null; Start-Sleep -Milliseconds 150; }`;
const PS_VOLUME_API = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LabVolume {
  [DllImport("user32.dll")] static extern void keybd_event(byte key, byte scan, uint flags, UIntPtr extra);
  public static void Tap(byte key) {
    keybd_event(key,0,0,UIntPtr.Zero);
    keybd_event(key,0,2,UIntPtr.Zero);
  }
}
'@;`;
const PS_VOLUME = `${PS_VOLUME_API}
$level=[int]$args[0];
for ($i=0; $i -lt 50; $i++) { [LabVolume]::Tap(174); };
$steps=[int][Math]::Ceiling($level/2);
for ($i=0; $i -lt $steps; $i++) { [LabVolume]::Tap(175); };`;
const PS_UNMUTE = `${PS_VOLUME_API}
[LabVolume]::Tap(175);`;

function runtimeFrom(options = {}) {
  return {
    platform: options.platform ?? process.platform,
    exec: options.execFileSync ?? execFileSync,
    writeBell: options.writeBell ?? ((value) => process.stdout.write(value)),
  };
}

function execute(runtime, file, args) {
  runtime.exec(file, args, EXEC_OPTIONS);
}

function executeFirst(runtime, candidates, label) {
  for (const [file, args] of candidates) {
    try {
      execute(runtime, file, args);
      return;
    } catch {
      // Try the next common Linux desktop utility.
    }
  }
  throw new Error(`${label} unavailable; tried ${candidates.map(([file]) => file).join(', ')}`);
}

function requireText(args, op) {
  const text = typeof args.text === 'string' ? args.text.trim() : '';
  if (!text) throw new Error(`${op} requires text`);
  if (text.length > MAX_FUN_TEXT) {
    throw new Error(`${op} text is too long: ${text.length} chars (cap ${MAX_FUN_TEXT})`);
  }
  return text;
}

function requireHttpUrl(args) {
  const raw = typeof args.url === 'string' ? args.url.trim() : '';
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('openurl requires a valid http(s) URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('openurl accepts http(s):// URLs only');
  }
  return url.href;
}

function requireVolume(args) {
  const level = Number(args.level);
  if (!Number.isInteger(level) || level < 0 || level > 100) {
    throw new Error('volume requires an integer from 0 to 100');
  }
  return level;
}

function powershell(runtime, script, ...args) {
  execute(runtime, 'powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script, ...args]);
}

function encoded(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

function openUrl(url, runtime) {
  if (runtime.platform === 'darwin') execute(runtime, 'open', [url]);
  else if (runtime.platform === 'linux') execute(runtime, 'xdg-open', [url]);
  else if (runtime.platform === 'win32') execute(runtime, 'rundll32.exe', ['url.dll,FileProtocolHandler', url]);
  else throw new Error(`openurl is not supported on ${runtime.platform}`);
}

function openRickroll(runtime) {
  if (runtime.platform === 'win32') powershell(runtime, PS_OPEN_MAXIMIZED, RICKROLL_URL);
  else openUrl(RICKROLL_URL, runtime);
}

function unmute(runtime) {
  if (runtime.platform === 'darwin') {
    execute(runtime, 'osascript', ['-e', 'set volume output muted false']);
  } else if (runtime.platform === 'linux') {
    executeFirst(runtime, [
      ['wpctl', ['set-mute', '@DEFAULT_AUDIO_SINK@', '0']],
      ['pactl', ['set-sink-mute', '@DEFAULT_SINK@', '0']],
      ['amixer', ['sset', 'Master', 'unmute']],
    ], 'volume unmute');
  } else if (runtime.platform === 'win32') powershell(runtime, PS_UNMUTE);
  else throw new Error(`volume unmute is not supported on ${runtime.platform}`);
}

function say(text, runtime) {
  if (runtime.platform === 'darwin') execute(runtime, 'say', [text]);
  else if (runtime.platform === 'linux') {
    executeFirst(runtime, [['spd-say', [text]], ['espeak', [text]]], 'text-to-speech');
  } else if (runtime.platform === 'win32') powershell(runtime, PS_SAY, encoded(text));
  else throw new Error(`say is not supported on ${runtime.platform}`);
}

function notify(text, runtime) {
  if (runtime.platform === 'darwin') {
    execute(runtime, 'osascript', [
      '-e', 'on run argv',
      '-e', 'display notification (item 1 of argv) with title "KC2"',
      '-e', 'end run',
      '--', text,
    ]);
  } else if (runtime.platform === 'linux') execute(runtime, 'notify-send', ['KC2', text]);
  else if (runtime.platform === 'win32') powershell(runtime, PS_NOTIFY, encoded(text));
  else throw new Error(`notify is not supported on ${runtime.platform}`);
}

function beep(runtime) {
  if (runtime.platform === 'darwin') execute(runtime, 'afplay', [MAC_SOUND]);
  else if (runtime.platform === 'linux') {
    try {
      executeFirst(runtime, [
        ['paplay', ['/usr/share/sounds/freedesktop/stereo/message.oga']],
        ['canberra-gtk-play', ['-i', 'message']],
        ['beep', []],
      ], 'system sound');
    } catch {
      runtime.writeBell('\u0007');
    }
  } else if (runtime.platform === 'win32') powershell(runtime, PS_BEEP);
  else throw new Error(`beep is not supported on ${runtime.platform}`);
}

function bounce(runtime) {
  if (runtime.platform === 'darwin') {
    execute(runtime, 'osascript', [
      '-l', 'JavaScript',
      '-e', 'ObjC.import("AppKit"); $.NSApplication.sharedApplication.requestUserAttention(0); $.NSThread.sleepForTimeInterval(1);',
    ]);
  } else if (runtime.platform === 'linux') {
    execute(runtime, 'notify-send', ['-u', 'critical', '-t', '2500', 'KC2', 'Bounce!']);
  } else if (runtime.platform === 'win32') powershell(runtime, PS_BOUNCE);
  else throw new Error(`bounce is not supported on ${runtime.platform}`);
}

function setVolume(level, runtime) {
  if (runtime.platform === 'darwin') {
    execute(runtime, 'osascript', [
      '-e', 'on run argv',
      '-e', 'set volume output volume (item 1 of argv as integer)',
      '-e', 'end run',
      '--', String(level),
    ]);
  } else if (runtime.platform === 'linux') {
    executeFirst(runtime, [
      ['wpctl', ['set-volume', '@DEFAULT_AUDIO_SINK@', (level / 100).toFixed(2)]],
      ['pactl', ['set-sink-volume', '@DEFAULT_SINK@', `${level}%`]],
      ['amixer', ['sset', 'Master', `${level}%`]],
    ], 'volume control');
  } else if (runtime.platform === 'win32') powershell(runtime, PS_VOLUME, String(level));
  else throw new Error(`volume is not supported on ${runtime.platform}`);
}

/** Run one fun task and return its user-facing result text. */
export function runFunTask(op, args = {}, options = {}) {
  const runtime = runtimeFrom(options);
  switch (op) {
    case 'openurl': {
      const url = requireHttpUrl(args);
      openUrl(url, runtime);
      return `opened ${url}`;
    }
    case 'say': {
      const text = requireText(args, op);
      say(text, runtime);
      return `spoke ${text.length} chars`;
    }
    case 'notify':
      notify(requireText(args, op), runtime);
      return 'notification displayed';
    case 'beep':
      beep(runtime);
      return 'played system sound';
    case 'bounce':
      bounce(runtime);
      return 'requested desktop attention';
    case 'volume': {
      const level = requireVolume(args);
      setVolume(level, runtime);
      return `volume set to ${level}`;
    }
    case 'rickroll':
      unmute(runtime);
      setVolume(100, runtime);
      openRickroll(runtime);
      return 'volume set to 100 and rickroll opened';
    case 'party':
      beep(runtime);
      notify('hello from the lab', runtime);
      openUrl(RICKROLL_URL, runtime);
      return 'party started';
    default:
      throw new Error(`unknown fun op "${op}"`);
  }
}
