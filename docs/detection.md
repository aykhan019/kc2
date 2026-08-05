# Detection Guide: npm dist-tag Indirect C2

## Overview & Threat Context

The indirect C2 mechanism over npm `dist-tags` abuses standard npm registry HTTP endpoints (`/-/package/<pkg>/dist-tags`) to transmit command-and-control messages. Because all network requests travel to a legitimate npm registry (or enterprise mirror) over HTTPS, traditional IP/domain blocklists will fail to detect or mitigate this activity.

However, because dist-tags are designed for semver environment aliases (e.g. `latest`, `beta`, `next`), abusing tag **names** for base64url payload transport leaves distinct, quantifiable anomalies across registry metadata, proxy/TLS traffic logs, and endpoint state.

---

## Indicators of Compromise (IoCs)

### 1. Registry & Metadata Artifacts
- **Non-semver Tag Names**: Package dist-tags beginning with sentinels like `x-cmd-`, `x-res-`, or `x-ann-`, or containing high-entropy base64url strings.
- **Single-Version Tag Churn**: Packages with a single immutable version (e.g. `1.0.0`) exhibiting high counts of added, modified, or deleted dist-tags without any corresponding `tarball` publishes or version increments.
- **Chunked Tag Multiplicity**: Presence of dist-tag names containing chunk index patterns such as `1of2`, `2of2`, `1of3`.

### 2. Network & Proxy IoCs
- **Target Endpoints**: Repeated `GET /-/package/<pkg>/dist-tags` (reads) or `PUT /-/package/<pkg>/dist-tags/<tag>` / `DELETE /-/package/<pkg>/dist-tags/<tag>` (writes).
- **User-Agent Anomalies**: HTTP requests to registry APIs originating from non-standard User-Agents (e.g., standard `node-fetch`, generic Node.js runtime, or custom agent strings rather than official `npm/<version> node/<version> <platform>`).
- **Periodic Beaconing**: Fixed-interval HTTP `GET` requests targeting `/-/package/*/dist-tags` from internal developer workstations or build agents.

### 3. Host / Endpoint Artifacts
- **State Files**: Creation of JSON state tracking files on disk (e.g. `victim-state.json` or `attacker-state.json`) recording sequence numbers (`lastSeq`, `nextSeq`) and generated agent identifiers (`agentId`).
- **Unusual Node Process Activity**: Long-running background `node` processes executing polling loops against external npm registry HTTP APIs without interactive developer invocation.

### 4. WiFi Positioning (Geolocation) Task Artifacts
- **WiFi Scan Tool Invocations**: A non-system process (e.g. `node`) spawning WiFi survey utilities — `airport -s` or `system_profiler SPAirPortDataType` (macOS), `nmcli ... dev wifi list` (Linux), `netsh wlan show networks mode=bssid` (Windows). Interactive users rarely script these; implants run them to harvest BSSIDs.
- **WPS Database Lookups**: Outbound HTTPS `POST` requests carrying a JSON body of `wifiAccessPoints`/`macAddress` entries to geolocation endpoints (`www.googleapis.com/geolocation`, `location.services.mozilla.com`, or similar) from a non-browser process. This is stage 2 of the WiFi positioning technique: BSSID list in, coordinates + accuracy out.
- **Result Tags Containing Coordinates**: `x-res-*` tag payloads that decode to `lat=`/`lng=`/`accuracyM=` fields.

### 5. Exfil-by-Reference (Cloud Upload) Task Artifacts
- **Anonymous File-Share Uploads**: Multipart `POST` requests (`curl -F file=@...`) from a non-browser process to public no-key file-sharing or paste services (`0x0.st`, `transfer.sh`, `tmpfiles.org`, `catbox.moe`, `litterbox.catbox.moe`, …). This is the "living off trusted sites" pattern: the payload rides a reputable domain, so domain reputation scoring alone will not catch it — process/service correlation will.
- **Screen Capture Followed by Upload**: A `screencapture`/`import`/virtual-screen read immediately followed by an outbound multipart POST of similar byte size is a high-confidence exfil sequence.
- **URL-Only Result Tags**: `x-res-*` payloads that decode to a bare `https://` link into a known file-sharing domain, where earlier results of the same op carried base64 file bytes.

### Detection 5: Screenshot Exfil Sequence (Host Correlation)
- **Logic**: Alert when a process (1) invokes a screen-capture binary and (2) within seconds initiates an outbound multipart upload to a file-sharing domain, or (3) the C2 channel result shrinks from chunked file bytes to a single URL-bearing tag. The upload destination being a "legitimate" service is the point of the technique; the *sequence* is the signal.

### Detection 4: WiFi Geolocation Beacon (Host + Network Correlation)
- **Logic**: Alert when a process that is not a location-enabled system service (1) invokes a WiFi survey tool and (2) within a short window makes an outbound POST to a known WPS endpoint. Either leg alone is a weak signal; the correlation is characteristic of implant-driven host geolocation.
- **Endpoint note (macOS)**: Modern macOS redacts BSSIDs unless the calling terminal holds Location Services permission — unexpected Location permission prompts for Terminal/iTerm are themselves an indicator worth surfacing in class demos.

---

## Behavioral Detections

### Detection 1: High Tag Churn on Immutable Package Version
- **Logic**: Monitor registry audit logs or API telemetry for `PUT` and `DELETE` requests targeting `/-/package/<pkg>/dist-tags/*`. Alert when the ratio of dist-tag modification events to package version publish events exceeds threshold (e.g., > 10 tag updates per version).

### Detection 2: Non-semver Tag Name Pattern Analysis
- **Logic**: Standard npm dist-tags follow simple identifiers (`latest`, `canary`, `v1.x`, `dev`). Tag names containing base64url character sets, hyphen-delimited sequence numbers, or sentinel prefixes (`x-cmd-`, `x-res-`, `x-ann-`) should trigger detection alerts.

### Detection 3: Polling Beacon Detection (Network Flow)
- **Logic**: Compute time delta between consecutive `GET /-/package/<pkg>/dist-tags` requests per source IP. A low variance in request intervals (e.g. polling every 5.0 seconds ± 0.2s) indicates automated C2 beaconing.

---

## Sample SIEM & Proxy Queries

### Splunk SPL (Web / Proxy Logs)
```spl
index=proxy sourcetype="access_combined" uri_path="*/-/package/*/dist-tags*"
| eval action=case(http_method=="GET", "POLL", http_method=="PUT", "WRITE_CMD_RES", http_method=="DELETE", "CLEANUP")
| stats count dc(uri_path) as unique_tags var(duration) as time_var by src_ip, user_agent, action
| where (action="POLL" AND count > 50) OR (action="WRITE_CMD_RES" AND unique_tags > 5)
```

### Elastic / Kibana (EQL - Endpoint & Network)
```eql
sequence by host.id with maxspan=1m
  [network where http.request.method == "GET" and http.request.body.content == "*dist-tags*" and not process.name in ("npm", "yarn", "pnpm")]
  [file where file.name == "*state.json" and event.action in ("creation", "modification")]
```

### SIGMA Rule (Generic HTTP Proxy Rule)
```yaml
title: Suspicious npm dist-tag Metadata Polling / C2 Activity
status: experimental
description: Detects abnormal GET/PUT requests to npm package dist-tags indicating covert C2 channel usage.
logsource:
    category: proxy
    product: webproxy
detection:
    selection_endpoint:
        c-uri|contains: '/-/package/'
        c-uri|endswith: '/dist-tags'
    selection_useragent:
        c-user-agent|contains:
            - 'node-fetch'
            - 'axios'
            - 'got'
            - 'undici'
    filter_official_npm:
        c-user-agent|startswith: 'npm/'
    condition: selection_endpoint and selection_useragent and not filter_official_npm
falsepositives:
    - Custom internal build scripts using fetch directly against internal verdaccio/nexus registries.
level: high
```

---

## YARA & Regular Expressions for Dist-Tag Names

### Tag Name Regexes

#### Command Tag Pattern (`x-cmd-<agentId>-<seq>-<base64url>`)
```regex
^x-cmd-[A-Za-z0-9_]{1,64}-[0-9]+-[A-Za-z0-9_-]+$
```

#### Result Tag Pattern (`x-res-<agentId>-<seq>-<chunk>of<total>-<base64url>`)
```regex
^x-res-[A-Za-z0-9_]{1,64}-[0-9]+-[0-9]+of[0-9]+-[A-Za-z0-9_-]+$
```

#### Announce Tag Pattern (`x-ann-<agentId>-<base64url>`)
```regex
^x-ann-[A-Za-z0-9_]{1,64}-[A-Za-z0-9_-]+$
```

### YARA Rule (Memory / Log / Network Packet Scanning)
```yara
rule Suspicious_npm_dist_tag_C2 {
    meta:
        description = "Detects npm dist-tag covert protocol tag names in memory or logs"
        author = "KC2"
        severity = "High"
    strings:
        $cmd_tag = /x-cmd-[A-Za-z0-9_]{1,64}-[0-9]+-[A-Za-z0-9_-]{10,}/
        $res_tag = /x-res-[A-Za-z0-9_]{1,64}-[0-9]+-[0-9]+of[0-9]+-[A-Za-z0-9_-]{10,}/
        $ann_tag = /x-ann-[A-Za-z0-9_]{1,64}-[A-Za-z0-9_-]{10,}/
    condition:
        any of them
}
```
