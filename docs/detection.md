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
- **User-Agent Anomalies**: KC2 sets `KC2/1.0 (educational research)` rather than an official npm CLI User-Agent. More generally, custom Node.js clients that call registry metadata APIs directly are worth correlating with process and package context.
- **Periodic Polling**: Repeated HTTP `GET` requests targeting `/-/package/*/dist-tags` from developer workstations or build agents. KC2 sleeps for the configured interval after a successful cycle and exponentially backs off failed cycles, so the observed cadence is near-periodic rather than perfectly fixed.

### 3. Host / Endpoint Artifacts
- **State Files**: Creation of JSON state tracking files on disk (e.g. `victim-state.json` or `attacker-state.json`) recording sequence numbers (`lastSeq`, `nextSeq`) and generated agent identifiers (`agentId`).
- **Unusual Node Process Activity**: Long-running background `node` processes executing polling loops against external npm registry HTTP APIs without interactive developer invocation.

### 4. WiFi Positioning (Geolocation) Task Artifacts
- **WiFi Scan Tool Invocations**: A non-system process (e.g. `node`) spawning WiFi survey utilities — `airport -s` or `system_profiler SPAirPortDataType` (macOS), `nmcli ... dev wifi list` (Linux), `netsh wlan show networks mode=bssid` (Windows). Interactive users rarely script these; implants run them to harvest BSSIDs.
- **WPS Database Lookups**: Outbound HTTPS `POST` requests made by `curl` with a `wifiAccessPoints`/`macAddress` JSON body. The example configuration uses `api.beacondb.net/v1/geolocate`; another configured MLS/Google-compatible endpoint or a loopback mock may be used instead.
- **Result Tags Containing Coordinates**: `x-res-*` tag payloads whose decoded JSON `output` string contains `location: lat=... lng=... accuracyM=...` and a `service:` host line.

---

## Behavioral Detections

### Detection 1: High Tag Churn on Immutable Package Version
- **Logic**: Monitor registry audit logs or API telemetry for `PUT` and `DELETE` requests targeting `/-/package/<pkg>/dist-tags/*`. Alert when the ratio of dist-tag modification events to package version publish events exceeds threshold (e.g., > 10 tag updates per version).

### Detection 2: Non-semver Tag Name Pattern Analysis
- **Logic**: Standard npm dist-tags follow simple identifiers (`latest`, `canary`, `v1.x`, `dev`). Tag names containing base64url character sets, hyphen-delimited sequence numbers, or sentinel prefixes (`x-cmd-`, `x-res-`, `x-ann-`) should trigger detection alerts.

### Detection 3: Polling Beacon Detection (Network Flow)
- **Logic**: Compute time deltas between consecutive `GET /-/package/<pkg>/dist-tags` requests per source and package. Alert on sustained, near-periodic access while allowing for request latency and exponential backoff after failures.

### Detection 4: WiFi Geolocation (Host + Network Correlation)
- **Logic**: Alert when a process that is not a location-enabled system service invokes a WiFi survey tool and then, within a short window, launches `curl` to POST to a WPS endpoint. Either leg alone is a weak signal; their correlation is stronger.
- **Endpoint note (macOS)**: BSSID visibility can depend on Location Services permissions. Correlate unexpected permission prompts or grants for the launching terminal/process with the scan and network activity.

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
  [network where http.request.method == "GET" and url.path like "*/-/package/*/dist-tags" and not process.name in ("npm", "yarn", "pnpm")]
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
        c-uri|re: '/-/package/.+/dist-tags'
    selection_useragent:
        c-user-agent|contains:
            - 'KC2/1.0 (educational research)'
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

#### Command Tag Pattern (single or chunked)
```regex
^x-cmd-[A-Za-z0-9_]{1,64}-[0-9]+-(?:[0-9]+of[0-9]+-)?[A-Za-z0-9_-]+$
```

#### Result Tag Pattern (`x-res-<agentId>-<seq>-<chunk>of<total>-<base64url>`)
```regex
^x-res-[A-Za-z0-9_]{1,64}-[0-9]+-[0-9]+of[0-9]+-[A-Za-z0-9_-]+$
```

#### Announce Tag Pattern (`x-ann-<agentId>-<base64url>`)
```regex
^x-ann-[A-Za-z0-9_]{1,64}-[A-Za-z0-9_-]+$
```

### YARA Rule (Memory or Decrypted Log Scanning)
```yara
rule Suspicious_npm_dist_tag_C2 {
    meta:
        description = "Detects npm dist-tag covert protocol tag names in memory or logs"
        author = "KC2"
        severity = "High"
    strings:
        $cmd_tag = /x-cmd-[A-Za-z0-9_]{1,64}-[0-9]+-(?:[0-9]+of[0-9]+-)?[A-Za-z0-9_-]{10,}/
        $res_tag = /x-res-[A-Za-z0-9_]{1,64}-[0-9]+-[0-9]+of[0-9]+-[A-Za-z0-9_-]{10,}/
        $ann_tag = /x-ann-[A-Za-z0-9_]{1,64}-[A-Za-z0-9_-]{10,}/
    condition:
        any of them
}
```
