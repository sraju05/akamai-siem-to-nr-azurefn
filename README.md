# Akamai SIEM → New Relic Forwarder · Azure Function

![Azure Functions](https://img.shields.io/badge/Azure_Functions-v4-0078D4?logo=azurefunctions&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![Akamai](https://img.shields.io/badge/Akamai-SIEM_API-009BDE?logo=akamai&logoColor=white)
![New Relic](https://img.shields.io/badge/New_Relic-Logs_API-1CE783?logo=newrelic&logoColor=black)

An **Azure Function (timer trigger)** that continuously polls the Akamai SIEM Integration API, optionally filters or truncates event fields, and forwards batches to the New Relic Logs API.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Why New Relic Logs API](#why-new-relic-logs-api)
4. [Project Structure](#project-structure)
5. [Prerequisites](#prerequisites)
6. [Configuration Reference](#configuration-reference)
7. [Payload Filtering](#payload-filtering)
8. [Akamai SIEM API Primer](#akamai-siem-api-primer)
9. [Offset and State Management](#offset-and-state-management)
10. [Batching and Limits](#batching-and-limits)
11. [Retry Behavior](#retry-behavior)
12. [Local Development](#local-development)
13. [Deploying to Azure](#deploying-to-azure)
14. [Monitoring and Observability](#monitoring-and-observability)
15. [Querying Events in New Relic](#querying-events-in-new-relic)
16. [Troubleshooting](#troubleshooting)
17. [Known Limitations](#known-limitations)

---

## Overview

Akamai's SIEM Integration API exposes a stream of security events (WAF triggers, DDoS detections, bot detections, rate-limiting hits, etc.) as newline-delimited JSON (NDJSON). This function:

1. Runs on a **60-second timer**.
2. Reads the last-processed **offset** from Azure Blob Storage so no events are replayed or lost across restarts.
3. Fetches up to 600 events per execution from the Akamai SIEM v1 API.
4. Applies optional **drop** and **truncate** filters to the raw payload.
5. Forwards filtered events to the **New Relic Logs API** in gzip-compressed batches.
6. Saves the new offset back to blob storage before exiting.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Azure Function                         │
│                                                              │
│  Timer (60s)                                                 │
│      │                                                       │
│      ▼                                                       │
│  Load offset ◄──── Azure Blob Storage                       │
│  (akamai-siem-state/offset-<configIds>.txt)                  │
│      │                                                       │
│      ▼                                                       │
│  Akamai SIEM API ─── EdgeGrid Auth ───► GET /siem/v1/configs │
│      │               (HMAC-SHA256)                           │
│      │   NDJSON response                                     │
│      ▼                                                       │
│  Parse events + extract new offset                           │
│      │                                                       │
│      ▼                                                       │
│  payload_filter.py                                           │
│  ┌─────────────────────────────────┐                         │
│  │  Drop fields  (FILTER_DROP_*)   │                         │
│  │  Truncate fields (FILTER_TRUNC*)│                         │
│  └─────────────────────────────────┘                         │
│      │                                                       │
│      ▼                                                       │
│  Batch (≤500 events or ≤900 KB)                             │
│      │                                                       │
│      ▼                                                       │
│  New Relic Logs API ──── gzip + Api-Key ──► 202 Accepted    │
│      │                                                       │
│      ▼                                                       │
│  Save new offset ──────► Azure Blob Storage                  │
└──────────────────────────────────────────────────────────────┘
```

---

## Why New Relic Logs API

The New Relic platform offers two ingest endpoints for custom data: the **Logs API** and the **Events API**. This function uses the Logs API for the following reasons:

| Criterion | Logs API | Events API |
|---|---|---|
| Attribute count limit | None | 255 per event |
| Attribute value size limit | 250 KB per log line | 4 KB per attribute |
| Typical Akamai event size | Several KB (headers, rules) | Exceeds Events API limits |
| Ingest volume | Designed for high throughput | Better for low-volume metrics |
| NR UI / alerting | Log management UI, patterns, parsing | Insights / dashboards |
| Security investigation | Logs query, LiveTail | Less suited |
| Compression support | gzip accepted | No compression |

Akamai SIEM events regularly contain raw HTTP request/response headers and long rule sets that exceed the Events API's per-attribute 4 KB cap. The Logs API handles these without truncation (unless you configure it yourself — see [Payload Filtering](#payload-filtering)).

---

## Project Structure

```
akamai-siem-forwarder/
├── function_app.py       # Function entry point, Akamai client, NR Logs client,
│                         # offset persistence, batching, retry logic
├── payload_filter.py     # Drop and truncate filter logic (dot-notation paths)
├── requirements.txt      # Python dependencies
├── host.json             # Azure Functions host configuration
└── local.settings.json   # Local dev config template — DO NOT COMMIT with secrets
```

---

## Prerequisites

### Tooling

| Tool | Version | Notes |
|---|---|---|
| Python | 3.11+ | `str \| None` union syntax requires ≥ 3.10 |
| Azure Functions Core Tools | v4 | `npm i -g azure-functions-core-tools@4` |
| Azure CLI | Any recent | For deployment |
| Azurite (optional) | v3 | Local blob storage emulator for dev |

### Azure resources

- **Azure Function App** — Consumption, Premium, or Dedicated plan (Python 3.11 stack)
- **Azure Storage Account** — Used by the Functions runtime (`AzureWebJobsStorage`) and for offset persistence. The container `akamai-siem-state` is created automatically on first run.

### Akamai

- An active **Akamai Security Configuration** with SIEM Integration enabled.
- An **Akamai OPEN API client** (client token, client secret, access token, host) with the `SIEM` grant. Generate credentials at **Luna Control Center → API Clients**.
- The numeric **Config ID(s)** of the security configurations you want to stream. Multiple IDs can be comma-separated.

### New Relic

- A **New Relic License Key** (ingest key) — found at **Account Settings → API Keys → License key**. This key is sent as the `Api-Key` header and authorises ingest.
- Confirm the correct regional endpoint:
  - US: `https://log-api.newrelic.com/log/v1`
  - EU: `https://log-api.eu.newrelic.com/log/v1`

---

## Configuration Reference

All configuration is via environment variables. In production these live in **Azure Function App → Configuration → Application settings**. For local development, put them in `local.settings.json`.

### Akamai settings

| Variable | Required | Default | Description |
|---|---|---|---|
| `AKAMAI_HOST` | Yes | — | Your Akamai EdgeGrid hostname, e.g. `akab-xxxx.luna.akamaiapis.net` |
| `AKAMAI_CLIENT_TOKEN` | Yes | — | EdgeGrid client token (`cliend_token` field from `.edgerc`) |
| `AKAMAI_CLIENT_SECRET` | Yes | — | EdgeGrid client secret |
| `AKAMAI_ACCESS_TOKEN` | Yes | — | EdgeGrid access token |
| `AKAMAI_CONFIG_IDS` | Yes | — | Security configuration ID(s). Single: `12345`. Multiple: `12345,67890` |
| `AKAMAI_BATCH_SIZE` | No | `600` | Events to request per API call. Maximum allowed by Akamai is `600`. |

### New Relic settings

| Variable | Required | Default | Description |
|---|---|---|---|
| `NR_LICENSE_KEY` | Yes | — | New Relic ingest (license) key |
| `NR_LOGS_ENDPOINT` | No | `https://log-api.newrelic.com/log/v1` | US endpoint. Change to EU endpoint if your NR account is in the EU data centre |
| `NR_BATCH_SIZE` | No | `500` | Maximum number of log entries per POST to New Relic. A batch is also flushed early if it reaches 900 KB uncompressed. |

### Azure infrastructure

| Variable | Required | Default | Description |
|---|---|---|---|
| `AzureWebJobsStorage` | Yes | — | Azure Storage connection string. Set to `UseDevelopmentStorage=true` locally when using Azurite. |

### Filter settings

| Variable | Required | Default | Description |
|---|---|---|---|
| `FILTER_DROP_FIELDS` | No | `""` (none) | Comma-separated list of field paths to remove entirely from each event before forwarding. |
| `FILTER_TRUNCATE_FIELDS` | No | `{}` (none) | Fields to cap at a maximum character length. Accepts JSON or simple `field:length` format. See [Payload Filtering](#payload-filtering). |

### Timer schedule

The schedule is hardcoded to `"0 */1 * * * *"` (every 60 seconds) in `function_app.py`. To change it without modifying code, override via `WEBSITE_OVERRIDE_STICKY_EXTENSION_VERSIONS` or simply edit the `schedule` parameter in `function_app.py`.

---

## Payload Filtering

Filtering is applied **before** data is sent to New Relic. The raw Akamai event is deep-copied before mutation — the original is never modified.

### Drop fields

Completely removes a field from the event. Useful for fields that are irrelevant to your use case, contain sensitive PII, or inflate ingest costs.

Set `FILTER_DROP_FIELDS` to a comma-separated list of dot-notation paths:

```
FILTER_DROP_FIELDS=geo,httpMessage.requestHeaders,httpMessage.responseHeaders
```

This example removes:
- The entire `geo` object (country, city, ASN, etc.)
- The raw request headers string from `httpMessage`
- The raw response headers string from `httpMessage`

### Truncate fields

Caps a string field at a maximum character length. The field is replaced with the truncated string plus a `…[truncated]` suffix so analysts know data was cut.

`FILTER_TRUNCATE_FIELDS` accepts two formats:

**JSON format** (recommended for complex configurations):
```json
{
  "httpMessage.requestHeaders": 512,
  "httpMessage.responseHeaders": 512,
  "attackData.rules": 1024
}
```

Set as an environment variable (must be a single-line string with escaped quotes or use Azure portal):
```
FILTER_TRUNCATE_FIELDS={"httpMessage.requestHeaders": 512, "httpMessage.responseHeaders": 512}
```

**Simple format** (easier to type in CLI or CI pipelines):
```
FILTER_TRUNCATE_FIELDS=httpMessage.requestHeaders:512,httpMessage.responseHeaders:512,attackData.rules:1024
```

Both formats are parsed identically at startup.

### Dot-notation path resolution

Paths are resolved recursively. For example, `httpMessage.requestHeaders` maps to:
```json
{
  "httpMessage": {
    "requestHeaders": "..."   ← this field is targeted
  }
}
```

Paths that do not exist in a given event are silently ignored. Only string values are truncated; integer/boolean/object values are left untouched even if a truncate rule targets them.

### Common field reference for Akamai SIEM events

The table below lists the most frequently filtered fields and their typical sizes:

| Field path | Typical size | Notes |
|---|---|---|
| `httpMessage.requestHeaders` | 0.5–5 KB | Raw HTTP headers; often truncated or dropped |
| `httpMessage.responseHeaders` | 0.2–2 KB | Raw HTTP headers |
| `attackData.rules` | 1–10 KB | Triggered WAF rule details; large for multi-rule events |
| `attackData.ruleMessages` | 0.5–5 KB | Human-readable rule messages |
| `attackData.ruleData` | 0.5–3 KB | Matched data strings |
| `geo` | ~200 B | Country, city, region, ASN. Drop if not needed |
| `userRiskData` | ~100 B | Bot/user risk scores |

---

## Akamai SIEM API Primer

### Endpoint

```
GET https://{AKAMAI_HOST}/siem/v1/configs/{configIds}
```

Query parameters:

| Parameter | Description |
|---|---|
| `limit` | Number of events to return. Maximum: `600`. |
| `offset` | Opaque cursor string from the previous response. Omit on first call to start from the earliest available event. |

### Authentication

Uses **Akamai EdgeGrid** — a custom HMAC-SHA256 scheme that signs the request URL, headers, and body. The `akamai-edgegrid` Python package handles this transparently via a `requests.auth` adapter.

### Response format (NDJSON)

Each line is a complete JSON object. Event lines contain security event data. The **final line** is a summary object used to advance the offset cursor:

```
{"type":"akamai_siem","version":"1.0","attackData":{...},"httpMessage":{...},"geo":{...}}
{"type":"akamai_siem","version":"1.0","attackData":{...},"httpMessage":{...},"geo":{...}}
{"total":42,"offset":"3b4a9f...","limit":600,"count":42}
```

The function identifies the summary line by the presence of both `"total"` and `"offset"` keys. All other lines are treated as events.

### Typical event structure

```json
{
  "type": "akamai_siem",
  "format": "json",
  "version": "1.0",
  "attackData": {
    "configId": "12345",
    "policyId": "pol_001",
    "clientIP": "203.0.113.42",
    "rules": "950001 950002",
    "ruleMessages": "SQL Injection Attack; XSS Attack",
    "ruleData": "UNION SELECT; <script>",
    "ruleSelectors": "ARGS; ARGS",
    "ruleTags": "OWASP_CRS/WEB_ATTACK/SQL_INJECTION; ...",
    "ruleVersions": "1; 1",
    "apiId": "",
    "apiKey": "",
    "slowPostAction": ""
  },
  "httpMessage": {
    "requestId": "a1b2c3d4",
    "start": "1727740800",
    "protocol": "HTTP/2.0",
    "method": "POST",
    "host": "api.example.com",
    "port": "443",
    "path": "/api/v1/users",
    "query": "debug=true",
    "requestHeaders": "User-Agent: Mozilla/5.0...\r\nContent-Type: application/json\r\n...",
    "requestBody": "",
    "status": "403",
    "bytes": "512",
    "responseHeaders": "Content-Type: application/json\r\nX-Cache: Miss\r\n..."
  },
  "geo": {
    "country": "CN",
    "city": "Shanghai",
    "regionCode": "SH",
    "continent": "AS",
    "asn": "4134"
  },
  "userRiskData": {
    "allow": "0",
    "risk": "85",
    "score": "92",
    "status": "3",
    "uuid": "uuid-value"
  }
}
```

---

## Offset and State Management

### How offsets work

The Akamai SIEM API is **cursor-based**, not time-based. Each response includes an opaque `offset` string in the summary line. Passing this back on the next request tells the API to return only events that occurred after the last batch.

Without offset tracking, every function execution would re-fetch events from the beginning of the retention window — typically 12 hours.

### Storage location

The current offset is stored as plain text in Azure Blob Storage:

```
Container : akamai-siem-state
Blob name : offset-{AKAMAI_CONFIG_IDS}.txt
             e.g. offset-12345.txt
                  offset-12345-67890.txt  (multiple config IDs)
```

The container is created automatically if it does not exist. The function uses the same `AzureWebJobsStorage` connection string that the Functions runtime already requires, so no extra storage account is needed.

### First run behaviour

If the offset blob does not exist (first deployment, or after manual deletion), `_load_offset()` returns `None`. The API call is made without an `offset` parameter, and Akamai returns events from the **earliest point in its retention window** (typically the last 12 hours).

### Offset safety

The offset is only written **after** a successful New Relic ingest call. If the function crashes or New Relic is unreachable, the offset is not advanced and the same events will be re-fetched and re-sent on the next invocation. This means events can be **delivered at least once** — not exactly once — in failure scenarios. Deduplication at query time in New Relic can be done using `attackData.requestId` or `httpMessage.requestId`.

### Resetting the offset

To replay all available events from scratch, delete the offset blob:

```bash
az storage blob delete \
  --account-name <storage-account> \
  --container-name akamai-siem-state \
  --name offset-<configIds>.txt
```

---

## Batching and Limits

### New Relic Logs API limits

| Limit | Value |
|---|---|
| Maximum payload per request | 1 MB (after decompression) |
| Maximum single log line | 250 KB |
| Compression | gzip supported and recommended |
| Rate limit | ~100 requests/minute per account (approximate) |

### How batching works

Events are accumulated into a batch. A batch is flushed to New Relic when **either** condition is met:

1. The batch reaches `NR_BATCH_SIZE` entries (default: 500).
2. The estimated uncompressed size of the batch reaches 900 KB (100 KB headroom below the 1 MB limit).

The 900 KB threshold is applied to the pre-compression size. Actual compressed payloads will be substantially smaller (gzip typically achieves 5–10× compression on JSON).

### New Relic Logs API payload structure

Each POST body is a JSON array with a single element containing common attributes and the log entries:

```json
[
  {
    "common": {
      "attributes": {
        "logtype":     "akamai-siem",
        "source":      "akamai",
        "forwardedBy": "azure-function"
      }
    },
    "logs": [
      {
        "timestamp":  1727740800000,
        "message":    "POST api.example.com/api/v1/users → 403",
        "attributes": { ...full Akamai event... }
      }
    ]
  }
]
```

The `message` field is synthesised from `httpMessage.method`, `httpMessage.host`, `httpMessage.path`, and `httpMessage.status`. For non-HTTP event types (DDoS, bot), the first 200 characters of the raw JSON are used.

The `timestamp` is derived from `httpMessage.start` (Unix epoch seconds, converted to milliseconds). If the field is absent, the current wall-clock time is used.

---

## Retry Behavior

### New Relic POST retries

`_post_with_retry()` makes up to **3 attempts** with the following strategy:

| Scenario | Behaviour |
|---|---|
| HTTP 200 or 202 | Success — return immediately |
| HTTP 429 (rate limited) | Wait `5 × 2^attempt` seconds (5s, 10s, 20s), then retry |
| HTTP 4xx (other) | Non-retryable — raise immediately |
| Network / timeout error | Wait `2^attempt` seconds (1s, 2s), then retry |
| All retries exhausted | Raise `RuntimeError` — function execution fails |

When the function execution fails, the Azure Functions runtime will log the exception. The offset is **not** saved, so the same events will be retried on the next timer tick.

### Akamai API

No automatic retry is implemented for the Akamai API call. A network failure there will cause the function execution to fail, the offset not to advance, and the same events to be fetched on the next tick.

---

## Local Development

### 1. Install dependencies

```bash
cd akamai-siem-forwarder
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start Azurite (local blob storage)

```bash
# Install once
npm install -g azurite

# Run
azurite --silent --location /tmp/azurite --debug /tmp/azurite/debug.log
```

Leave this running in a separate terminal.

### 3. Fill in local.settings.json

Copy the template and fill in your credentials:

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "python",

    "AKAMAI_HOST":           "akab-xxxx.luna.akamaiapis.net",
    "AKAMAI_CLIENT_TOKEN":   "akab-client-token-xxx",
    "AKAMAI_CLIENT_SECRET":  "secret",
    "AKAMAI_ACCESS_TOKEN":   "akab-access-token-xxx",
    "AKAMAI_CONFIG_IDS":     "12345",
    "AKAMAI_BATCH_SIZE":     "600",

    "NR_LICENSE_KEY":        "your-40-char-license-key",
    "NR_LOGS_ENDPOINT":      "https://log-api.newrelic.com/log/v1",
    "NR_BATCH_SIZE":         "500",

    "FILTER_DROP_FIELDS":    "geo",
    "FILTER_TRUNCATE_FIELDS": "{\"httpMessage.requestHeaders\": 512}"
  }
}
```

> **Never commit `local.settings.json` to source control.** Add it to `.gitignore`.

### 4. Run the function locally

```bash
func start
```

The function will fire immediately on startup (`run_on_startup=True`) and then every 60 seconds. Check the terminal for log output like:

```
[2026-10-01T10:00:00] Pulling Akamai SIEM | configIds=12345 offset=initial
[2026-10-01T10:00:01] Fetched 42 events; applying filters (drop=['geo'] truncate=['httpMessage.requestHeaders'])
[2026-10-01T10:00:02] Done | forwarded=42 newOffset=3b4a9f...
```

---

## Deploying to Azure

### Option A — Azure CLI (zip deploy)

```bash
# 1. Create a resource group (skip if reusing an existing one)
az group create --name rg-akamai-siem --location eastus

# 2. Create a storage account
az storage account create \
  --name stakamaisiem001 \
  --resource-group rg-akamai-siem \
  --sku Standard_LRS

# 3. Create the Function App (Python 3.11, Consumption plan)
az functionapp create \
  --resource-group rg-akamai-siem \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name func-akamai-siem-nr \
  --storage-account stakamaisiem001

# 4. Deploy the code
func azure functionapp publish func-akamai-siem-nr

# 5. Set application settings (secrets — do NOT pass via command history in prod; use Key Vault)
az functionapp config appsettings set \
  --name func-akamai-siem-nr \
  --resource-group rg-akamai-siem \
  --settings \
    AKAMAI_HOST="akab-xxxx.luna.akamaiapis.net" \
    AKAMAI_CLIENT_TOKEN="akab-client-token-xxx" \
    AKAMAI_CLIENT_SECRET="your-secret" \
    AKAMAI_ACCESS_TOKEN="akab-access-token-xxx" \
    AKAMAI_CONFIG_IDS="12345" \
    NR_LICENSE_KEY="your-license-key" \
    FILTER_DROP_FIELDS="geo" \
    "FILTER_TRUNCATE_FIELDS={\"httpMessage.requestHeaders\": 512}"
```

### Option B — Azure Key Vault references (recommended for production)

Rather than storing secrets as plaintext application settings, store them in Key Vault and reference them:

```bash
# Store a secret
az keyvault secret set \
  --vault-name kv-akamai-siem \
  --name AkamaiClientSecret \
  --value "your-secret"

# Grant the Function App's managed identity access to Key Vault
az functionapp identity assign \
  --name func-akamai-siem-nr \
  --resource-group rg-akamai-siem

PRINCIPAL_ID=$(az functionapp identity show \
  --name func-akamai-siem-nr \
  --resource-group rg-akamai-siem \
  --query principalId -o tsv)

az keyvault set-policy \
  --name kv-akamai-siem \
  --object-id $PRINCIPAL_ID \
  --secret-permissions get list

# Reference the secret in the app setting
az functionapp config appsettings set \
  --name func-akamai-siem-nr \
  --resource-group rg-akamai-siem \
  --settings \
    AKAMAI_CLIENT_SECRET="@Microsoft.KeyVault(SecretUri=https://kv-akamai-siem.vault.azure.net/secrets/AkamaiClientSecret/)"
```

### Option C — GitHub Actions CI/CD

A minimal workflow (`.github/workflows/deploy.yml`):

```yaml
name: Deploy Akamai SIEM Forwarder

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -r requirements.txt --target=".python_packages/lib/site-packages"

      - name: Deploy to Azure Functions
        uses: Azure/functions-action@v1
        with:
          app-name: func-akamai-siem-nr
          publish-profile: ${{ secrets.AZURE_FUNCTIONAPP_PUBLISH_PROFILE }}
```

---

## Monitoring and Observability

### Application Insights

If the Function App is linked to an Application Insights instance (recommended), all `logging.*` calls are automatically captured. Key log messages emitted at each execution:

| Level | Message pattern | Meaning |
|---|---|---|
| `INFO` | `Pulling Akamai SIEM \| configIds=... offset=...` | Execution started |
| `INFO` | `Fetched N events; applying filters ...` | Events received from Akamai |
| `INFO` | `No new events from Akamai` | API returned 0 events (quiet period) |
| `INFO` | `Done \| forwarded=N newOffset=...` | Execution completed successfully |
| `WARNING` | `Timer is past due` | Previous execution ran long; consider increasing timeout or reducing batch size |
| `WARNING` | `New Relic rate-limited (429); retrying in Xs` | Transient NR rate limit hit |
| `WARNING` | `New Relic request failed (attempt N/3): ...` | Transient network failure, will retry |
| `ERROR` | `New Relic rejected batch: 4xx ...` | Permanent failure; check license key and endpoint |

### Useful KQL queries (Application Insights)

Events forwarded per execution:
```kql
traces
| where message has "Done | forwarded="
| parse message with * "forwarded=" count " newOffset=" *
| project timestamp, count = toint(count)
| render timechart
```

Failed executions:
```kql
exceptions
| where outerMessage has "New Relic POST failed"
| project timestamp, outerMessage, innermostMessage
| order by timestamp desc
```

Average execution duration:
```kql
requests
| where name == "akamai_siem_forwarder"
| summarize avg(duration), percentile(duration, 95) by bin(timestamp, 5m)
| render timechart
```

---

## Querying Events in New Relic

All events arrive under `logtype = 'akamai-siem'`. Use **New Relic Query Language (NRQL)** or the **Logs UI** to explore them.

### Common NRQL queries

Events in the last hour by country:
```sql
SELECT count(*) FROM Log
WHERE logtype = 'akamai-siem'
SINCE 1 hour ago
FACET attributes.geo.country
```

Top attacking IPs:
```sql
SELECT count(*) FROM Log
WHERE logtype = 'akamai-siem'
SINCE 24 hours ago
FACET attributes.attackData.clientIP
LIMIT 20
```

WAF rule hits over time:
```sql
SELECT count(*) FROM Log
WHERE logtype = 'akamai-siem'
SINCE 1 hour ago
TIMESERIES 5 minutes
```

Events with a specific HTTP status:
```sql
SELECT * FROM Log
WHERE logtype = 'akamai-siem'
AND attributes.httpMessage.status = '403'
SINCE 1 hour ago
LIMIT 100
```

### Logs UI

Navigate to **New Relic → Logs** and filter with:
```
logtype:"akamai-siem"
```

Use **LiveTail** (`Logs → Live tail`) to watch events arrive in real time. Events typically appear within 30–90 seconds of the Akamai API returning them.

---

## Troubleshooting

### No events appearing in New Relic

1. **Check Application Insights** for exceptions or error-level log messages.
2. Verify `NR_LICENSE_KEY` is an **ingest key** (starts with the account ID prefix), not a user API key.
3. Verify `NR_LOGS_ENDPOINT` matches your NR account's data centre (US vs EU).
4. Check that the Function App's outbound IP is not blocked by a firewall rule on either Akamai or New Relic's side.

### `KeyError` on startup

A required environment variable is missing. The variables without defaults (`AKAMAI_HOST`, `AKAMAI_CLIENT_TOKEN`, `AKAMAI_CLIENT_SECRET`, `AKAMAI_ACCESS_TOKEN`, `AKAMAI_CONFIG_IDS`, `NR_LICENSE_KEY`) will raise `KeyError` at cold start if unset. Check **Function App → Configuration → Application settings**.

### Akamai returns HTTP 401

EdgeGrid credentials are invalid or expired. Regenerate the API client credentials in Akamai Luna Control Center and update the four `AKAMAI_*` settings.

### Akamai returns HTTP 403

The API client does not have the **SIEM** grant, or the `AKAMAI_CONFIG_IDS` value references a config that the client is not authorised to read.

### Akamai returns HTTP 404

`AKAMAI_CONFIG_IDS` contains an invalid or non-existent security configuration ID.

### Events are duplicated in New Relic

This is expected in crash/retry scenarios because the offset is only saved after a successful NR ingest (at-least-once delivery). Deduplicate using:

```sql
SELECT * FROM Log
WHERE logtype = 'akamai-siem'
SINCE 1 hour ago
```

The `attributes.httpMessage.requestId` field is unique per Akamai request and can be used as a deduplication key.

### Function execution exceeds timeout

The default `functionTimeout` in `host.json` is `00:05:00` (5 minutes). If you are processing a very large backlog on first run, the function may time out. Options:

- Increase `functionTimeout` in `host.json` (maximum 10 minutes on Consumption plan; unlimited on Premium/Dedicated).
- Reduce `AKAMAI_BATCH_SIZE` so each execution processes fewer events.
- After the initial backlog is cleared, normal 60-second executions will process at most 600 events, which typically completes in under 10 seconds.

### `FILTER_TRUNCATE_FIELDS` is not applying

Ensure the environment variable value is valid JSON if using the JSON format. Single-line only — newlines inside the JSON string will cause a parse error. Test with the simple `field:N` format first to isolate parsing issues.

---

## Known Limitations

| Limitation | Detail |
|---|---|
| At-least-once delivery | In failure scenarios, events may be sent to New Relic more than once. Exactly-once delivery would require a transactional offset commit that is not supported by Blob Storage. |
| IPv6 and non-HTTP events | The `message` field synthesis in `_to_log_entry()` is optimised for HTTP events. Non-HTTP events (DDoS, bot) use a truncated JSON string as the message. |
| Single-region | The function writes one offset blob per unique `AKAMAI_CONFIG_IDS` value. Running multiple instances targeting the same config IDs without coordination would cause duplicate ingest. Use Azure's singleton timer trigger pattern or a single instance. |
| No dead-letter queue | Events that permanently fail to ingest (e.g., single event exceeding 250 KB after filtering) will cause the entire batch to fail. Consider adding per-event error handling with a dead-letter blob container if this is a concern. |
| Akamai retention window | The SIEM API retains events for approximately 12 hours. If the function is stopped for longer than 12 hours, events from that window will be lost. |
| Filter config is static | `FILTER_DROP_FIELDS` and `FILTER_TRUNCATE_FIELDS` are read once at cold start. Changing them requires a function restart (which happens automatically on app setting changes in Azure). |
