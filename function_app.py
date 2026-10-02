"""
Azure Function — Akamai SIEM → New Relic Logs forwarder.

Runs on a timer (default: every 60 s), pulls events from the Akamai SIEM API,
optionally filters/truncates fields, then forwards batches to the New Relic
Logs API (chosen over the Events API: no 255-attribute limit, no 4 KB value
cap, better fit for high-volume security telemetry).

Required env vars: see local.settings.json for the full list.
"""

import gzip
import json
import logging
import os
import time
from urllib.parse import urljoin

import azure.functions as func
import requests
from akamai.edgegrid import EdgeGridAuth
from azure.storage.blob import BlobServiceClient

from payload_filter import apply_filters, load_filter_config

logger = logging.getLogger(__name__)
app    = func.FunctionApp()

# ── Akamai ─────────────────────────────────────────────────────────────────────
AKAMAI_HOST          = os.environ["AKAMAI_HOST"]            # e.g. akab-xxxx.luna.akamaiapis.net
AKAMAI_CLIENT_TOKEN  = os.environ["AKAMAI_CLIENT_TOKEN"]
AKAMAI_CLIENT_SECRET = os.environ["AKAMAI_CLIENT_SECRET"]
AKAMAI_ACCESS_TOKEN  = os.environ["AKAMAI_ACCESS_TOKEN"]
AKAMAI_CONFIG_IDS    = os.environ["AKAMAI_CONFIG_IDS"]      # e.g. "12345" or "12345,67890"
AKAMAI_BATCH_SIZE    = int(os.environ.get("AKAMAI_BATCH_SIZE", "600"))  # max 600 per Akamai docs

# ── New Relic ──────────────────────────────────────────────────────────────────
NR_LICENSE_KEY   = os.environ["NR_LICENSE_KEY"]
NR_LOGS_ENDPOINT = os.environ.get("NR_LOGS_ENDPOINT", "https://log-api.newrelic.com/log/v1")
NR_BATCH_SIZE    = int(os.environ.get("NR_BATCH_SIZE", "500"))

# ── Offset persistence (Azure Blob Storage) ────────────────────────────────────
STORAGE_CONN_STR = os.environ["AzureWebJobsStorage"]
OFFSET_CONTAINER = "akamai-siem-state"
OFFSET_BLOB      = f"offset-{AKAMAI_CONFIG_IDS.replace(',', '-')}.txt"

# ── Filter config (loaded once at cold start) ──────────────────────────────────
DROP_FIELDS, TRUNCATE_FIELDS = load_filter_config()


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

@app.timer_trigger(
    schedule="0 */1 * * * *",   # every minute; adjust via FUNCTIONS_TIMER_SCHEDULE if needed
    arg_name="timer",
    run_on_startup=True,
    use_monitor=False,
)
def akamai_siem_forwarder(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logger.warning("Timer is past due — previous execution may have been slow")

    offset = _load_offset()
    logger.info("Pulling Akamai SIEM | configIds=%s offset=%s", AKAMAI_CONFIG_IDS, offset or "initial")

    events, new_offset = _fetch_akamai_events(offset)
    if not events:
        logger.info("No new events from Akamai")
        return

    logger.info("Fetched %d events; applying filters (drop=%s truncate=%s)",
                len(events), DROP_FIELDS, list(TRUNCATE_FIELDS.keys()))

    filtered = [apply_filters(e, DROP_FIELDS, TRUNCATE_FIELDS) for e in events]
    _send_to_newrelic(filtered)

    if new_offset:
        _save_offset(new_offset)

    logger.info("Done | forwarded=%d newOffset=%s", len(filtered), new_offset)


# ══════════════════════════════════════════════════════════════════════════════
# Akamai SIEM client
# ══════════════════════════════════════════════════════════════════════════════

def _fetch_akamai_events(offset: str | None) -> tuple[list[dict], str | None]:
    """
    Call the Akamai SIEM v1 API and parse the NDJSON response.

    The last line of the response is a summary object:
      {"total": N, "offset": "abc123", "limit": 600, "count": N}
    All other lines are individual security events.
    """
    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=AKAMAI_CLIENT_TOKEN,
        client_secret=AKAMAI_CLIENT_SECRET,
        access_token=AKAMAI_ACCESS_TOKEN,
    )
    params: dict = {"limit": AKAMAI_BATCH_SIZE}
    if offset:
        params["offset"] = offset

    url  = urljoin(f"https://{AKAMAI_HOST}", f"/siem/v1/configs/{AKAMAI_CONFIG_IDS}")
    resp = session.get(url, params=params, timeout=60)
    resp.raise_for_status()

    events: list[dict] = []
    new_offset: str | None = None

    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        # Summary line contains "offset" + "total"; event lines do not
        if "total" in obj and "offset" in obj:
            new_offset = obj.get("offset")
        else:
            events.append(obj)

    return events, new_offset


# ══════════════════════════════════════════════════════════════════════════════
# New Relic Logs API client
# ══════════════════════════════════════════════════════════════════════════════

_NR_MAX_PAYLOAD_BYTES = 900_000   # NR limit is 1 MB; keep headroom for envelope

_NR_HEADERS = {
    "Api-Key":          NR_LICENSE_KEY,
    "Content-Type":     "application/json",
    "Content-Encoding": "gzip",
}


def _send_to_newrelic(events: list[dict]) -> None:
    """Split events into size-bounded batches and flush each one."""
    batch: list[dict] = []
    batch_bytes = 0

    for event in events:
        entry      = _to_log_entry(event)
        entry_size = len(json.dumps(entry).encode())

        # Flush before adding if this entry would breach limits
        if batch and (len(batch) >= NR_BATCH_SIZE or batch_bytes + entry_size > _NR_MAX_PAYLOAD_BYTES):
            _flush_batch(batch)
            batch, batch_bytes = [], 0

        batch.append(entry)
        batch_bytes += entry_size

    if batch:
        _flush_batch(batch)


def _to_log_entry(event: dict) -> dict:
    """Convert an Akamai SIEM event to a New Relic log entry."""
    http = event.get("httpMessage") or {}

    # Timestamp: Akamai uses Unix epoch seconds in httpMessage.start
    ts_sec: int | None = None
    try:
        ts_sec = int(http.get("start", 0)) or None
    except (TypeError, ValueError):
        pass
    timestamp_ms = ts_sec * 1000 if ts_sec else int(time.time() * 1000)

    # Build a concise human-readable message for the NR log line
    method  = http.get("method", "")
    host    = http.get("host", "")
    path    = http.get("path", "")
    status  = http.get("status", "")
    if method:
        message = f"{method} {host}{path} → {status}"
    else:
        # Non-HTTP event types (DDoS, bot, etc.) — use a short JSON summary
        message = json.dumps(event)[:200]

    return {
        "timestamp":  timestamp_ms,
        "message":    message,
        "attributes": event,
    }


def _flush_batch(logs: list[dict]) -> None:
    """POST a batch of log entries to New Relic Logs API with retry."""
    payload = [
        {
            "common": {
                "attributes": {
                    "logtype":     "akamai-siem",
                    "source":      "akamai",
                    "forwardedBy": "azure-function",
                }
            },
            "logs": logs,
        }
    ]
    body = gzip.compress(json.dumps(payload).encode("utf-8"))
    _post_with_retry(NR_LOGS_ENDPOINT, body, _NR_HEADERS)
    logger.debug("Flushed %d log entries to New Relic", len(logs))


def _post_with_retry(url: str, data: bytes, headers: dict, max_retries: int = 3) -> requests.Response:
    """POST with exponential back-off; raises on final failure."""
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=30)
            if resp.status_code in (200, 202):
                return resp
            if resp.status_code == 429:
                wait = 5 * (2 ** attempt)
                logger.warning("New Relic rate-limited (429); retrying in %ds", wait)
                time.sleep(wait)
                continue
            # 4xx other than 429 are not retryable
            resp.raise_for_status()
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                logger.warning("New Relic request failed (attempt %d/%d): %s — retrying in %ds",
                               attempt + 1, max_retries, exc, wait)
                time.sleep(wait)

    raise RuntimeError(f"New Relic POST failed after {max_retries} attempts") from last_exc


# ══════════════════════════════════════════════════════════════════════════════
# Offset persistence (Azure Blob Storage)
# ══════════════════════════════════════════════════════════════════════════════

def _blob_client():
    svc       = BlobServiceClient.from_connection_string(STORAGE_CONN_STR)
    container = svc.get_container_client(OFFSET_CONTAINER)
    try:
        container.create_container()
    except Exception:
        pass  # container already exists
    return svc.get_blob_client(OFFSET_CONTAINER, OFFSET_BLOB)


def _load_offset() -> str | None:
    try:
        raw = _blob_client().download_blob().readall()
        return raw.decode().strip() or None
    except Exception:
        return None  # first run or storage unavailable — start from beginning


def _save_offset(offset: str) -> None:
    _blob_client().upload_blob(offset.encode(), overwrite=True)
