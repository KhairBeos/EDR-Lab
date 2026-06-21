"""Run a local realtime/near-realtime EDR dashboard API for Windows Sysmon."""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.realtime.realtime_core import (  # noqa: E402
    SUPPORTED_EVENT_IDS,
    SYSMON_LOG_NAME,
    RealtimeElasticsearchSink,
    RealtimeStore,
    T1105RealtimeCorrelator,
    WinEventRecord,
    normalize_realtime_record,
    run_realtime_rules,
)


class SysmonRealtimeCollector(threading.Thread):
    """Poll Windows Sysmon Event Log and push normalized events into the store."""

    def __init__(
        self,
        *,
        store: RealtimeStore,
        poll_interval: float,
        log_name: str,
        event_ids: tuple[int, ...] = SUPPORTED_EVENT_IDS,
    ) -> None:
        super().__init__(daemon=True)
        self.store = store
        self.poll_interval = poll_interval
        self.log_name = log_name
        self.event_ids = event_ids
        self.started_at = datetime.now(UTC)
        self.stop_requested = threading.Event()
        self.seen_record_ids: set[int] = set()
        self.correlator = T1105RealtimeCorrelator(window_seconds=300)

    def stop(self) -> None:
        self.stop_requested.set()

    def run(self) -> None:
        if platform.system().lower() != "windows":
            self.store.set_collector_state(
                running=False,
                last_error="Sysmon realtime collection is only available on Windows; API is serving empty demo buffers.",
            )
            return

        self.store.log_name = self.log_name
        self.store.set_collector_state(running=True)
        while not self.stop_requested.is_set():
            try:
                records = query_sysmon_events(
                    log_name=self.log_name,
                    event_ids=self.event_ids,
                    start_time=self.started_at,
                    timeout_seconds=max(15, int(self.poll_interval * 5)),
                )
                self._process_records(records)
                self.store.set_collector_state(running=True)
            except Exception as exc:  # noqa: BLE001 - keep demo API alive and expose error in /api/health.
                self.store.set_collector_state(running=True, last_error=str(exc))

            self.stop_requested.wait(self.poll_interval)

    def _process_records(self, records: list[WinEventRecord]) -> None:
        for record in sorted(records, key=lambda item: item.record_id):
            if record.record_id in self.seen_record_ids:
                continue
            self.seen_record_ids.add(record.record_id)

            event = normalize_realtime_record(record)
            self.store.add_event(event)

            for alert in run_realtime_rules(event):
                self.store.add_alert(alert)
            for alert in self.correlator.add_event(event):
                self.store.add_alert(alert)


class RealtimeApiHandler(BaseHTTPRequestHandler):
    """Small CORS-enabled JSON API for the static dashboard."""

    store: RealtimeStore
    stream_interval: float = 2.0

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - BaseHTTPRequestHandler API.
        sys.stderr.write(f"[realtime-api] {self.address_string()} - {format % args}\n")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        snapshot = self.store.snapshot()

        if path == "/api/health":
            self.send_json({"ok": True, "status": "ok", **snapshot["summary"]})
            return
        if path == "/api/events":
            self.send_json(snapshot["events"])
            return
        if path == "/api/alerts":
            self.send_json(snapshot["alerts"])
            return
        if path == "/api/evaluation":
            self.send_json(snapshot["evaluation"])
            return
        if path == "/api/summary":
            self.send_json(snapshot["summary"])
            return
        if path == "/api/stream":
            self.send_stream()
            return

        self.send_json({"error": "not_found", "path": path}, status=404)

    def send_json(self, payload: Any, *, status: int = 200) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_stream(self) -> None:
        self.send_response(200)
        self.send_cors_headers()
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        while True:
            snapshot = self.store.snapshot()
            payload = json.dumps(snapshot, sort_keys=True)
            try:
                self.wfile.write(f"event: snapshot\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            time.sleep(self.stream_interval)

    def send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")


def query_sysmon_events(
    *,
    log_name: str,
    event_ids: tuple[int, ...],
    start_time: datetime,
    timeout_seconds: int,
) -> list[WinEventRecord]:
    """Query Windows Event Log through PowerShell Get-WinEvent."""

    script = build_get_winevent_script(log_name=log_name, event_ids=event_ids, start_time=start_time)
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )

    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "Get-WinEvent failed"
        raise RuntimeError(stderr)

    raw_output = completed.stdout.strip()
    if not raw_output:
        return []

    parsed = json.loads(raw_output)
    rows = parsed if isinstance(parsed, list) else [parsed]
    records: list[WinEventRecord] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        records.append(
            WinEventRecord(
                record_id=int(row.get("RecordId", 0)),
                event_id=int(row.get("Id", 0)),
                time_created=str(row.get("TimeCreated", "")),
                provider_name=str(row.get("ProviderName", "")),
                message=str(row.get("Message", "")),
                xml=str(row.get("Xml", "")),
            )
        )
    return records


def build_get_winevent_script(*, log_name: str, event_ids: tuple[int, ...], start_time: datetime) -> str:
    ids = ",".join(str(event_id) for event_id in event_ids)
    start = start_time.astimezone(UTC).isoformat()
    return f"""
$ErrorActionPreference = 'Stop'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom
$start = [datetime]::Parse('{start}')
$ids = @({ids})
$filter = @{{ LogName = '{log_name}'; Id = $ids; StartTime = $start }}
$events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
$rows = @(
  $events |
    Sort-Object RecordId |
    ForEach-Object {{
      [pscustomobject]@{{
        RecordId = $_.RecordId
        Id = $_.Id
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        ProviderName = $_.ProviderName
        Message = $_.Message
        Xml = $_.ToXml()
      }}
    }}
)
$rows | ConvertTo-Json -Depth 8 -Compress
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local realtime EDR dashboard API.")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--log-name", default=SYSMON_LOG_NAME)
    parser.add_argument(
        "--elastic-url",
        default=os.environ.get("EDR_ELASTICSEARCH_URL", ""),
        help="Elasticsearch URL. Defaults to EDR_ELASTICSEARCH_URL when set.",
    )
    parser.add_argument("--elastic-timeout", type=int, default=3)
    parser.add_argument("--no-collector", action="store_true", help="Serve API/static buffers without polling Sysmon.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    elastic_url = args.elastic_url.strip()
    elasticsearch = (
        RealtimeElasticsearchSink(base_url=elastic_url, timeout_seconds=args.elastic_timeout) if elastic_url else None
    )
    store = RealtimeStore(repo_root=REPO_ROOT, elasticsearch=elasticsearch)
    store.write_static_snapshots()
    store.refresh_elasticsearch_connection()

    collector: SysmonRealtimeCollector | None = None
    if args.no_collector:
        store.set_collector_state(running=False, last_error="Collector disabled with --no-collector.")
    else:
        collector = SysmonRealtimeCollector(store=store, poll_interval=args.poll_interval, log_name=args.log_name)
        collector.start()

    RealtimeApiHandler.store = store
    RealtimeApiHandler.stream_interval = args.poll_interval
    server = ThreadingHTTPServer((args.host, args.port), RealtimeApiHandler)

    print(f"Realtime EDR API listening on http://{args.host}:{args.port}")
    if elastic_url:
        print(f"Elasticsearch realtime sink: {elastic_url} ({store.elasticsearch_status})")
    else:
        print("Elasticsearch realtime sink: disabled; set EDR_ELASTICSEARCH_URL or pass --elastic-url to enable.")
    print(f"Dashboard static server command: python -m http.server 8088 -d dashboard/static")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping realtime dashboard API...")
    finally:
        if collector is not None:
            collector.stop()
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
