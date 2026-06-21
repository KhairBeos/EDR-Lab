"""Fixture-based Phase 1 ART telemetry ingestion smoke path.

This script does not require a live Windows VM. It loads the existing Sysmon
Event ID 1 fixture, creates one raw payload, creates one ECS-normalized payload,
and can optionally POST both payloads to the local Logstash HTTP endpoint.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from normalization.sysmon.process_create_normalizer import normalize_sysmon_event_1
from scripts.lab_config import default_elasticsearch_url, default_logstash_url

DEFAULT_FIXTURE_PATH = REPO_ROOT / "collection" / "sysmon" / "fixtures" / "sysmon_event_1_process_create.xml"

ART_METADATA: dict[str, str] = {
    "technique_id": "T1059.001",
    "test_guid": "a538de64-1c74-46ed-aa60-b995ed302598",
    "test_name": "PowerShell Command Execution",
    "platform": "windows",
    "executor": "powershell",
}


def load_fixture(path: Path = DEFAULT_FIXTURE_PATH) -> str:
    return path.read_text(encoding="utf-8")


def build_normalized_payload(xml_event: str) -> dict[str, Any]:
    payload = normalize_sysmon_event_1(xml_event)
    payload["art"] = dict(ART_METADATA)

    tags = list(payload.get("tags", []))
    for tag in ("ecs_normalized", "sysmon_event_1"):
        if tag not in tags:
            tags.append(tag)
    payload["tags"] = tags
    payload["event"]["dataset"] = "windows.sysmon_operational"

    return payload


def build_raw_payload(xml_event: str, normalized_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized = normalized_payload or normalize_sysmon_event_1(xml_event)

    return {
        "@timestamp": normalized.get("@timestamp", ""),
        "event": {
            "kind": "event",
            "code": normalized["event"]["code"],
            "module": "sysmon",
            "dataset": "edr.raw",
            "original": xml_event,
        },
        "host": copy.deepcopy(normalized.get("host", {})),
        "log": copy.deepcopy(normalized.get("log", {})),
        "sysmon": {
            "event_data": copy.deepcopy(normalized["sysmon"]["event_data"]),
        },
        "art": dict(ART_METADATA),
        "tags": ["sysmon_event_1_raw", "fixture_smoke"],
    }


def build_smoke_payloads(xml_event: str) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = build_normalized_payload(xml_event)
    raw = build_raw_payload(xml_event, normalized)
    return raw, normalized


def post_json(url: str, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def print_verification_commands(logstash_url: str, elasticsearch_url: str) -> None:
    print(
        f"""
Smoke payloads generated.

Logstash endpoint:
  {logstash_url}

Elasticsearch verification:
  curl.exe -s "{elasticsearch_url.rstrip('/')}/edr-raw-events-*/_search?q=art.technique_id:T1059.001&size=5&pretty"

Kibana filter:
  art.technique_id : "T1059.001"

Expected markers:
  raw.event.dataset = edr.raw
  normalized.event.dataset = windows.sysmon_operational
  normalized.tags include ecs_normalized and sysmon_event_1
""".strip()
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Phase 1 ART telemetry smoke payloads.")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE_PATH)
    parser.add_argument("--post-logstash", action="store_true", help="POST raw and normalized payloads to Logstash.")
    parser.add_argument("--logstash-url", default=default_logstash_url())
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--print-payloads", action="store_true", help="Print raw and normalized JSON payloads.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    xml_event = load_fixture(args.fixture)
    raw_payload, normalized_payload = build_smoke_payloads(xml_event)

    if args.print_payloads:
        print(json.dumps({"raw": raw_payload, "normalized": normalized_payload}, indent=2))

    if args.post_logstash:
        try:
            post_json(args.logstash_url, raw_payload)
            post_json(args.logstash_url, normalized_payload)
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            print(f"Logstash POST failed: {exc}", file=sys.stderr)
            print_verification_commands(args.logstash_url, args.elasticsearch_url)
            return 2

        print("Posted raw and normalized smoke payloads to Logstash.")

    print_verification_commands(args.logstash_url, args.elasticsearch_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
