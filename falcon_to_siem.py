#!/usr/bin/env python3
"""Pull CrowdStrike Falcon alerts, normalize them and forward them to a SIEM (Splunk HEC).

Usage:
    python falcon_to_siem.py --sample --dry-run          # offline demo, no credentials needed
    python falcon_to_siem.py --dry-run                   # real Falcon alerts, print instead of sending
    python falcon_to_siem.py                             # Falcon -> Splunk HEC

Env: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_CLOUD (default us1),
     SPLUNK_HEC_URL (e.g. https://splunk.lab:8088/services/collector/event), SPLUNK_HEC_TOKEN
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

CHECKPOINT = Path(".checkpoint.json")  # newest alert timestamp already forwarded
SAMPLE = Path(__file__).parent / "sample" / "falcon_alerts.json"


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def normalize(alert: dict) -> dict:
    """Flatten a Falcon alert into a stable, SIEM-friendly schema (fields chosen to line up with CIM/ECS)."""
    device = alert.get("device") or {}
    return {
        "event_id": alert.get("composite_id"),
        "created": alert.get("created_timestamp"),
        "vendor": "crowdstrike",
        "product": alert.get("product", "falcon"),
        "rule_name": alert.get("name"),
        "description": alert.get("description"),
        "severity": alert.get("severity_name"),
        "severity_score": alert.get("severity"),
        "status": alert.get("status"),
        "action": alert.get("pattern_disposition_description"),
        "mitre_tactic": alert.get("tactic"),
        "mitre_technique_id": alert.get("technique_id"),
        "host": device.get("hostname"),
        "host_ip": device.get("local_ip"),
        "platform": device.get("platform_name"),
        "user": alert.get("user_name"),
        "file_name": alert.get("filename"),
        "cmdline": alert.get("cmdline"),
        "sha256": alert.get("sha256"),
    }


def to_hec(event: dict) -> dict:
    """Wrap a normalized event in Splunk's HTTP Event Collector envelope, using the alert's own timestamp."""
    return {
        "time": parse_ts(event["created"]).timestamp(),
        "host": event.get("host") or "unknown",
        "source": "falcon_to_siem",
        "sourcetype": "crowdstrike:alert",
        "event": event,
    }


def fetch_falcon_alerts(since: str) -> list[dict]:
    from falconpy import Alerts  # imported here so --sample works without the SDK installed

    falcon = Alerts(
        client_id=os.environ["FALCON_CLIENT_ID"],
        client_secret=os.environ["FALCON_CLIENT_SECRET"],
        base_url=os.environ.get("FALCON_CLOUD", "us1"),
    )
    found = falcon.query_alerts_v2(filter=f"created_timestamp:>'{since}'", sort="created_timestamp.asc", limit=500)
    if found["status_code"] != 200:
        sys.exit(f"Falcon query failed: {found['body'].get('errors')}")
    ids = found["body"]["resources"]
    alerts: list[dict] = []
    for i in range(0, len(ids), 100):  # fetch details in batches of 100
        detail = falcon.get_alerts_v2(composite_ids=ids[i : i + 100])
        if detail["status_code"] != 200:
            sys.exit(f"Falcon detail fetch failed: {detail['body'].get('errors')}")
        alerts += detail["body"]["resources"]
    return alerts


def send_to_splunk(envelopes: list[dict]) -> None:
    import requests

    resp = requests.post(
        os.environ["SPLUNK_HEC_URL"],
        headers={"Authorization": f"Splunk {os.environ['SPLUNK_HEC_TOKEN']}"},
        data="\n".join(json.dumps(e) for e in envelopes),  # HEC accepts concatenated JSON events
        timeout=15,
    )
    resp.raise_for_status()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", action="store_true", help="use bundled fake alerts instead of calling Falcon")
    ap.add_argument("--dry-run", action="store_true", help="print HEC events instead of sending them")
    ap.add_argument("--lookback-minutes", type=int, default=60, help="first-run window (default 60)")
    args = ap.parse_args()

    if args.sample:
        raw = json.loads(SAMPLE.read_text(encoding="utf-8"))
    else:
        if CHECKPOINT.exists():
            since = json.loads(CHECKPOINT.read_text())["last_created"]
        else:
            since = (datetime.now(timezone.utc) - timedelta(minutes=args.lookback_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = fetch_falcon_alerts(since)

    events = [normalize(a) for a in raw]
    envelopes = [to_hec(e) for e in events]
    if not envelopes:
        print("No new alerts.")
        return

    if args.dry_run:
        for env in envelopes:
            print(json.dumps(env))
    else:
        send_to_splunk(envelopes)
        print(f"Sent {len(envelopes)} alerts to Splunk.")

    if not args.sample and not args.dry_run:  # only advance the checkpoint after a successful send
        newest = max(events, key=lambda e: parse_ts(e["created"]))["created"]
        CHECKPOINT.write_text(json.dumps({"last_created": newest}))


if __name__ == "__main__":
    main()
