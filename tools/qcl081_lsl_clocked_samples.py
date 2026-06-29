"""Emit a Manifold-owned QCL-081 LSL sample-continuity report.

This is an optional adapter tool. It does not make the Manifold core crates
open sockets; it emits route evidence when the local pylsl/liblsl runtime is
available.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import uuid
from typing import Any


REPORT_SCHEMA = "rusty.manifold.lsl.qcl081_clocked_samples_report.v1"
ROUTE_EVIDENCE_SCHEMA = "rusty.manifold.bridge.route_evidence.v1"
ROUTE_ID = "bridge_route.clock.lsl.roundtrip_echo"
AUTHORITY_OWNER = "rusty.manifold.transport"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = run_probe(args)
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(
            "QCL-081 LSL samples: "
            f"status={report['status']} "
            f"received={report.get('samples_received', 0)}/{report.get('samples_requested', 0)} "
            f"loss={report.get('loss_percent', 100.0)}%"
        )
        print(json.dumps(report, sort_keys=True))
    return 0 if report.get("status") == "pass" else 2


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit a single JSON report line.")
    parser.add_argument("--source", default="manifold-lsl-broker")
    parser.add_argument("--stream-name", default="RustyManifoldQCL081")
    parser.add_argument("--stream-type", default="rusty.manifold.qcl081")
    parser.add_argument("--sample-count", type=int, default=16)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--warmup-seconds", type=float, default=0.15)
    parser.add_argument("--interval-seconds", type=float, default=0.01)
    return parser.parse_args(argv)


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    started_at_ms = epoch_ms()
    source = str(args.source or "manifold-lsl-broker")
    sample_count = max(1, int(args.sample_count or 16))
    timeout = max(0.5, float(args.timeout_seconds or 5.0))
    stream_name = str(args.stream_name or "RustyManifoldQCL081")
    stream_type = str(args.stream_type or "rusty.manifold.qcl081")
    source_id = f"rusty-manifold-qcl081-{uuid.uuid4()}"

    try:
        import pylsl
        from pylsl import StreamInfo, StreamInlet, StreamOutlet, resolve_byprop
    except Exception as exc:
        return blocked_report(
            source=source,
            stream_name=stream_name,
            stream_type=stream_type,
            source_id=source_id,
            sample_count=sample_count,
            started_at_ms=started_at_ms,
            issue_codes=["rusty.manifold.issue.lsl_runtime_unavailable"],
            notes=f"pylsl/liblsl unavailable: {exc}",
        )

    library_version = safe_library_version(pylsl)
    issue_codes: list[str] = []
    try:
        info = StreamInfo(stream_name, stream_type, 1, 0, "float32", source_id)
        outlet = StreamOutlet(info)
    except Exception as exc:
        return blocked_report(
            source=source,
            stream_name=stream_name,
            stream_type=stream_type,
            source_id=source_id,
            sample_count=sample_count,
            started_at_ms=started_at_ms,
            library_version=library_version,
            issue_codes=["rusty.manifold.issue.lsl_outlet_create_failed"],
            notes=f"LSL outlet creation failed: {exc}",
        )

    time.sleep(max(0.0, float(args.warmup_seconds or 0.0)))
    discovery_started = time.monotonic()
    streams = resolve_unique_stream(
        resolve_byprop=resolve_byprop,
        stream_name=stream_name,
        source_id=source_id,
        timeout=timeout,
    )
    discovery_ms = int(round((time.monotonic() - discovery_started) * 1000.0))
    if not streams:
        return finish_report(
            source=source,
            stream_name=stream_name,
            stream_type=stream_type,
            source_id=source_id,
            sample_count=sample_count,
            received=[],
            discovery_ms=discovery_ms,
            library_version=library_version,
            started_at_ms=started_at_ms,
            status="fail",
            issue_codes=["rusty.manifold.issue.lsl_discovery_timeout"],
            notes="No LSL stream matching the unique source id was discovered.",
        )

    try:
        inlet = StreamInlet(streams[0])
        try:
            inlet.open_stream(timeout=timeout)
        except Exception:
            pass
    except Exception as exc:
        return finish_report(
            source=source,
            stream_name=stream_name,
            stream_type=stream_type,
            source_id=source_id,
            sample_count=sample_count,
            received=[],
            discovery_ms=discovery_ms,
            library_version=library_version,
            started_at_ms=started_at_ms,
            status="blocked",
            issue_codes=["rusty.manifold.issue.lsl_inlet_open_failed"],
            notes=f"LSL inlet creation/open failed: {exc}",
        )

    producer_done = threading.Event()

    def producer() -> None:
        for sequence in range(sample_count):
            outlet.push_sample([float(sequence)])
            time.sleep(max(0.0, float(args.interval_seconds or 0.0)))
        producer_done.set()

    producer_thread = threading.Thread(target=producer, daemon=True)
    producer_thread.start()
    received: list[int] = []
    deadline = time.monotonic() + timeout
    while len(received) < sample_count and (
        time.monotonic() < deadline or not producer_done.is_set()
    ):
        sample, _timestamp = inlet.pull_sample(timeout=0.2)
        if not sample:
            continue
        try:
            received.append(int(round(float(sample[0]))))
        except (TypeError, ValueError, IndexError):
            issue_codes.append("rusty.manifold.issue.lsl_sample_decode_failed")

    producer_thread.join(timeout=1.0)
    expected_prefix = list(range(len(received)))
    monotonic = received == expected_prefix
    if len(received) == sample_count and monotonic:
        status = "pass"
    elif received:
        status = "warn"
        issue_codes.append("rusty.manifold.issue.lsl_sample_continuity_degraded")
    else:
        status = "fail"
        issue_codes.append("rusty.manifold.issue.lsl_sample_continuity_failed")

    return finish_report(
        source=source,
        stream_name=stream_name,
        stream_type=stream_type,
        source_id=source_id,
        sample_count=sample_count,
        received=received,
        discovery_ms=discovery_ms,
        library_version=library_version,
        started_at_ms=started_at_ms,
        status=status,
        issue_codes=dedupe(issue_codes),
        notes="Manifold-owned LSL producer and subscriber sample-continuity report.",
    )


def resolve_unique_stream(
    *,
    resolve_byprop: Any,
    stream_name: str,
    source_id: str,
    timeout: float,
) -> list[Any]:
    streams = list(resolve_byprop("source_id", source_id, minimum=1, timeout=timeout) or [])
    if streams:
        return streams
    named = list(resolve_byprop("name", stream_name, minimum=1, timeout=timeout) or [])
    return [stream for stream in named if stream_source_id(stream) == source_id]


def stream_source_id(stream: Any) -> str:
    try:
        value = stream.source_id()
    except Exception:
        return ""
    return str(value or "")


def blocked_report(
    *,
    source: str,
    stream_name: str,
    stream_type: str,
    source_id: str,
    sample_count: int,
    started_at_ms: int,
    issue_codes: list[str],
    notes: str,
    library_version: Any = None,
) -> dict[str, Any]:
    return finish_report(
        source=source,
        stream_name=stream_name,
        stream_type=stream_type,
        source_id=source_id,
        sample_count=sample_count,
        received=[],
        discovery_ms=None,
        library_version=library_version,
        started_at_ms=started_at_ms,
        status="blocked",
        issue_codes=issue_codes,
        notes=notes,
    )


def finish_report(
    *,
    source: str,
    stream_name: str,
    stream_type: str,
    source_id: str,
    sample_count: int,
    received: list[int],
    discovery_ms: int | None,
    library_version: Any,
    started_at_ms: int,
    status: str,
    issue_codes: list[str],
    notes: str,
) -> dict[str, Any]:
    ended_at_ms = epoch_ms()
    loss_percent = round(((sample_count - len(received)) / sample_count) * 100.0, 2)
    evidence_tier = "broker_owned" if source == "manifold-lsl-broker" else "host_loopback"
    monotonic = received == list(range(len(received)))
    return {
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "status": status,
        "source": source,
        "evidence_tier": evidence_tier,
        "route_id": ROUTE_ID,
        "authority": {
            "owner": AUTHORITY_OWNER,
            "runtime_adapter": "rusty-manifold-lsl-pylsl",
            "route_descriptor_owned_by": "rusty-manifold",
        },
        "stream_name": stream_name,
        "stream_type": stream_type,
        "source_id": source_id,
        "samples_requested": sample_count,
        "samples_received": len(received),
        "loss_percent": loss_percent,
        "discovery_ms": discovery_ms,
        "monotonic_sequences": monotonic,
        "received_sequences": received[:50],
        "duration_ms": max(0, ended_at_ms - started_at_ms),
        "library_version": library_version,
        "issue_codes": dedupe(issue_codes),
        "notes": notes,
        "bridge_route_evidence": route_evidence(
            status=status,
            issue_codes=dedupe(issue_codes),
            started_at_ms=started_at_ms,
            ended_at_ms=ended_at_ms,
            discovery_ms=discovery_ms,
            samples_received=len(received),
        ),
    }


def route_evidence(
    *,
    status: str,
    issue_codes: list[str],
    started_at_ms: int,
    ended_at_ms: int,
    discovery_ms: int | None,
    samples_received: int,
) -> dict[str, Any]:
    sent_status = "pass" if status in {"pass", "warn", "fail"} else status
    transport_status = "pass" if discovery_ms is not None and status != "blocked" else status
    observed_status = "pass" if status == "pass" else status
    return {
        "$schema": ROUTE_EVIDENCE_SCHEMA,
        "evidence_id": "evidence.bridge_route.clock.lsl.roundtrip_echo.qcl081_live",
        "route_id": ROUTE_ID,
        "status": status,
        "started_at_ms": started_at_ms,
        "ended_at_ms": ended_at_ms,
        "stage_reports": [
            {
                "stage": "sent",
                "status": sent_status,
                "observed_at_ms": started_at_ms,
                "evidence_refs": ["evidence.lsl.probe_outlet.published"],
                "issue_codes": [] if sent_status == "pass" else issue_codes,
            },
            {
                "stage": "transport_ok",
                "status": transport_status,
                "observed_at_ms": started_at_ms + max(0, int(discovery_ms or 0)),
                "evidence_refs": [
                    "evidence.lsl.echo_inlet.resolved",
                    "evidence.lsl.native_runtime.available",
                ],
                "issue_codes": [] if transport_status == "pass" else issue_codes,
            },
            {
                "stage": "observed",
                "status": observed_status,
                "observed_at_ms": ended_at_ms,
                "evidence_refs": [
                    "evidence.lsl.echo_samples.received",
                    "evidence.lsl.sample_continuity.monotonic",
                ]
                if samples_received
                else [],
                "issue_codes": [] if observed_status == "pass" else issue_codes,
            },
        ],
        "artifact_refs": ["artifact.lsl.qcl081_clocked_samples.report"],
        "issues": [{"issue_code": code} for code in issue_codes],
    }


def safe_library_version(pylsl_module: Any) -> dict[str, Any]:
    version: dict[str, Any] = {"pylsl": str(getattr(pylsl_module, "__version__", ""))}
    try:
        version["liblsl"] = pylsl_module.library_version()
    except Exception:
        version["liblsl"] = None
    return version


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def epoch_ms() -> int:
    return int(round(time.time() * 1000.0))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
