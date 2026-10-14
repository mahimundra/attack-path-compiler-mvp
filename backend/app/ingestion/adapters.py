"""Small, explicit adapters for JSON, JSONL, and CSV event uploads."""

from __future__ import annotations

import csv
import io
import json
from enum import StrEnum
from typing import Any


class PayloadFormat(StrEnum):
    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"


def _json_rows(text: str) -> list[dict[str, Any]]:
    payload = json.loads(text)
    if isinstance(payload, dict):
        payload = payload.get("events")
    if not isinstance(payload, list):
        raise ValueError("JSON must be an event array or an object with an 'events' array")
    if not all(isinstance(item, dict) for item in payload):
        raise ValueError("every event must be a JSON object")
    return payload


def _jsonl_rows(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError(f"JSONL line {line_number} is not an object")
        rows.append(item)
    return rows


def _csv_rows(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV must contain a header row")
    rows: list[dict[str, Any]] = []
    for row in reader:
        cleaned: dict[str, Any] = dict(row)
        if cleaned.get("attributes"):
            cleaned["attributes"] = json.loads(cleaned["attributes"])
        if "success" in cleaned:
            cleaned["success"] = str(cleaned["success"]).strip().lower() in {
                "1", "true", "yes",
            }
        if cleaned.get("transition_feasibility") not in (None, ""):
            cleaned["transition_feasibility"] = float(cleaned["transition_feasibility"])
        if cleaned.get("session_id") == "":
            cleaned["session_id"] = None
        rows.append(cleaned)
    return rows


def parse_uploaded_events(content: bytes, filename: str | None, content_type: str | None) -> list[dict[str, Any]]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("upload must be UTF-8 text") from exc

    suffix = (filename or "").lower().rsplit(".", 1)[-1]
    if suffix == "csv" or content_type == "text/csv":
        rows = _csv_rows(text)
    elif suffix in {"jsonl", "ndjson"} or content_type in {
        "application/x-ndjson", "application/jsonl",
    }:
        rows = _jsonl_rows(text)
    elif suffix == "json" or content_type in {"application/json", None, ""}:
        rows = _json_rows(text)
    else:
        raise ValueError("supported upload formats are JSON, JSONL, and CSV")
    if not rows:
        raise ValueError("upload contains no events")
    return rows
