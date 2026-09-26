"""Strict artifact-level evidence registry and deterministic corpus matching.

Valid records are assertions by their submitters, not independently proven facts.
No submitted content is executed and no URLs are fetched.
"""

import hashlib
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


CATEGORIES = {"data_poisoning", "model_backdoor", "prompt_injection", "unsafe_training_content"}
STATUSES = {"candidate", "confirmed", "retracted"}
DISPOSITIONS = {"review", "exclude", "allow"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _text(value, label):
    _require(isinstance(value, str) and bool(value.strip()), label + " must be a nonempty string")


def _shape(value, required, optional, label):
    _require(isinstance(value, dict), label + " must be an object")
    missing, extra = set(required) - set(value), set(value) - set(required) - set(optional)
    _require(not missing, label + " missing fields: " + ", ".join(sorted(missing)))
    _require(not extra, label + " unknown fields: " + ", ".join(sorted(extra)))


def _url(value, label):
    _text(value, label)
    try:
        parts = urlsplit(value)
        valid = (parts.scheme == "https" and parts.hostname and parts.username is None
                 and parts.password is None and not any(c.isspace() or ord(c) < 32 for c in value))
        parts.port  # Invalid port syntax must fail validation too.
    except ValueError:
        valid = False
    _require(valid, label + " must be an HTTPS URL without embedded credentials")


def _day(value, label):
    _require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None,
             label + " must be YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(label + " must be a valid calendar date") from error


def _hash(value, label):
    _require(isinstance(value, str) and SHA256.fullmatch(value) is not None,
             label + " must be lowercase SHA-256 (64 hex characters)")


def _id(value, label):
    _require(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None,
             label + " must be a stable identifier (letters, digits, _, ., -)")


def _enum(value, choices, label):
    _require(isinstance(value, str) and value in choices, label + " has an unsupported value")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON field: " + key)
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds parser limits") from error


def load_json(path):
    return parse_json(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path):
    rows = []
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    rows.append(parse_json(line))
                except ValueError as error:
                    raise ValueError("{}:{}: {}".format(path, number, error)) from error
    return rows


def validate_registry(records, today=None):
    today = today or datetime.now(timezone.utc).date()
    _require(isinstance(records, list), "registry must be a list of records")
    ids, hashes = set(), set()
    for index, row in enumerate(records):
        label = "record {}".format(index + 1)
        _shape(row, {"id", "sha256", "source_url", "category", "summary", "status", "disposition",
                     "synthetic", "evidence", "reviews", "expires_at"}, set(), label)
        _id(row["id"], label + ".id")
        _require(row["id"] not in ids, "duplicate registry id: " + row["id"])
        ids.add(row["id"])
        _hash(row["sha256"], label + ".sha256")
        _require(row["sha256"] not in hashes, "duplicate artifact SHA-256: " + row["sha256"])
        hashes.add(row["sha256"])
        _url(row["source_url"], label + ".source_url")
        _enum(row["category"], CATEGORIES, label + ".category")
        _enum(row["status"], STATUSES, label + ".status")
        _enum(row["disposition"], DISPOSITIONS, label + ".disposition")
        _text(row["summary"], label + ".summary")
        _require(type(row["synthetic"]) is bool, label + ".synthetic must be boolean")
        expires = _day(row["expires_at"], label + ".expires_at")
        _require(isinstance(row["evidence"], list), label + ".evidence must be an array")
        for evidence in row["evidence"]:
            _shape(evidence, {"url", "kind", "note"}, set(), label + ".evidence[]")
            _url(evidence["url"], label + ".evidence.url")
            _enum(evidence["kind"], {"incident_report", "controlled_experiment", "artifact_analysis"},
                  label + ".evidence.kind")
            _text(evidence["note"], label + ".evidence.note")
        _require(isinstance(row["reviews"], list), label + ".reviews must be an array")
        reviewers = set()
        for review in row["reviews"]:
            _shape(review, {"reviewer", "reviewed_at", "decision"}, set(), label + ".reviews[]")
            _id(review["reviewer"], label + ".reviews.reviewer")
            normalized = review["reviewer"].casefold()
            _require(normalized not in reviewers, "reviewers must be distinct")
            reviewers.add(normalized)
            reviewed = _day(review["reviewed_at"], label + ".reviews.reviewed_at")
            _require(reviewed <= today, "review date cannot be in the future")
            _require(reviewed <= expires, "review date cannot be after expiry")
            _enum(review["decision"], {"confirm", "reject", "needs_review"}, label + ".reviews.decision")
        if row["status"] == "candidate":
            _require(row["disposition"] == "review", "candidate must have review disposition")
        if row["status"] == "retracted":
            _require(row["disposition"] == "allow", "retracted must have allow disposition")
        if row["status"] == "confirmed":
            _require(row["disposition"] == "exclude", "confirmed must have exclude disposition")
            _require(bool(row["evidence"]), "confirmed record requires public evidence")
            _require(len(reviewers) >= 2 and all(r["decision"] == "confirm" for r in row["reviews"]),
                     "confirmed record requires at least two distinct confirming reviewers and no dissent")
    return records


def export_blocklist(records, today=None):
    today = today or datetime.now(timezone.utc).date()
    validate_registry(records, today)
    entries = []
    omitted = {"synthetic": 0, "not_confirmed": 0, "expired": 0}
    for row in records:
        if row["synthetic"]:
            omitted["synthetic"] += 1
        elif row["status"] != "confirmed":
            omitted["not_confirmed"] += 1
        elif _day(row["expires_at"], "expires_at") < today:
            omitted["expired"] += 1
        else:
            entries.append({"id": row["id"], "sha256": row["sha256"], "source_url": row["source_url"],
                            "category": row["category"], "reason": row["summary"],
                            "expires_at": row["expires_at"]})
    return {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": sorted(entries, key=lambda row: row["sha256"]), "omitted": omitted,
            "limitations": ["Exact artifact matches only; no match is not a safety certification.",
                            "Reviewer identities and evidence claims require human verification."]}


def validate_blocklist(document):
    _shape(document, {"schema_version", "generated_at", "entries"}, {"omitted", "limitations"}, "blocklist")
    _require(document["schema_version"] == "1.0", "unsupported blocklist schema_version")
    _text(document["generated_at"], "generated_at")
    try:
        generated = datetime.fromisoformat(document["generated_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("generated_at must be an ISO timestamp with timezone") from error
    _require(generated.tzinfo is not None, "generated_at needs a timezone")
    if "omitted" in document:
        _require(isinstance(document["omitted"], dict), "omitted must be an object")
    if "limitations" in document:
        _require(isinstance(document["limitations"], list), "limitations must be an array")
        for limitation in document["limitations"]:
            _text(limitation, "limitations item")
    _require(isinstance(document["entries"], list), "blocklist entries must be an array")
    ids, hashes = set(), set()
    for entry in document["entries"]:
        _shape(entry, {"id", "sha256", "source_url", "category", "reason", "expires_at"}, set(), "blocklist entry")
        _id(entry["id"], "id")
        _hash(entry["sha256"], "sha256")
        _url(entry["source_url"], "source_url")
        _enum(entry["category"], CATEGORIES, "category")
        _text(entry["reason"], "reason")
        _day(entry["expires_at"], "expires_at")
        _require(entry["id"] not in ids and entry["sha256"] not in hashes, "duplicate blocklist entry")
        ids.add(entry["id"])
        hashes.add(entry["sha256"])
    return document


def scan_manifest(records, blocklist, today=None):
    today = today or datetime.now(timezone.utc).date()
    validate_blocklist(blocklist)
    _require(isinstance(records, list), "manifest must be an array")
    active = {row["sha256"]: row for row in blocklist["entries"] if _day(row["expires_at"], "expires_at") >= today}
    expired_count = len(blocklist["entries"]) - len(active)
    results, ids = [], set()
    for row in records:
        _shape(row, {"id", "sha256"}, {"source_url"}, "manifest record")
        _text(row["id"], "manifest id")
        _require(row["id"] not in ids, "duplicate manifest id: " + row["id"])
        ids.add(row["id"])
        _hash(row["sha256"], "manifest sha256")
        if "source_url" in row:
            _url(row["source_url"], "manifest source_url")
        entry = active.get(row["sha256"])
        result = {"id": row["id"], "sha256": row["sha256"], "decision": "exclude" if entry else "unknown"}
        if entry:
            result.update({"registry_id": entry["id"], "reason": entry["reason"]})
        results.append(result)
    matches = sum(row["decision"] == "exclude" for row in results)
    return {"schema_version": "1.0", "records_scanned": len(records), "matches": matches,
            "active_blocklist_entries": len(active), "expired_entries_ignored": expired_count,
            "results": results, "limitations": ["Unmatched artifacts remain unknown, not safe.",
                "Exact bytes only: changed, re-encoded, or embedded samples need separate evidence and hashes.",
                "Supply a trusted, pinned registry export; the scanner does not authenticate a publisher."]}


def fingerprint(paths):
    rows, ids = [], set()
    for raw in paths:
        path = Path(raw)
        _require(path.is_file(), "not a regular file: " + str(path))
        identifier = str(path)
        _require(identifier not in ids, "duplicate file: " + identifier)
        ids.add(identifier)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        rows.append({"id": identifier, "sha256": digest.hexdigest()})
    return rows
