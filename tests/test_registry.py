import copy
import hashlib
import tempfile
import unittest
from datetime import date
from pathlib import Path

from aisafety.registry import (export_blocklist, fingerprint, load_jsonl, parse_json,
                               scan_manifest, validate_blocklist, validate_registry)


TODAY = date(2026, 9, 26)


def record(**changes):
    """Fabricated unit-test metadata; this is never a real-world allegation."""
    row = {"id": "TEST-001", "sha256": "a" * 64, "source_url": "https://example.org/fixture",
           "category": "data_poisoning", "summary": "Fabricated test fixture, not an actual incident.",
           "status": "confirmed", "disposition": "exclude", "synthetic": False,
           "evidence": [{"url": "https://example.org/report", "kind": "artifact_analysis", "note": "Test only"}],
           "reviews": [{"reviewer": "test-reviewer-1", "reviewed_at": "2026-09-25", "decision": "confirm"},
                       {"reviewer": "test-reviewer-2", "reviewed_at": "2026-09-25", "decision": "confirm"}],
           "expires_at": "2026-10-26"}
    row.update(changes)
    return row


class RegistryTests(unittest.TestCase):
    def test_empty_registry_means_no_known_exclusions(self):
        exported = export_blocklist([], TODAY)
        self.assertEqual(exported["entries"], [])
        scanned = scan_manifest([{"id": "doc", "sha256": "b" * 64}], exported, TODAY)
        self.assertEqual(scanned["results"][0]["decision"], "unknown")

    def test_exact_hash_matches_regardless_of_source_url(self):
        exported = export_blocklist([record()], TODAY)
        scanned = scan_manifest([{"id": "mirror", "sha256": "a" * 64,
                                  "source_url": "https://example.org/mirror"},
                                 {"id": "same-url-different-content", "sha256": "b" * 64,
                                  "source_url": "https://example.org/fixture"}], exported, TODAY)
        self.assertEqual(scanned["matches"], 1)
        self.assertEqual([r["decision"] for r in scanned["results"]], ["exclude", "unknown"])

    def test_only_current_confirmed_non_synthetic_records_export(self):
        cases = [record(synthetic=True), record(status="candidate", disposition="review", reviews=[]),
                 record(status="retracted", disposition="allow"), record(expires_at="2026-09-25")]
        for row in cases:
            with self.subTest(row=row):
                self.assertEqual(export_blocklist([row], TODAY)["entries"], [])
        self.assertEqual(len(export_blocklist([record(expires_at="2026-09-26")], TODAY)["entries"]), 1)

    def test_old_export_cannot_keep_expired_exclusion_active(self):
        exported = export_blocklist([record()], TODAY)
        scanned = scan_manifest([{"id": "doc", "sha256": "a" * 64}], exported, date(2026, 10, 27))
        self.assertEqual(scanned["matches"], 0)
        self.assertEqual(scanned["expired_entries_ignored"], 1)

    def test_confirmation_requires_evidence_and_two_reviewers(self):
        for changes in ({"evidence": []}, {"reviews": []}, {"reviews": record()["reviews"][:1]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_registry([record(**changes)], TODAY)

    def test_case_variant_reviewers_are_not_independent(self):
        row = record()
        row["reviews"][1]["reviewer"] = row["reviews"][0]["reviewer"].upper()
        with self.assertRaisesRegex(ValueError, "distinct"):
            validate_registry([row], TODAY)

    def test_dissent_prevents_confirmation(self):
        row = record()
        row["reviews"][1]["decision"] = "reject"
        with self.assertRaises(ValueError):
            validate_registry([row], TODAY)

    def test_review_dates_are_valid_and_not_future(self):
        for bad_date in ("2026-02-30", "2026-09-27", "2026-9-1"):
            row = record()
            row["reviews"][0]["reviewed_at"] = bad_date
            with self.subTest(date=bad_date), self.assertRaises(ValueError):
                validate_registry([row], TODAY)

    def test_state_and_disposition_must_agree(self):
        for status, disposition in (("candidate", "exclude"), ("retracted", "exclude"), ("confirmed", "allow")):
            with self.subTest(status=status), self.assertRaises(ValueError):
                validate_registry([record(status=status, disposition=disposition)], TODAY)

    def test_duplicate_ids_and_hashes_are_rejected(self):
        for second in (record(sha256="b" * 64), record(id="TEST-002")):
            with self.assertRaises(ValueError):
                validate_registry([record(), second], TODAY)

    def test_invalid_types_raise_value_error(self):
        for field, value in (("category", []), ("status", {}), ("synthetic", "false"),
                             ("reviews", None), ("evidence", {}), ("sha256", 123),
                             ("source_url", "https://example.org:broken/x"), ("id", [])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_registry([record(**{field: value})], TODAY)

    def test_unknown_fields_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            validate_registry([record(execute="not allowed")], TODAY)

    def test_urls_never_accept_credentials_or_local_protocols(self):
        for url in ("file:///etc/passwd", "https://user:password@example.org", "javascript:alert(1)",
                    "https:///missing-host", "https://example.org/\nsecret"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_registry([record(source_url=url)], TODAY)

    def test_noncanonical_hash_is_rejected(self):
        for value in ("A" * 64, "a" * 63, "g" * 64, "a" * 64 + "\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_registry([record(sha256=value)], TODAY)

    def test_parser_rejects_duplicate_fields_and_nonfinite_numbers(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_json(raw)

    def test_jsonl_identifies_bad_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text('\n{"x":1}\nnot json\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"bad.jsonl:3:"):
                load_jsonl(path)

    def test_tampered_blocklist_is_rejected(self):
        original = export_blocklist([record()], TODAY)
        for field, value in (("entries", "not an array"), ("schema_version", "99"),
                             ("generated_at", "2026-09-26")):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_blocklist(changed)
        original["entries"].append(copy.deepcopy(original["entries"][0]))
        with self.assertRaises(ValueError):
            validate_blocklist(original)

    def test_manifest_invalid_rows_rejected_even_with_empty_blocklist(self):
        for manifest in ([{"id": "x", "sha256": "wrong"}], [{"id": "x"}],
                         [{"id": "x", "sha256": "a" * 64}] * 2):
            with self.assertRaises(ValueError):
                scan_manifest(manifest, export_blocklist([], TODAY), TODAY)

    def test_fingerprint_hashes_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inert.txt"
            raw = b"inert\r\nfixture\x00"
            path.write_bytes(raw)
            rows = fingerprint([path])
            self.assertEqual(rows[0]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(rows[0]["id"], str(path))
            with self.assertRaises(ValueError):
                fingerprint([directory])
            with self.assertRaises(ValueError):
                fingerprint([path, path])


if __name__ == "__main__":
    unittest.main()
