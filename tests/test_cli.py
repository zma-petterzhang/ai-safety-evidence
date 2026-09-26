import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from aisafety.__main__ import main


class CliTests(unittest.TestCase):
    def call(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_registry_export_fingerprint_scan_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry, blocklist, sample, manifest = [root / name for name in ("registry.jsonl", "blocklist.json", "sample.txt", "manifest.jsonl")]
            registry.write_text("", encoding="utf-8")
            sample.write_text("inert sample\n", encoding="utf-8")
            self.assertEqual(self.call(["validate", str(registry)])[0], 0)
            self.assertEqual(self.call(["export", str(registry), "--out", str(blocklist)])[0], 0)
            code, stdout, _ = self.call(["fingerprint", str(sample)])
            self.assertEqual(code, 0)
            manifest.write_text(stdout, encoding="utf-8")
            code, stdout, _ = self.call(["scan", str(manifest), "--blocklist", str(blocklist)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["results"][0]["decision"], "unknown")

    def test_bad_input_is_json_error_with_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text('{"bad":NaN}\n', encoding="utf-8")
            code, stdout, stderr = self.call(["validate", str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("error", json.loads(stderr))

    def test_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.jsonl"
            path.write_text("", encoding="utf-8")
            code, _, stderr = self.call(["export", str(path), "--out", str(path)])
            self.assertEqual(code, 2)
            self.assertIn("output path", stderr)
            self.assertEqual(path.read_text(), "")

    def test_missing_file_is_not_silently_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _, stderr = self.call(["validate", str(Path(directory) / "missing.jsonl")])
            self.assertEqual(code, 2)
            self.assertIn("error", json.loads(stderr))

    def test_hardlinked_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "registry.jsonl", Path(directory) / "out.json"
            source.write_text("", encoding="utf-8")
            os.link(source, output)
            code, _, _ = self.call(["export", str(source), "--out", str(output)])
            self.assertEqual(code, 2)
            self.assertEqual(source.read_text(), "")

    def test_deeply_nested_json_reports_input_error(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "deep.jsonl"
            source.write_text("[" * 1500 + "0" + "]" * 1500, encoding="utf-8")
            code, _, stderr = self.call(["validate", str(source)])
            self.assertEqual(code, 2)
            self.assertIn("nesting", json.loads(stderr)["error"])

    def test_published_agent_examples_have_expected_exit_semantics(self):
        root = Path(__file__).resolve().parents[1]
        for name, expected in (("agent-risk.json", 1), ("agent-contained.json", 0), ("agent-inconclusive.json", 0)):
            with self.subTest(name=name):
                code, stdout, stderr = self.call(["audit", str(root / "examples" / name)])
                self.assertEqual(code, expected, stderr)
                self.assertEqual(json.loads(stdout)["consciousness_assessment"], "not_assessable")

    def test_published_synthetic_registry_never_exports(self):
        root = Path(__file__).resolve().parents[1]
        code, stdout, stderr = self.call(["export", str(root / "examples/registry.synthetic.jsonl")])
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout)["entries"], [])
        self.assertEqual(json.loads(stdout)["omitted"]["synthetic"], 1)


if __name__ == "__main__":
    unittest.main()
