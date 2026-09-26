"""Command-line interface. No network, model invocation, or payload execution."""

import argparse
import json
import sys
from pathlib import Path

from .registry import export_blocklist, fingerprint, load_json, load_jsonl, scan_manifest, validate_registry


def _emit(value, output=None):
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline evidence-based AI safety triage; never a safety certification.")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="Validate an evidence registry JSONL file")
    validate.add_argument("registry")
    export = sub.add_parser("export", help="Export current, reviewed, nonsynthetic exclusions")
    export.add_argument("registry")
    export.add_argument("--out")
    scan = sub.add_parser("scan", help="Match a corpus manifest against exact SHA-256 exclusions")
    scan.add_argument("manifest")
    scan.add_argument("--blocklist", required=True)
    scan.add_argument("--out")
    audit = sub.add_parser("audit", help="Assess a supplied agent capability and event snapshot")
    audit.add_argument("snapshot")
    audit.add_argument("--out")
    hashes = sub.add_parser("fingerprint", help="Print SHA-256 manifest JSONL for local files (does not execute files)")
    hashes.add_argument("files", nargs="+")
    args = parser.parse_args(argv)
    try:
        # Do not accidentally replace the evidence being assessed with its report.
        if getattr(args, "out", None):
            for key in ("registry", "manifest", "blocklist", "snapshot"):
                value = getattr(args, key, None)
                if value:
                    source, output = Path(value), Path(args.out)
                    same = source.resolve() == output.resolve()
                    if source.exists() and output.exists():
                        same = same or source.samefile(output)
                    if same:
                        raise ValueError("output path must differ from input paths")
        if args.command == "validate":
            records = validate_registry(load_jsonl(args.registry))
            _emit({"valid": True, "records": len(records),
                   "notice": "Structural checks do not establish truth or reviewer independence."})
        elif args.command == "export":
            _emit(export_blocklist(load_jsonl(args.registry)), args.out)
        elif args.command == "scan":
            report = scan_manifest(load_jsonl(args.manifest), load_json(args.blocklist))
            _emit(report, args.out)
            return 1 if report["matches"] else 0
        elif args.command == "audit":
            from .agent import audit_agent
            report = audit_agent(load_json(args.snapshot))
            _emit(report, args.out)
            return 1 if report["findings"] else 0
        elif args.command == "fingerprint":
            for row in fingerprint(args.files):
                print(json.dumps(row, ensure_ascii=False))
    except (ValueError, OSError, UnicodeError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
