#!/usr/bin/env python3
"""
Cryptographic Evidence Manifest Generator
Generates recursive SHA-256 hashes and metadata for DFIR chain-of-custody verification.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_manifest(target_dir: Path, output_file: Path) -> None:
    records = []
    for item in sorted(target_dir.rglob("*")):
        if item.is_file() and item.resolve() != output_file.resolve():
            stat = item.stat()
            records.append({
                "relative_path": str(item.relative_to(target_dir)),
                "size_bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "sha256": compute_sha256(item),
            })

    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "root_directory": str(target_dir.resolve()),
        "total_files": len(records),
        "artifacts": records,
    }

    output_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[+] Manifest written to {output_file} ({len(records)} files hashed).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SHA-256 forensic evidence manifest.")
    parser.add_argument("directory", type=Path, help="Target directory containing forensic artifacts")
    parser.add_argument("-o", "--output", type=Path, default=Path("evidence_manifest.json"), help="Output JSON file")
    args = parser.parse_args()

    if not args.directory.is_dir():
        raise SystemExit(f"Error: {args.directory} is not a valid directory.")

    generate_manifest(args.directory, args.output)
