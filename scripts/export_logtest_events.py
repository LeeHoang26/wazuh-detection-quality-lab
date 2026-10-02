"""Export fixture JSON for decoder inspection, not EventChannel rule validation."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test-cases" / "manifest.json"
OUTPUT = ROOT / "reports" / "logtest-inputs"


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for item in manifest["cases"]:
        fixture = json.loads((ROOT / item["fixture"]).read_text(encoding="utf-8-sig"))
        output_path = OUTPUT / f"{item['case_id']}.json"
        output_path.write_text(json.dumps(fixture["data"], separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"exported {len(manifest['cases'])} JSON decoder inputs to {OUTPUT}")
    print("Note: pasted JSON uses the json decoder, not the Windows EventChannel decoder.")


if __name__ == "__main__":
    main()
