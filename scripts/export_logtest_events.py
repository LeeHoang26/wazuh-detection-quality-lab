"""Export only the Wazuh event body from each fixture for wazuh-logtest."""

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
    print(f"exported {len(manifest['cases'])} wazuh-logtest inputs to {OUTPUT}")


if __name__ == "__main__":
    main()
