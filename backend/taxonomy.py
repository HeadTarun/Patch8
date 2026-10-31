"""Small adapter for MITRE's versioned CWE XML schema."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

_XML_RELATIVE = Path("data") / "cwe" / "full" / "cwec_v5.0.xml"
XML_PATH = next(path for path in (Path(__file__).parent / _XML_RELATIVE, Path(__file__).parent.parent / _XML_RELATIVE) if path.is_file())
MITRE_BASE = "https://cwe.mitre.org/data/definitions/"
EXPECTED_VERSION = "5.0"
NS = {"c": "http://cwe.mitre.org/cwe-8"}
ALLOWED_IDS = {"120", "121", "122", "476"}


def _text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join(" ".join(element.itertext()).split())


@lru_cache(maxsize=1)
def catalog() -> dict:
    root = ET.parse(XML_PATH).getroot()
    version = root.get("Version", "unknown")
    if version != EXPECTED_VERSION:
        raise RuntimeError(f"Expected CWE {EXPECTED_VERSION}, found {version}")

    top25_ranks = {}
    top25 = next((view for view in root.findall("c:Views/c:View", NS) if view.get("ID") == "1435"), None)
    if top25 is not None:
        for rank, member in enumerate(top25.findall("c:Members/c:Has_Member", NS), start=1):
            top25_ranks[member.get("CWE_ID", "")] = rank

    weaknesses = {}
    for weakness in root.findall("c:Weaknesses/c:Weakness", NS):
        weakness_id = weakness.get("ID", "")
        if not weakness_id.isdigit():
            continue
        mapping_notes = weakness.find("c:Mapping_Notes", NS)
        mapping = weakness.find("c:Mapping_Notes/c:Usage", NS)
        mitigations = []
        for item in weakness.findall("c:Potential_Mitigations/c:Mitigation", NS):
            note = _text(item.find("c:Description", NS))
            if note:
                mitigations.append(note)
        weaknesses[weakness_id] = {
            "id": f"CWE-{weakness_id}",
            "name": weakness.get("Name", "Unknown weakness"),
            "abstraction": weakness.get("Abstraction", "Unknown"),
            "status": weakness.get("Status", "Unknown"),
            "description": _text(weakness.find("c:Description", NS)),
            "mapping_usage": (mapping_notes.get("Usage", "") if mapping_notes is not None else "") or _text(mapping),
            "top25_2025_rank": top25_ranks.get(weakness_id),
            "mitigations": mitigations[:4],
            "url": f"{MITRE_BASE}{weakness_id}.html",
        }
    return {"version": version, "schema": "8.0", "weaknesses": weaknesses}


def get_weakness(weakness_id: str) -> dict | None:
    match = re.fullmatch(r"(?:CWE-)?(\d+)", weakness_id.strip(), re.IGNORECASE)
    if not match:
        return None
    return catalog()["weaknesses"].get(match.group(1))


def supported_weaknesses() -> list[dict]:
    all_weaknesses = catalog()["weaknesses"]
    return [all_weaknesses[item] for item in sorted(ALLOWED_IDS, key=int)]
