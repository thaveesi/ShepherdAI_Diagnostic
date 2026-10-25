"""Prepare one review packet per distinct skill: blanked file copies plus the static scan.

The review reads only the packet folder, never the original skill. File copies come from the
scanner's collector, which blanks secret values as it reads; the static scan is the same rule set
the offline report uses, run on the original folder, with its text blanked the same way.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shepherd_scan._vendor import skillrules
from shepherd_scan._vendor.discovery.models import SkillFile
from shepherd_scan._vendor.discovery.redact import redact_text
from shepherd_scan._vendor.discovery.utils import get_relative_path
from shepherd_scan.discovery import Discovery
from shepherd_scan.names import agent_name


@dataclass
class SkillSource:
    """A distinct skill and everywhere it is installed."""

    name: str
    folder: Path
    files: list[SkillFile]
    install_locations: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        """Fingerprint of the skill's files, so copies installed in several places count once."""
        hasher = hashlib.sha256()
        for skill_file in sorted(self.files, key=lambda item: item.path):
            hasher.update(skill_file.path.encode("utf-8", "surrogatepass"))
            hasher.update(b"\0")
            hasher.update(skill_file.content.encode("utf-8", "replace"))
            hasher.update(b"\0")
        return hasher.hexdigest()


def skills_on_this_computer(discovery: Discovery) -> tuple[list[SkillSource], list[str]]:
    """Distinct skills found by discovery, and a note for each skill that could not be read."""
    distinct: dict[str, SkillSource] = {}
    skipped: list[str] = []
    for path in discovery.paths:
        agent = agent_name(path.client)
        for skill in path.skills:
            if skill.error is not None or not skill.files:
                skipped.append(f"{skill.name}: {get_relative_path(skill.installation_path)}")
                continue
            source = SkillSource(skill.name, Path(skill.installation_path), list(skill.files))
            entry = distinct.setdefault(source.digest, source)
            location = get_relative_path(skill.installation_path)
            if location not in entry.install_locations:
                entry.install_locations.append(location)
            if agent not in entry.agents:
                entry.agents.append(agent)
    return list(distinct.values()), sorted(set(skipped))


def static_scan(folder: Path) -> dict[str, Any]:
    """The rule set's findings for one skill, with secrets and the folder's location removed.

    Files the rules cannot read leave the packet marked ``not_scanned``; its files are still
    sent for review.
    """
    try:
        if folder.is_file():
            content = folder.read_text(encoding="utf-8", errors="replace")
            findings = skillrules.check_prompt_injection(content, folder.name)
            findings += skillrules.check_obfuscation(content, folder.name)
            findings += skillrules.check_secrets(content, folder.name)
            result: dict[str, Any] = {"findings": findings, "total_findings": len(findings)}
        else:
            result = skillrules.scan_skill(folder)
        result.pop("skill_dir", None)
        return _blank(result)
    except Exception as error:  # one add-on's odd file must not stop the whole package
        return {"findings": [], "total_findings": 0, "not_scanned": type(error).__name__}


def write_packet(
    source: SkillSource, skill_id: str, skills_dir: Path, *, folder_name: str | None
) -> dict[str, Any]:
    """Write the packet folder for one skill and return its summary.

    ``folder_name`` is the skill's original folder name, sent for review; None withholds it
    (blind samples, whose folder names could give the answer away).
    """
    target = skills_dir / skill_id
    files_dir = target / "files"
    files_dir.mkdir(parents=True)
    written: list[dict[str, Any]] = []
    for skill_file in source.files:
        destination = (files_dir / skill_file.path).resolve()
        if not destination.is_relative_to(files_dir.resolve()):
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(skill_file.content, encoding="utf-8")
        written.append({"path": skill_file.path, "characters": len(skill_file.content)})
    packet = {
        "id": skill_id,
        "name": source.name,
        "folder_name": folder_name,
        "install_locations": source.install_locations,
        "agents": source.agents,
        "files": written,
        "static_scan": static_scan(source.folder),
    }
    (target / "packet.json").write_text(json.dumps(packet, indent=1, default=str), encoding="utf-8")
    return packet


def _json_key(key: Any) -> Any:
    """A header key as JSON writes it: text, numbers, booleans and null as they are."""
    return key if key is None or isinstance(key, str | int | float | bool) else str(key)


def _blank(value: Any) -> Any:
    """Blank secret values in every string of a nested structure."""
    if isinstance(value, str):
        return redact_text(value) or ""
    if isinstance(value, list):
        return [_blank(item) for item in value]
    if isinstance(value, dict):
        return {_json_key(key): _blank(item) for key, item in value.items()}
    return value
