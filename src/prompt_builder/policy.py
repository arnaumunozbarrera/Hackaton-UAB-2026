"""SOC policy: severity matrix, adjustments, SLA, approvals and mandatory escalation.

Why: the final severity must follow politica_soc.md. The prompt carries the relevant sections verbatim and a
pre-computed *base* severity (rule severity x most critical affected asset or identity), so the LLM only has to
justify the +-1 adjustment instead of re-deriving the matrix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CRITICALITY_ORDER = ("Baja", "Media", "Alta", "Crítica")
SECTIONS = ("2", "3", "4", "5", "6")  # matrix, SLA, approvals, escalation, grouping


@dataclass(frozen=True)
class Policy:
    matrix: dict[tuple[str, str], str]  # (rule_severity, criticality) -> base severity
    sections: dict[str, str]  # section number -> markdown text

    def base_severity(self, rule_severity: str, criticality: str) -> str | None:
        return self.matrix.get((rule_severity, criticality))

    def row(self, rule_severity: str) -> str:
        """Matrix row of one rule severity, e.g. 'Baja=low, Media=medium, ...'."""
        return ", ".join(
            f"{c}={self.matrix[(rule_severity, c)]}" for c in CRITICALITY_ORDER if (rule_severity, c) in self.matrix
        )

    def compact(self, numbers: tuple[str, ...] = SECTIONS) -> str:
        """Compact text of the policy sections (the matrix itself is given per alert as one row)."""
        return "\n".join(_compact_section(self.sections[n], n == "2") for n in numbers if n in self.sections)

    def text(self, numbers: tuple[str, ...] = SECTIONS) -> str:
        """Selected sections, headings demoted to ### so they nest under the prompt's own sections."""
        parts = [re.sub(r"^## \d+\.\s*", "### ", self.sections[n]) for n in numbers if n in self.sections]
        return "\n\n".join(parts)


def _clean(line: str) -> str:
    return line.replace("**", "").replace("`", "").strip()


def _compact_section(text: str, drop_tables: bool) -> str:
    """Markdown section -> short lines: tables become 'a: b · c', bullets kept, blank lines removed."""
    lines = text.splitlines()
    title = re.sub(r"^## \d+\.\s*", "", lines[0]).strip()
    out = ["Ajustes de severidad (máximo ±1 en total):" if drop_tables else f"{title}:"]
    for raw in lines[1:]:
        line = _clean(raw)
        if not line or "---" in line:
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if drop_tables or cells[0] in ("Severidad", "Acción", "Regla \\ Activo"):
                continue
            rest = [c for c in cells[1:] if c and c != "—"]
            out.append(f"- {cells[0]}: {' · '.join(rest)}")
        elif not drop_tables or line.startswith("-"):
            out.append(line if line.startswith("-") else f"- {line}")
    return "\n".join(out)


def _split_sections(text: str) -> dict[str, str]:
    parts = re.split(r"(?m)^## (\d+)\.", text)
    return {parts[i]: f"## {parts[i]}.{parts[i + 1]}".strip() for i in range(1, len(parts) - 1, 2)}


def _parse_matrix(section: str) -> dict[tuple[str, str], str]:
    rows = [r for r in section.splitlines() if r.startswith("|") and "---" not in r]
    header = [c.strip() for c in rows[0].strip("|").split("|")]
    matrix = {}
    for row in rows[1:]:
        cells = [c.strip() for c in row.strip("|").split("|")]
        for criticality, value in zip(header[1:], cells[1:], strict=False):
            matrix[(cells[0], criticality)] = value
    return matrix


def load_policy(path: str | Path) -> Policy:
    """Parse politica_soc.md."""
    sections = _split_sections(Path(path).read_text(encoding="utf-8"))
    return Policy(_parse_matrix(sections["2"]), sections)


def most_critical(levels: list[str]) -> str | None:
    """Highest criticality in the list, following the matrix column order."""
    known = [lv for lv in levels if lv in CRITICALITY_ORDER]
    return max(known, key=CRITICALITY_ORDER.index) if known else None
