from maintenance_man import output
from maintenance_man.models.scan import (
    UpdateFinding,
    VulnFinding,
    sort_vulns_by_severity,
)

type Selection = tuple[list[VulnFinding], list[UpdateFinding]]


def print_numbered_findings(
    vulns: list[VulnFinding], updates: list[UpdateFinding]
) -> list[VulnFinding | UpdateFinding]:
    numbered: list[VulnFinding | UpdateFinding] = [
        *sort_vulns_by_severity(vulns),
        *updates,
    ]
    rows = []
    for finding in numbered:
        owner = ""
        if isinstance(finding, VulnFinding):
            kind = "! vuln"
            risk = f"{finding.severity.value.lower()} · {finding.vuln_id}"
            if finding.gradle_target is not None:
                target = finding.gradle_target
                owner = (
                    f" via {target.display_name} "
                    f"{target.members[0].installed_version} → {target.target_version}"
                )
        else:
            kind = "~ update"
            risk = finding.semver_tier.value
        rows.append(
            (
                kind,
                risk,
                f"{finding.installed_version} → {finding.target_version}",
                finding.pkg_name + owner,
            )
        )
    output.choices(rows)
    return numbered


def parse_selection(
    text: str,
    numbered: list[VulnFinding | UpdateFinding],
    vulns: list[VulnFinding],
    updates: list[UpdateFinding],
) -> Selection | None:
    """The chosen findings for a keyword or comma-separated numbers, else None."""
    choice = text.strip().lower()
    keywords = {
        "all": (vulns, updates),
        "none": ([], []),
        "vulns": (vulns, []),
        "updates": ([], updates),
    }
    if choice in keywords:
        return keywords[choice]
    try:
        indices = [int(part) for part in choice.split(",")]
    except ValueError:
        return None
    if not all(1 <= index <= len(numbered) for index in indices):
        return None
    selected = [numbered[index - 1] for index in dict.fromkeys(indices)]
    return (
        [finding for finding in selected if isinstance(finding, VulnFinding)],
        [finding for finding in selected if isinstance(finding, UpdateFinding)],
    )


def choose_findings(
    selectable_vulns: list[VulnFinding],
    selectable_updates: list[UpdateFinding],
) -> Selection:
    numbered = print_numbered_findings(selectable_vulns, selectable_updates)
    parts = [
        "all",
        *(["vulns"] if selectable_vulns else []),
        *(["updates"] if selectable_updates else []),
        "1,2,...",
        "none",
    ]
    message = f"Select updates [{'/'.join(parts)}]"
    while True:
        text = output.prompt(message, default="all")
        selection = parse_selection(
            text, numbered, selectable_vulns, selectable_updates
        )
        if selection is not None:
            return selection
        output.diagnostic("error", f"Invalid selection: {text}")
