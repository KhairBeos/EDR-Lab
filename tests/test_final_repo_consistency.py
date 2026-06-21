from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readme_references_phase_9_phase_10_and_protection_index() -> None:
    readme = read("README.md").lower()

    assert "phase 9" in readme
    assert "phase 10" in readme
    assert "demo case matrix" in readme
    assert "tp/tn/fp/fn" in readme
    assert "lab-only protection action" in readme
    assert "edr-protection-actions-*" in readme


def test_readme_uses_current_protection_safety_wording() -> None:
    readme = read("README.md").lower()

    assert "no production containment" in readme
    assert "lab-only kill-process" in readme
    assert "explicit" in readme
    assert "no real process kill" not in readme


def test_architecture_references_lab_only_protection_and_reporting() -> None:
    architecture = read("docs/architecture.md").lower()

    assert "lab-only protection action path" in architecture
    assert "edr-protection-actions-*" in architecture
    assert "dashboard / reporting" in architecture
    assert "safe-by-default" in architecture
    assert "no production containment is implemented" in architecture


def test_known_stubs_and_future_work_exists_and_marks_stub_categories() -> None:
    path = ROOT / "docs" / "known_stubs_and_future_work.md"
    assert path.exists()

    content = path.read_text(encoding="utf-8").lower()
    required_categories = [
        "behavioral stubs",
        "ml model stubs",
        "sigma compiler stub",
        "threat intel stubs",
        "containment legacy stubs",
        "detection validator placeholder",
        "placeholder ci workflows",
    ]

    for category in required_categories:
        assert category in content

    assert "not an mvp claim" in content
    assert "future work" in content


def test_placeholder_workflows_are_manual_only_and_clear() -> None:
    workflow_paths = [
        ROOT / ".github" / "workflows" / "detection-ci.yml",
        ROOT / ".github" / "workflows" / "rule-deploy.yml",
    ]

    for path in workflow_paths:
        if not path.exists():
            continue

        content = path.read_text(encoding="utf-8").lower()

        assert "workflow_dispatch" in content
        assert "future-work" in content or "placeholder" in content
        assert ".github/workflows/ci.yml" in content
        assert re.search(r"(?m)^\s*push\s*:", content) is None
        assert re.search(r"(?m)^\s*pull_request\s*:", content) is None


def test_pytest_temp_directory_guidance_exists() -> None:
    candidate_paths = [
        ROOT / "pytest.ini",
        ROOT / "pyproject.toml",
        ROOT / "setup.cfg",
        ROOT / "README.md",
        ROOT / "docs" / "cicd.md",
    ]

    combined = "\n".join(
        path.read_text(encoding="utf-8").lower()
        for path in candidate_paths
        if path.exists()
    )

    assert ".pytest_tmp" in combined or "--basetemp=.pytest_tmp" in combined


def test_completed_scratch_implementation_statuses_are_done() -> None:
    issue_files = list((ROOT / ".scratch").glob("*/issues/*.md"))
    design_files = list((ROOT / ".scratch").glob("*/design-*.md"))

    assert issue_files

    stale_files = []
    for path in issue_files + design_files:
        first_line = path.read_text(encoding="utf-8").splitlines()[0].strip().lower()
        if first_line in {"status: ready-for-agent", "status: design-only"}:
            stale_files.append(path.relative_to(ROOT).as_posix())

    assert stale_files == []
