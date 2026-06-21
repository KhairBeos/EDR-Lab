from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_rehearsal_doc_exists_and_has_timing_target() -> None:
    path = ROOT / "docs" / "final_teacher_demo_rehearsal.md"

    assert path.exists()
    assert "7 to 10 minutes" in path.read_text(encoding="utf-8")


def test_rehearsal_includes_exact_core_commands() -> None:
    doc = read("docs/final_teacher_demo_rehearsal.md")

    assert "python -m pytest tests --basetemp=.pytest_tmp_demo" in doc
    assert "python scripts\\reporting\\generate_detection_coverage_report.py" in doc
    assert "python scripts\\reporting\\generate_final_demo_report.py" in doc
    assert "python scripts\\demo\\run_demo_case_matrix.py --output reports\\demo_cases\\case_matrix.json" in doc
    assert "python scripts\\demo\\generate_demo_dashboard_data.py --case-matrix reports\\demo_cases\\case_matrix.json --output reports\\demo_cases\\dashboard_data.json" in doc
    assert "python scripts\\reporting\\generate_attack_navigator_layer.py" in doc
    assert "python scripts\\demo\\build_demo_evidence_bundle.py --output-dir reports\\demo_evidence" in doc


def test_rehearsal_mentions_kibana_navigator_fallbacks_and_safety() -> None:
    doc = read("docs/final_teacher_demo_rehearsal.md").lower()

    assert "kibana" in doc
    assert "att&ck navigator" in doc
    assert "fallback" in doc
    assert "elasticsearch or kibana is unavailable" in doc
    assert "windows vm or atomic red team is unavailable" in doc
    assert "lab-only" in doc
    assert "execute-protection" in doc
    assert "lab-allow-execute" in doc


def test_talk_track_exists_and_covers_required_demo_story() -> None:
    path = ROOT / "docs" / "final_teacher_demo_talk_track.md"
    assert path.exists()

    doc = path.read_text(encoding="utf-8").lower()
    for phrase in [
        "tp",
        "tn",
        "fp",
        "fn",
        "behavioral correlation",
        "lab-only",
        "native detection",
        "sigma-like detection",
        "ml anomaly detection",
        "t1059.001",
        "t1105",
        "t1547.001",
        "t1218-lite",
        "soar is dry-run",
        "do not hide fp/fn",
        "not full att&ck coverage",
        "no production containment",
    ]:
        assert phrase in doc


def test_submission_checklist_mentions_required_submission_items() -> None:
    path = ROOT / "docs" / "final_submission_checklist.md"
    assert path.exists()

    doc = path.read_text(encoding="utf-8").lower()
    for phrase in [
        "tests pass",
        "reports regenerated",
        "case matrix regenerated",
        "dashboard data regenerated",
        "navigator layer generated",
        "evidence bundle generated",
        "readme.md",
        "docs/architecture.md",
        "screenshots captured",
        "vm xml sample exported",
        "protection remains dry-run",
        "git tag created",
    ]:
        assert phrase in doc


def test_evidence_checklist_mentions_final_generated_and_manual_artifacts() -> None:
    doc = read("reports/demo_evidence/demo_evidence_checklist.md").lower()

    for phrase in [
        "final_demo_report.md",
        "final_demo_report.json",
        "detection_coverage_report.md",
        "detection_coverage_report.json",
        "case_matrix.md",
        "case_matrix.json",
        "dashboard_data.json",
        "attack_navigator/edr_attack_layer.json",
        "attack_navigator/coverage_summary.md",
        "kibana screenshots",
        "optional vm sysmon exported xml",
        "optional protection execution screenshot",
        "missing optional screenshots or vm artifacts do not mean the deterministic demo failed",
    ]:
        assert phrase in doc


def test_readme_final_demo_section_mentions_phase_15_phase_16_and_links_docs() -> None:
    readme = read("README.md").lower()

    assert "phase 15/16" in readme
    assert "docs/final_teacher_demo_rehearsal.md" in readme
    assert "docs/final_teacher_demo_talk_track.md" in readme
    assert "docs/final_submission_checklist.md" in readme
