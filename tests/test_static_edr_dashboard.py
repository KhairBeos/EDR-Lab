import importlib.util
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_JSON = {
    "dashboard_data.json",
    "case_matrix.json",
    "final_demo_report.json",
    "detection_coverage_report.json",
}


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_static_dashboard_files_exist() -> None:
    for path in [
        "dashboard/static/index.html",
        "dashboard/static/app.js",
        "dashboard/static/styles.css",
        "dashboard/static/README.md",
    ]:
        assert (ROOT / path).exists()


def test_dashboard_mentions_project_name_and_required_sections() -> None:
    combined = "\n".join(
        [
            read("dashboard/static/index.html"),
            read("dashboard/static/app.js"),
        ]
    )

    for phrase in [
        "EDR Advanced Operator Dashboard",
        "ATT&CK Technique",
        "Detection Engine",
        "Severity",
        "Sysmon Event ID",
        "Case Matrix",
        "Recent Alerts",
        "Alert Detail",
    ]:
        assert phrase in combined


def test_dashboard_static_readme_documents_local_requirements() -> None:
    readme = read("dashboard/static/README.md").lower()

    for phrase in [
        "python scripts\\demo\\export_static_dashboard_data.py",
        "python -m http.server 8088 -d dashboard/static",
        "no npm",
        "no internet",
        "local deterministic demo",
        "not claim to be a production edr console",
    ]:
        assert phrase in readme


def test_dashboard_docs_mention_tp_tn_fp_fn_and_sysmon_event_ids() -> None:
    doc = read("docs/edr_operator_dashboard_demo.md")

    assert "TP/TN/FP/FN" in doc
    assert "Event ID 1" in doc
    assert "Event ID 3" in doc
    assert "Event ID 11" in doc
    assert "Event ID 13" in doc
    assert "not a production EDR console" in doc


def test_dashboard_classification_summary_uses_numeric_values_only() -> None:
    app = read("dashboard/static/app.js")
    html = read("dashboard/static/index.html")

    assert "<span>TP/TN/FP/FN</span>" in html
    assert "${matrixCounts.true_positive} / ${matrixCounts.true_negative} / ${matrixCounts.false_positive} / ${matrixCounts.false_negative}" in app
    assert "TP ${matrixCounts.true_positive}" not in app
    assert "TN ${matrixCounts.true_negative}" not in app
    assert "FP ${matrixCounts.false_positive}" not in app
    assert "FN ${matrixCounts.false_negative}" not in app


def test_dashboard_detail_key_value_layout_prevents_overlap() -> None:
    css = read("dashboard/static/styles.css")

    assert "grid-template-columns: minmax(0, 130px) minmax(0, 1fr);" in css
    assert ".detail-kv dt {\n  min-width: 0;" in css
    assert ".detail-kv dd {\n  min-width: 0;" in css
    assert "overflow-wrap: anywhere;" in css


def test_dashboard_docs_include_required_commands() -> None:
    doc = read("docs/edr_operator_dashboard_demo.md")

    for command in [
        "python scripts\\demo\\run_demo_case_matrix.py --output reports\\demo_cases\\case_matrix.json",
        "python scripts\\demo\\generate_demo_dashboard_data.py --case-matrix reports\\demo_cases\\case_matrix.json --output reports\\demo_cases\\dashboard_data.json",
        "python scripts\\reporting\\generate_detection_coverage_report.py",
        "python scripts\\reporting\\generate_final_demo_report.py",
        "python scripts\\demo\\export_static_dashboard_data.py",
        "python -m http.server 8088 -d dashboard/static",
    ]:
        assert command in doc


def test_export_script_writes_required_json_files_to_temp_static_data_dir(tmp_path: Path) -> None:
    module = load_export_module()
    output_dir = tmp_path / "static" / "data"

    written = module.export_static_dashboard_data(output_dir=output_dir)

    assert {path.name for path in written} == REQUIRED_JSON
    for filename in REQUIRED_JSON:
        assert (output_dir / filename).exists()


def test_generated_static_dashboard_data_exists() -> None:
    data_dir = ROOT / "dashboard" / "static" / "data"

    for filename in REQUIRED_JSON:
        assert (data_dir / filename).exists()


def test_index_has_no_external_cdn_links() -> None:
    html = read("dashboard/static/index.html")

    external_asset_links = re.findall(r"""(?:src|href)=["']https?://[^"']+["']""", html, flags=re.IGNORECASE)
    assert external_asset_links == []


def test_dashboard_tests_are_file_based_and_do_not_require_live_infrastructure() -> None:
    test_source = read("tests/test_static_edr_dashboard.py").lower()
    forbidden_terms = [
        "selen" + "ium",
        "play" + "wright",
        "elastic" + "search",
        "kib" + "ana",
        "dock" + "er",
        "kaf" + "ka",
    ]

    for forbidden in forbidden_terms:
        assert forbidden not in test_source


def load_export_module():
    path = ROOT / "scripts" / "demo" / "export_static_dashboard_data.py"
    spec = importlib.util.spec_from_file_location("export_static_dashboard_data", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
