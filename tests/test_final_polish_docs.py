from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readme_references_phase_1_through_phase_7() -> None:
    readme = read_text("README.md")

    for phase in range(1, 8):
        assert f"Phase {phase}" in readme


def test_readme_references_final_operator_docs() -> None:
    readme = read_text("README.md")

    assert "CI/CD" in readme
    assert "Windows VM" in readme
    assert "Docker Lab" in readme
    assert "Final Demo Report" in readme
    assert "docs/architecture.md" in readme
    assert "docs/windows_vm_lab_setup.md" in readme
    assert "docs/docker_lab_setup.md" in readme
    assert "docs/cicd.md" in readme
    assert "docs/final_demo_script.md" in readme
    assert "docs/final_demo_report_mvp.md" in readme


def test_ci_workflow_exists_and_runs_pytest_suite() -> None:
    workflow = read_text(".github/workflows/ci.yml")

    assert "actions/checkout" in workflow
    assert "actions/setup-python" in workflow
    assert "python -m pytest tests" in workflow


def test_architecture_doc_has_required_runtime_references() -> None:
    architecture = read_text("docs/architecture.md")

    assert "```mermaid" in architecture
    assert "edr-normalized-events-*" in architecture
    assert "edr-alerts-native-*" in architecture
    assert "edr-response-actions-*" in architecture
    assert "normalized-events" in architecture


def test_lab_docs_exist_and_cover_manual_boundaries() -> None:
    docker_doc = read_text("docs/docker_lab_setup.md")
    vm_doc = read_text("docs/windows_vm_lab_setup.md")

    assert "docker compose up -d" in docker_doc
    assert "docker-compose.kafka.yml" in docker_doc
    assert "Port 9092" in docker_doc
    assert "Sysmon Event ID 1" in vm_doc
    assert "Atomic Red Team" in vm_doc
    assert "not required for tests" in vm_doc
