"""Typed demo case catalog for the Phase 9 teacher demo."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

CATEGORIES = ("attack", "benign", "limitation")
INPUT_TYPES = ("fixture", "xml", "json")
ENGINES = ("native", "sigma-like", "all", "ml-anomaly", "behavioral")
EXPECTED_PROTECTIONS = ("none", "dry-run", "execute-lab-only")
RUNNER_MODES = ("phase8", "live", "ml", "behavioral")


class DemoCaseCatalogError(ValueError):
    """Raised when the demo case catalog is invalid."""


@dataclass(frozen=True)
class DemoCase:
    case_id: str
    name: str
    category: str
    input_type: str
    engine: str
    expected_alert: bool
    expected_engines: tuple[str, ...]
    expected_rule_ids: tuple[str, ...]
    expected_response: bool
    expected_protection: str
    description: str
    teacher_demo_notes: str
    technique_id: str | None = None
    input_path: Path | None = None
    runner_mode: str = "phase8"


def load_demo_cases() -> list[DemoCase]:
    """Return the deterministic Phase 9 demo catalog."""

    cases = [
        DemoCase(
            case_id="attack_t1059_001_art_powershell_xml",
            name="Atomic Red Team T1059.001 PowerShell XML",
            category="attack",
            technique_id="T1059.001",
            input_type="xml",
            input_path=REPO_ROOT / "samples" / "sysmon" / "art_t1059_001_powershell_event.xml",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=(
                "det.t1059_001.powershell_process_start",
                "sigma_like.t1059_001.powershell_process_start",
            ),
            expected_response=True,
            expected_protection="dry-run",
            description="Safe Atomic Red Team backed PowerShell marker exported as Sysmon Event ID 1 XML.",
            teacher_demo_notes="Main live VM path: ART activity -> Sysmon XML -> native/Sigma-like alerts -> SOAR dry-run.",
        ),
        DemoCase(
            case_id="attack_t1059_001_fixture_powershell",
            name="Detectable PowerShell fixture",
            category="attack",
            technique_id="T1059.001",
            input_type="fixture",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=(
                "det.t1059_001.powershell_process_start",
                "sigma_like.t1059_001.powershell_process_start",
            ),
            expected_response=True,
            expected_protection="dry-run",
            description="Deterministic fixture path that mutates the base Sysmon fixture into detectable PowerShell.",
            teacher_demo_notes="Use this when the VM is unavailable; it proves the same detection engines deterministically.",
        ),
        DemoCase(
            case_id="attack_ml_encoded_download_json",
            name="ML-style encoded/download indicators",
            category="attack",
            technique_id="T1059.001",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "sysmon" / "ml_suspicious_process_event.json",
            engine="ml-anomaly",
            expected_alert=True,
            expected_engines=("ml-anomaly",),
            expected_rule_ids=("ml.process_anomaly",),
            expected_response=False,
            expected_protection="none",
            description="Crafted normalized ECS-like JSON with encoded-command and download-keyword indicators.",
            teacher_demo_notes="Shows the ML-style heuristic path without downloading or executing anything.",
            runner_mode="ml",
        ),
        DemoCase(
            case_id="attack_t1059_001_safe_manual_marker_xml",
            name="Safe manual PowerShell marker XML",
            category="attack",
            technique_id="T1059.001",
            input_type="xml",
            input_path=REPO_ROOT / "samples" / "sysmon" / "demo_cases" / "safe_manual_marker_powershell.xml",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=(
                "det.t1059_001.powershell_process_start",
                "sigma_like.t1059_001.powershell_process_start",
            ),
            expected_response=True,
            expected_protection="dry-run",
            description="Safe manual fallback command for T1059.001 when Atomic Red Team is not available.",
            teacher_demo_notes="Clearly label this as fallback, not the primary attack simulator.",
        ),
        DemoCase(
            case_id="attack_t1059_001_atomic_marker_json",
            name="Atomic marker suspicious normalized JSON",
            category="attack",
            technique_id="T1059.001",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "atomic_marker_ml_event.json",
            engine="ml-anomaly",
            expected_alert=True,
            expected_engines=("ml-anomaly",),
            expected_rule_ids=("ml.process_anomaly",),
            expected_response=False,
            expected_protection="none",
            description="Safe normalized JSON derived from an Atomic Red Team style marker for ML anomaly scoring.",
            teacher_demo_notes="A local sample for the teacher demo; it is data only and does not execute commands.",
            runner_mode="ml",
        ),
        DemoCase(
            case_id="benign_cmd_whoami_fixture",
            name="Benign cmd whoami fixture",
            category="benign",
            input_type="fixture",
            engine="all",
            expected_alert=False,
            expected_engines=(),
            expected_rule_ids=(),
            expected_response=False,
            expected_protection="none",
            description="Existing Sysmon Event ID 1 fixture without PowerShell mutation.",
            teacher_demo_notes="Demonstrates a true negative for normal command execution.",
            runner_mode="live",
        ),
        DemoCase(
            case_id="benign_explorer_cmd_json",
            name="Benign explorer-launched cmd JSON",
            category="benign",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "benign_explorer_cmd_event.json",
            engine="ml-anomaly",
            expected_alert=False,
            expected_engines=(),
            expected_rule_ids=(),
            expected_response=False,
            expected_protection="none",
            description="Normal cmd.exe /c whoami normalized JSON expected to score below ML threshold.",
            teacher_demo_notes="Demonstrates a true negative in the ML-style path.",
            runner_mode="ml",
        ),
        DemoCase(
            case_id="analysis_fp_admin_powershell_inventory",
            name="Admin PowerShell inventory analysis FP",
            category="benign",
            technique_id="T1059.001",
            input_type="xml",
            input_path=REPO_ROOT / "samples" / "sysmon" / "demo_cases" / "admin_powershell_inventory.xml",
            engine="all",
            expected_alert=False,
            expected_engines=(),
            expected_rule_ids=(),
            expected_response=False,
            expected_protection="none",
            description="Safe admin inventory command that currently matches broad PowerShell process-start rules.",
            teacher_demo_notes="Intentional false positive; future tuning could add context, allowlists, or risk scoring.",
        ),
        DemoCase(
            case_id="limitation_fn_non_powershell_execution",
            name="Non-PowerShell script host limitation FN",
            category="limitation",
            technique_id="T1059",
            input_type="xml",
            input_path=REPO_ROOT / "samples" / "sysmon" / "demo_cases" / "wscript_marker.xml",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=("future.non_powershell_execution",),
            expected_response=False,
            expected_protection="none",
            description="Safe wscript marker showing current MVP coverage does not include non-PowerShell execution.",
            teacher_demo_notes="Intentional false negative; use it to explain scoped detection coverage.",
            runner_mode="live",
        ),
        DemoCase(
            case_id="benign_ml_common_process_json",
            name="Benign ML common process JSON",
            category="benign",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "benign_ml_common_process_event.json",
            engine="ml-anomaly",
            expected_alert=False,
            expected_engines=(),
            expected_rule_ids=(),
            expected_response=False,
            expected_protection="none",
            description="Common parent/child process pair expected to remain below anomaly threshold.",
            teacher_demo_notes="A second true negative for the local deterministic ML path.",
            runner_mode="ml",
        ),
        DemoCase(
            case_id="attack_t1105_process_lolbin_download_json",
            name="T1105 LOLBin process download marker JSON",
            category="attack",
            technique_id="T1105",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "t1105_certutil_process_event.json",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=("det.t1105.lolbin_download", "sigma_like.t1105.lolbin_download"),
            expected_response=False,
            expected_protection="none",
            description="Safe certutil process command line with local T1105 demo marker.",
            teacher_demo_notes="Shows Command and Control transfer semantics without downloading anything external.",
        ),
        DemoCase(
            case_id="attack_t1105_network_lolbin_download_json",
            name="T1105 LOLBin network connection JSON",
            category="attack",
            technique_id="T1105",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "t1105_certutil_network_event.json",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=("det.t1105.lolbin_download", "sigma_like.t1105.lolbin_download"),
            expected_response=False,
            expected_protection="none",
            description="Safe Sysmon Event ID 3 style network connection to 127.0.0.1/example.test.",
            teacher_demo_notes="Highlights Event ID 3 evidence for transfer behavior.",
        ),
        DemoCase(
            case_id="attack_t1105_file_create_download_json",
            name="T1105 downloaded file create JSON",
            category="attack",
            technique_id="T1105",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "t1105_file_create_event.json",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=("det.t1105.lolbin_download", "sigma_like.t1105.lolbin_download"),
            expected_response=False,
            expected_protection="none",
            description="Safe Sysmon Event ID 11 style file create in Downloads with edr_demo marker.",
            teacher_demo_notes="Highlights file evidence for an ingress transfer story.",
        ),
        DemoCase(
            case_id="attack_t1547_001_registry_run_key_json",
            name="T1547.001 Registry Run key persistence JSON",
            category="attack",
            technique_id="T1547.001",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "t1547_registry_run_key_event.json",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=(
                "det.t1547_001.registry_run_key_persistence",
                "sigma_like.t1547_001.registry_run_key_persistence",
            ),
            expected_response=False,
            expected_protection="none",
            description="Safe Sysmon Event ID 13 style Run key value with explicit demo marker.",
            teacher_demo_notes="Shows Persistence coverage without creating a real registry value.",
        ),
        DemoCase(
            case_id="attack_t1218_rundll32_lolbin_json",
            name="T1218 rundll32 LOLBin marker JSON",
            category="attack",
            technique_id="T1218",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "t1218_rundll32_process_event.json",
            engine="all",
            expected_alert=True,
            expected_engines=("native", "sigma-like"),
            expected_rule_ids=("det.t1218.lolbin_suspicious_execution", "sigma_like.t1218.lolbin_suspicious_execution"),
            expected_response=False,
            expected_protection="none",
            description="Safe rundll32 command line with T1218-lite marker.",
            teacher_demo_notes="Label this as T1218-lite; it is deterministic demo coverage, not complete LOLBin analytics.",
        ),
        DemoCase(
            case_id="attack_behavioral_t1105_sequence_json",
            name="Behavioral T1105 process/network/file sequence JSON",
            category="attack",
            technique_id="T1105",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "behavioral_t1105_sequence.json",
            engine="behavioral",
            expected_alert=True,
            expected_engines=("behavioral",),
            expected_rule_ids=("det.behavioral.t1105_download_sequence",),
            expected_response=False,
            expected_protection="none",
            description="Correlates safe process, network, and file evidence for a local T1105 download story.",
            teacher_demo_notes="Shows Phase 14 behavioral correlation without changing single-event T1105 rules.",
            runner_mode="behavioral",
        ),
        DemoCase(
            case_id="attack_behavioral_t1547_001_sequence_json",
            name="Behavioral T1547.001 process/registry sequence JSON",
            category="attack",
            technique_id="T1547.001",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "behavioral_t1547_sequence.json",
            engine="behavioral",
            expected_alert=True,
            expected_engines=("behavioral",),
            expected_rule_ids=("det.behavioral.t1547_001_registry_persistence_sequence",),
            expected_response=False,
            expected_protection="none",
            description="Correlates safe process and registry evidence for a local Run key persistence story.",
            teacher_demo_notes="Shows Phase 14 persistence correlation with deterministic local JSON events.",
            runner_mode="behavioral",
        ),
        DemoCase(
            case_id="benign_behavioral_unrelated_sequence_json",
            name="Benign unrelated behavioral sequence JSON",
            category="benign",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "behavioral_benign_unrelated_sequence.json",
            engine="behavioral",
            expected_alert=False,
            expected_engines=(),
            expected_rule_ids=(),
            expected_response=False,
            expected_protection="none",
            description="Unrelated process and network events that should not form a behavioral sequence.",
            teacher_demo_notes="True negative for the Phase 14 behavioral engine.",
            runner_mode="behavioral",
        ),
        DemoCase(
            case_id="benign_phase13_network_json",
            name="Benign network connection JSON",
            category="benign",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "benign_network_event.json",
            engine="all",
            expected_alert=False,
            expected_engines=(),
            expected_rule_ids=(),
            expected_response=False,
            expected_protection="none",
            description="Normal service network connection without demo markers.",
            teacher_demo_notes="True negative for Event ID 3 style telemetry.",
        ),
        DemoCase(
            case_id="benign_phase13_file_create_json",
            name="Benign file create JSON",
            category="benign",
            input_type="json",
            input_path=REPO_ROOT / "samples" / "demo_cases" / "benign_file_create_event.json",
            engine="all",
            expected_alert=False,
            expected_engines=(),
            expected_rule_ids=(),
            expected_response=False,
            expected_protection="none",
            description="Normal file creation outside Downloads without edr_demo marker.",
            teacher_demo_notes="True negative for Event ID 11 style telemetry.",
        ),
    ]
    validate_demo_cases(cases)
    return cases


def validate_demo_cases(cases: list[DemoCase]) -> None:
    """Validate catalog integrity."""

    seen: set[str] = set()
    for case in cases:
        if not case.case_id:
            raise DemoCaseCatalogError("case_id is required.")
        if case.case_id in seen:
            raise DemoCaseCatalogError(f"Duplicate case_id: {case.case_id}.")
        seen.add(case.case_id)
        if case.category not in CATEGORIES:
            raise DemoCaseCatalogError(f"{case.case_id} has invalid category {case.category!r}.")
        if case.input_type not in INPUT_TYPES:
            raise DemoCaseCatalogError(f"{case.case_id} has invalid input_type {case.input_type!r}.")
        if case.engine not in ENGINES:
            raise DemoCaseCatalogError(f"{case.case_id} has invalid engine {case.engine!r}.")
        if case.expected_protection not in EXPECTED_PROTECTIONS:
            raise DemoCaseCatalogError(
                f"{case.case_id} has invalid expected_protection {case.expected_protection!r}."
            )
        if case.runner_mode not in RUNNER_MODES:
            raise DemoCaseCatalogError(f"{case.case_id} has invalid runner_mode {case.runner_mode!r}.")
        if case.category == "attack" and case.expected_alert and not case.expected_engines and not case.expected_rule_ids:
            raise DemoCaseCatalogError(f"{case.case_id} expected attack alert must define engines or rule IDs.")
        if case.expected_protection == "execute-lab-only":
            raise DemoCaseCatalogError(f"{case.case_id} execute-lab-only is documentation-only and unsupported.")
