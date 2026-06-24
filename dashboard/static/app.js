"use strict";

const DATA_PATHS = {
  dashboard: "data/dashboard_data.json",
  caseMatrix: "data/case_matrix.json",
  finalReport: "data/final_demo_report.json",
  coverage: "data/detection_coverage_report.json",
  realtimeSummary: "data/realtime_summary.json",
  realtimeAlerts: "data/realtime_alerts.json",
  realtimeEvents: "data/realtime_events.json",
  realtimeEvaluation: "data/realtime_evaluation.json",
};

const REALTIME_API_PORT = "8090";
const REALTIME_API_DEFAULT_BASE = "http://localhost:8090";
const REALTIME_API_BASES = buildRealtimeApiBases();
const REALTIME_REFRESH_MS = 2000;
const SECTION_LABELS = ["ATT&CK Technique", "Detection Engine", "Severity", "Sysmon Event ID", "Case Matrix", "Realtime Evaluation", "Recent Alerts", "Alert Detail"];
const TECHNIQUES = ["T1059.001", "T1105", "T1547.001", "T1218"];
const ENGINES = ["native", "sigma-like", "ml-anomaly", "behavioral"];
const SEVERITIES = ["low", "medium", "high", "critical", "unknown"];
const SYSMON_EVENTS = [
  { code: "1", label: "process creation" },
  { code: "3", label: "network connection" },
  { code: "11", label: "file creation" },
  { code: "13", label: "registry value set" },
];

const CLASSIFICATION_COPY = {
  true_positive: {
    short: "TP",
    css: "tp",
    text: "Expected malicious and at least one alert fired.",
  },
  true_negative: {
    short: "TN",
    css: "tn",
    text: "Expected benign and no alert fired.",
  },
  false_positive: {
    short: "FP",
    css: "fp",
    text: "Expected benign but an alert fired. Keep visible for demo honesty.",
  },
  false_negative: {
    short: "FN",
    css: "fn",
    text: "Expected malicious but no alert fired. Keep visible for coverage discussion.",
  },
  pending: {
    short: "PENDING",
    css: "pending",
    text: "Marker observed; waiting for the realtime evaluation window.",
  },
};

let selectedCaseId = null;
let selectedRealtimeAlertId = null;
let model = null;
let activeRealtimeApiBase = "";
let realtimeState = {
  connected: false,
  apiBase: "",
  summary: null,
  alerts: [],
  events: [],
  evaluation: null,
  lastError: "",
};

async function loadJson(path) {
  const response = await fetch(path);

  if (!response.ok) {
    throw new Error(`Failed to load ${path}: ${response.status}`);
  }

  return response.json();
}

function buildRealtimeApiBases() {
  const params = new URLSearchParams(window.location.search);
  const configuredApi = normalizeRealtimeApiBase(params.get("api") || "");
  const pageHost = hostForRealtimeApi(window.location.hostname);
  const sameHostApi = pageHost ? `http://${pageHost}:${REALTIME_API_PORT}` : "";
  return uniqueValues([configuredApi, sameHostApi, "http://127.0.0.1:8090", REALTIME_API_DEFAULT_BASE]);
}

function hostForRealtimeApi(hostname) {
  if (!hostname || hostname === "::" || hostname === "0.0.0.0") {
    return "127.0.0.1";
  }
  if (hostname.includes(":") && !hostname.startsWith("[")) {
    return `[${hostname}]`;
  }
  return hostname;
}

function normalizeRealtimeApiBase(value) {
  return value.trim().replace(/\/+$/, "");
}

function uniqueValues(values) {
  return [...new Set(values.filter(Boolean))];
}

function realtimeApiCandidates() {
  return activeRealtimeApiBase
    ? uniqueValues([activeRealtimeApiBase, ...REALTIME_API_BASES])
    : REALTIME_API_BASES;
}

async function boot() {
  try {
    const [dashboardData, caseMatrix, finalReport, coverageReport] = await Promise.all([
      loadJson(DATA_PATHS.dashboard),
      loadJson(DATA_PATHS.caseMatrix),
      loadJson(DATA_PATHS.finalReport),
      loadJson(DATA_PATHS.coverage),
    ]);

    model = buildViewModel({ dashboardData, caseMatrix, finalReport, coverageReport });
    selectedCaseId = model.rows[0]?.case_id || null;
    render(model);
    startRealtimePolling();
  } catch (error) {
    showError(error);
  }
}

function buildViewModel({ dashboardData, caseMatrix, finalReport, coverageReport }) {
  const ruleInventory = Array.isArray(coverageReport.rule_inventory) ? coverageReport.rule_inventory : [];
  const ruleLookup = Object.fromEntries(ruleInventory.map((rule) => [rule.rule_id, rule]));
  const caseLookup = Object.fromEntries((caseMatrix.cases || []).map((row) => [row.case_id, row]));
  const rows = (dashboardData.case_rows || caseMatrix.cases || []).map((row) =>
    normalizeRow({ row, caseLookup, ruleLookup }),
  );

  return {
    dashboardData,
    caseMatrix,
    finalReport,
    coverageReport,
    rows,
    ruleInventory,
    totals: buildTotals({ dashboardData, finalReport, coverageReport, rows }),
    techniqueCounts: ensureKeys(dashboardData.alert_count_by_technique || countBy(rows, (row) => row.technique_id), TECHNIQUES),
    engineCounts: ensureKeys(dashboardData.alert_count_by_engine || countEngines(rows), ENGINES),
    severityCounts: ensureKeys(countBy(rows, (row) => row.severity || "unknown"), SEVERITIES),
    sysmonCounts: countSysmonEvents(rows),
    matrixCounts: {
      true_positive: numberOrZero(dashboardData.true_positive_count),
      true_negative: numberOrZero(dashboardData.true_negative_count),
      false_positive: numberOrZero(dashboardData.false_positive_count),
      false_negative: numberOrZero(dashboardData.false_negative_count),
    },
  };
}

function normalizeRow({ row, caseLookup, ruleLookup }) {
  const detail = caseLookup[row.case_id] || {};
  const merged = { ...detail, ...row };
  const ruleIds = arrayValue(merged.actual_rule_ids);
  const engines = arrayValue(merged.actual_engines);
  const sequenceNames = arrayValue(merged.actual_sequence_names);
  const severity = merged.severity || pickRuleSeverity(ruleIds, ruleLookup) || "unknown";

  return {
    ...merged,
    actual_rule_ids: ruleIds,
    actual_engines: engines,
    actual_sequence_names: sequenceNames,
    severity,
    process: merged.process || merged.process_name || merged.image || merged.name || "-",
    event_code: stringValue(merged.event_code),
    technique_id: merged.technique_id || "-",
    classification: merged.classification || "unknown",
    alert_count: numberOrZero(merged.alert_count),
    expected_malicious: Boolean(merged.expected_alert),
  };
}

function buildTotals({ dashboardData, finalReport, coverageReport, rows }) {
  const totalAlerts = rows.reduce((sum, row) => sum + numberOrZero(row.alert_count), 0);
  const coverageSummary = coverageReport.engine_coverage_summary || {};

  return {
    totalCases: numberOrFallback(dashboardData.total_cases, rows.length),
    totalAlerts,
    ruleCount: numberOrFallback(coverageSummary.total_rule_count, coverageReport.rule_inventory?.length || 0),
    techniqueCount: Array.isArray(coverageReport.covered_techniques) ? coverageReport.covered_techniques.length : 0,
    correlatedSequences: numberOrFallback(
      dashboardData.correlated_sequence_count,
      finalReport.correlated_sequence_count || 0,
    ),
    projectStatus: finalReport.project_status || coverageReport.project_phase || "Local deterministic demo ready",
    generatedAt:
      dashboardData.generated_at ||
      caseGeneratedAt(dashboardData, finalReport, coverageReport) ||
      "unknown",
  };
}

function caseGeneratedAt(...sources) {
  return sources.map((source) => source?.generated_at).find(Boolean);
}

function render(currentModel) {
  renderHeader(currentModel);
  renderSummary(currentModel);
  renderBarChart(document.querySelector("#technique-chart"), currentModel.techniqueCounts, TECHNIQUES);
  renderBarChart(document.querySelector("#engine-chart"), currentModel.engineCounts, ENGINES);
  renderBarChart(document.querySelector("#severity-chart"), currentModel.severityCounts, SEVERITIES);
  renderSysmon(currentModel.sysmonCounts);
  renderMatrix(currentModel.matrixCounts);
  renderAlertsTable(currentModel.rows);
  renderAlertDetail(currentModel.rows.find((row) => row.case_id === selectedCaseId));
  renderRealtime(realtimeState);
}

function renderHeader(currentModel) {
  document.querySelector("#project-status").textContent = `Project status: ${currentModel.totals.projectStatus}`;
  document.querySelector("#last-generated").textContent = `Last generated: ${currentModel.totals.generatedAt}`;
}

function renderSummary(currentModel) {
  const { totals, matrixCounts } = currentModel;

  text("#metric-total-cases", totals.totalCases);
  text("#metric-total-alerts", totals.totalAlerts);
  text("#metric-rule-count", totals.ruleCount);
  text("#metric-techniques", totals.techniqueCount);
  text(
    "#metric-classification",
    `${matrixCounts.true_positive} / ${matrixCounts.true_negative} / ${matrixCounts.false_positive} / ${matrixCounts.false_negative}`,
  );
  text("#metric-sequences", totals.correlatedSequences);
}

function renderBarChart(container, counts, orderedKeys) {
  const max = Math.max(1, ...Object.values(counts).map(numberOrZero));

  container.replaceChildren(
    ...orderedKeys.map((key) => {
      const value = numberOrZero(counts[key]);
      const row = element("div", "bar-row");
      row.append(
        element("span", "bar-label", key),
        element("div", "bar-track", element("div", "bar-fill")),
        element("span", "bar-value", value),
      );
      row.querySelector(".bar-fill").style.width = `${Math.max(4, (value / max) * 100)}%`;
      return row;
    }),
  );
}

function renderSysmon(counts) {
  const container = document.querySelector("#sysmon-chart");
  container.replaceChildren(
    ...SYSMON_EVENTS.map(({ code, label }) => {
      const card = element("div", "event-card");
      card.append(element("span", "", `Event ID ${code}`), element("strong", "", counts[code] || 0), element("span", "", label));
      return card;
    }),
  );
}

function renderMatrix(counts) {
  const container = document.querySelector("#case-matrix");
  const items = [
    ["true_positive", "TP", counts.true_positive],
    ["true_negative", "TN", counts.true_negative],
    ["false_positive", "FP", counts.false_positive],
    ["false_negative", "FN", counts.false_negative],
  ];
  if (numberOrZero(counts.pending) > 0) {
    items.push(["pending", "PENDING", counts.pending]);
  }

  container.replaceChildren(
    ...items.map(([key, label, value]) => {
      const copy = CLASSIFICATION_COPY[key];
      const card = element("div", `matrix-card ${copy.css}`);
      card.append(element("span", "", label), element("strong", "", value), element("span", "", copy.text));
      return card;
    }),
  );
}

function renderAlertsTable(rows) {
  const tbody = document.querySelector("#alerts-table");
  tbody.replaceChildren(
    ...rows.map((row) => {
      const tr = element("tr");
      if (row.case_id === selectedCaseId) {
        tr.classList.add("selected");
      }
      tr.addEventListener("click", () => {
        selectedCaseId = row.case_id;
        renderAlertsTable(model.rows);
        renderAlertDetail(row);
      });
      tr.append(
        tableCell(row.case_id, "mono"),
        tableCell(pill(classificationShort(row.classification), classificationCss(row.classification))),
        tableCell(listValue(row.actual_rule_ids), "mono"),
        tableCell(row.technique_id),
        tableCell(listValue(row.actual_engines)),
        tableCell(pill(row.severity, row.severity)),
        tableCell(row.process),
        tableCell(row.event_code),
        tableCell(row.expected_malicious ? "true" : "false"),
        tableCell(row.alert_count),
      );
      return tr;
    }),
  );
}

function startRealtimePolling() {
  fetchRealtimeSnapshot();
  window.setInterval(fetchRealtimeSnapshot, REALTIME_REFRESH_MS);
}

async function fetchRealtimeSnapshot() {
  try {
    const { summary, alerts, events, evaluation, apiBase } = await loadRealtimeSnapshotFromApi();

    realtimeState = {
      connected: true,
      apiBase,
      summary,
      alerts: Array.isArray(alerts) ? alerts : [],
      events: Array.isArray(events) ? events : [],
      evaluation,
      lastError: "",
    };
  } catch (error) {
    const fallback = await loadStaticRealtimeSnapshot();
    realtimeState = {
      ...fallback,
      connected: false,
      apiBase: "",
      lastError: error instanceof Error ? error.message : String(error),
    };
  }

  renderRealtime(realtimeState);
}

async function loadRealtimeSnapshotFromApi() {
  const errors = [];
  for (const apiBase of realtimeApiCandidates()) {
    try {
      const [summary, alerts, events, evaluation] = await Promise.all([
        loadRealtimeJson(apiBase, "/api/summary"),
        loadRealtimeJson(apiBase, "/api/alerts"),
        loadRealtimeJson(apiBase, "/api/events"),
        loadRealtimeJson(apiBase, "/api/evaluation"),
      ]);
      activeRealtimeApiBase = apiBase;
      return { summary, alerts, events, evaluation, apiBase };
    } catch (error) {
      errors.push(`${apiBase}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  activeRealtimeApiBase = "";
  throw new Error(`Realtime API unreachable. Tried ${errors.join(" | ")}`);
}

async function loadRealtimeJson(apiBase, path) {
  const response = await fetch(`${apiBase}${path}`, {
    cache: "no-store",
    mode: "cors",
  });

  if (!response.ok) {
    throw new Error(`Realtime API ${path} returned ${response.status}`);
  }

  return response.json();
}

async function loadStaticRealtimeSnapshot() {
  try {
    const [summary, alerts, events, evaluation] = await Promise.all([
      loadJson(DATA_PATHS.realtimeSummary),
      loadJson(DATA_PATHS.realtimeAlerts),
      loadJson(DATA_PATHS.realtimeEvents),
      loadJson(DATA_PATHS.realtimeEvaluation),
    ]);

    return {
      summary,
      alerts: Array.isArray(alerts) ? alerts : [],
      events: Array.isArray(events) ? events : [],
      evaluation,
    };
  } catch (_error) {
    return {
      summary: realtimeState.summary,
      alerts: realtimeState.alerts,
      events: realtimeState.events,
      evaluation: realtimeState.evaluation,
    };
  }
}

function renderRealtime(state) {
  renderRealtimeStatus(state);
  renderRealtimeSummary(state.summary, state.connected);
  renderRealtimeEvaluation(state.evaluation, state.connected);
  renderRealtimeAlerts(state.alerts);
  renderRealtimeEvents(state.events);
}

function renderRealtimeStatus(state) {
  const status = document.querySelector("#realtime-status");
  if (!status) {
    return;
  }

  status.classList.toggle("connected", state.connected);
  status.classList.toggle("disconnected", !state.connected);
  status.textContent = state.connected ? "Realtime: connected" : "Realtime: disconnected / using static data";
  status.title = state.connected
    ? `Realtime API is reachable at ${state.apiBase}.`
    : state.lastError || "Realtime API is offline.";
}

function renderRealtimeSummary(summary, connected) {
  text("#realtime-event-count", summary ? numberOrZero(summary.event_count) : 0);
  text("#realtime-alert-count", summary ? numberOrZero(summary.alert_count) : 0);
  text("#realtime-last-event", summary ? summary.latest_event_at || "-" : "-");
  text("#realtime-last-alert", summary ? summary.latest_alert_at || "-" : "-");
  text(
    "#realtime-api-health",
    connected && summary?.collector_running
      ? `collector running (${displayRealtimeApiBase(realtimeState.apiBase)})`
      : connected
        ? `api online (${displayRealtimeApiBase(realtimeState.apiBase)})`
        : "offline / static snapshot",
  );
}

function renderRealtimeEvaluation(evaluation, connected = false) {
  if (!evaluation) {
    return;
  }

  const counts = evaluation.counts || {};
  const matrixCounts = {
    true_positive: numberOrZero(counts.true_positive),
    true_negative: numberOrZero(counts.true_negative),
    false_positive: numberOrZero(counts.false_positive),
    false_negative: numberOrZero(counts.false_negative),
    pending: numberOrZero(counts.pending),
  };
  const hasLiveEvaluation =
    numberOrZero(evaluation.observed_case_count) > 0 ||
    Object.values(matrixCounts).some((value) => numberOrZero(value) > 0);

  if (connected && hasLiveEvaluation) {
    text(
      "#metric-classification",
      `${matrixCounts.true_positive} / ${matrixCounts.true_negative} / ${matrixCounts.false_positive} / ${matrixCounts.false_negative}`,
    );
    renderMatrix(matrixCounts);
  }

  text(
    "#realtime-evaluation-status",
    hasLiveEvaluation
      ? `${numberOrZero(evaluation.observed_case_count)} / ${numberOrZero(evaluation.case_count)} observed`
      : "waiting for simulation",
  );
  renderRealtimeEvaluationTable(Array.isArray(evaluation.cases) ? evaluation.cases : []);
}

function renderRealtimeEvaluationTable(cases) {
  const tbody = document.querySelector("#realtime-evaluation-table");
  if (!tbody) {
    return;
  }

  const observedCases = cases.filter((item) => item.status !== "not_seen");
  if (!observedCases.length) {
    tbody.replaceChildren(emptyTableRow("No realtime evaluation markers observed yet.", 6));
    return;
  }

  tbody.replaceChildren(
    ...observedCases.map((item) => {
      const classification = item.classification || item.status || "pending";
      const tr = element("tr");
      tr.append(
        tableCell(item.case_id, "mono"),
        tableCell(item.marker, "mono"),
        tableCell(item.expected_alert ? "alert" : "no alert"),
        tableCell(pill(classificationShort(classification), classificationCss(classification))),
        tableCell(listValue(item.actual_rule_ids), "mono"),
        tableCell(item.reason),
      );
      return tr;
    }),
  );
}

function renderRealtimeAlerts(alerts) {
  const tbody = document.querySelector("#realtime-alerts-table");
  if (!tbody) {
    return;
  }

  if (!alerts.length) {
    tbody.replaceChildren(emptyTableRow("No realtime alerts yet.", 7));
    return;
  }

  tbody.replaceChildren(
    ...alerts
      .slice()
      .reverse()
      .map((alert) => {
        const tr = element("tr");
        const id = alertId(alert);
        if (id === selectedRealtimeAlertId) {
          tr.classList.add("selected");
        }
        tr.addEventListener("click", () => {
          selectedRealtimeAlertId = id;
          renderRealtimeAlerts(realtimeState.alerts);
          renderRealtimeAlertDetail(alert);
        });
        tr.append(
          tableCell(alert.timestamp || getPath(alert, "alert.created"), "mono"),
          tableCell(getPath(alert, "rule.id"), "mono"),
          tableCell(getPath(alert, "attack.technique.id")),
          tableCell(getPath(alert, "detection.engine")),
          tableCell(pill(alert.severity || getPath(alert, "alert.severity"), alert.severity || getPath(alert, "alert.severity"))),
          tableCell(getPath(alert, "event.code")),
          tableCell(evidenceSummary(alert), "mono"),
        );
        return tr;
      }),
  );
}

function renderRealtimeEvents(events) {
  const tbody = document.querySelector("#realtime-events-table");
  if (!tbody) {
    return;
  }

  if (!events.length) {
    tbody.replaceChildren(emptyTableRow("No realtime events yet.", 6));
    return;
  }

  tbody.replaceChildren(
    ...events
      .slice()
      .reverse()
      .slice(0, 80)
      .map((event) => {
        const tr = element("tr");
        tr.append(
          tableCell(event["@timestamp"] || getPath(event, "event.created"), "mono"),
          tableCell(getPath(event, "event.code")),
          tableCell(getPath(event, "process.name")),
          tableCell(getPath(event, "process.command_line") || getPath(event, "process.executable"), "mono"),
          tableCell(getPath(event, "file.path") || getPath(event, "registry.path") || networkSummary(event), "mono"),
          tableCell(getPath(event, "winlog.record_id") || getPath(event, "event.id"), "mono"),
        );
        return tr;
      }),
  );
}

function renderRealtimeAlertDetail(alert) {
  const container = document.querySelector("#alert-detail");
  if (!container) {
    return;
  }

  container.replaceChildren(
    detailBlock("Realtime alert", {
      alert_id: getPath(alert, "alert.id"),
      rule_id: getPath(alert, "rule.id"),
      rule_name: getPath(alert, "rule.name"),
      attack_technique_id: getPath(alert, "attack.technique.id"),
      detection_engine: getPath(alert, "detection.engine"),
      alert_severity: alert.severity || getPath(alert, "alert.severity"),
      event_code: getPath(alert, "event.code"),
    }),
    detailBlock("Matched fields", {
      matched_fields: listValue(getPath(alert, "matched_fields") || getPath(alert, "detection.matched_fields")),
      reason: getPath(alert, "detection.reason") || alert.reason,
    }),
    detailBlock("Raw evidence", {
      process_name: getPath(alert, "process.name") || getEvidence(alert, "process.name"),
      process_command_line: getEvidence(alert, "process.command_line"),
      file_path: getEvidence(alert, "file.path"),
      registry_path: getEvidence(alert, "registry.path"),
      registry_data: getEvidence(alert, "registry.data"),
      destination_ip: getPath(alert, "destination.ip") || getEvidence(alert, "destination.ip"),
      destination_port: getPath(alert, "destination.port") || getEvidence(alert, "destination.port"),
      raw_message: getEvidence(alert, "raw.message"),
    }),
  );
}

function renderAlertDetail(row) {
  const container = document.querySelector("#alert-detail");
  if (!row) {
    container.textContent = "Select a row to review alert evidence.";
    return;
  }

  const classification = CLASSIFICATION_COPY[row.classification] || {
    short: row.classification,
    text: "Classification was not available in the exported case matrix.",
  };

  container.replaceChildren(
    detailBlock("Alert summary", {
      case_id: row.case_id,
      classification: `${classification.short} - ${classification.text}`,
      rule_id: listValue(row.actual_rule_ids),
      technique: row.technique_id,
      engine: listValue(row.actual_engines),
      severity: row.severity,
    }),
    detailBlock("Matched fields", {
      expected_alert: String(row.expected_alert),
      actual_alert: String(row.actual_alert),
      alert_count: String(row.alert_count),
      sequence_names: listValue(row.actual_sequence_names),
      correlated_sequence_count: String(numberOrZero(row.correlated_sequence_count)),
    }),
    detailBlock("Source log fields", {
      event_code: row.event_code,
      input_type: row.input_type || "-",
      input_path: row.input_path || "-",
      runner_mode: row.runner_mode || "-",
      normalized_event_count: String(numberOrZero(row.normalized_event_count)),
      status: row.status || "-",
    }),
    detailBlock("Why this alert fired", {
      reason: row.teacher_demo_notes || row.description || "Existing report data did not include a detailed reason.",
      tp_tn_fp_fn: classification.text,
      related_sysmon_event_ids: relatedSysmonIds(row.event_code).join(", ") || "-",
    }),
  );
}

function detailBlock(title, values) {
  const block = element("section", "detail-block");
  const list = element("dl", "detail-kv");
  Object.entries(values).forEach(([key, value]) => {
    list.append(
      element("dt", "", key),
      element("dd", key.includes("path") || key.includes("id") || key.includes("command") ? "mono" : "", detailValue(value)),
    );
  });
  block.append(element("h3", "", title), list);
  return block;
}

function showError(error) {
  const message = error instanceof Error ? error.message : String(error);
  document.querySelector("#app-error").textContent =
    `Dashboard data could not be loaded: ${message}. Run "python scripts\\demo\\export_static_dashboard_data.py" and serve with "python -m http.server 8088 -d dashboard/static".`;
}

function countBy(items, getKey) {
  return items.reduce((acc, item) => {
    const key = getKey(item) || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function countEngines(rows) {
  return rows.reduce((acc, row) => {
    const engines = row.actual_engines.length ? row.actual_engines : ["unknown"];
    engines.forEach((engine) => {
      acc[engine] = (acc[engine] || 0) + numberOrZero(row.alert_count || 1);
    });
    return acc;
  }, {});
}

function countSysmonEvents(rows) {
  const counts = Object.fromEntries(SYSMON_EVENTS.map(({ code }) => [code, 0]));
  rows.forEach((row) => {
    relatedSysmonIds(row.event_code).forEach((code) => {
      if (code in counts) {
        counts[code] += 1;
      }
    });
  });
  return counts;
}

function relatedSysmonIds(value) {
  return stringValue(value)
    .split("/")
    .map((part) => part.trim())
    .filter((part) => ["1", "3", "11", "13"].includes(part));
}

function ensureKeys(counts, keys) {
  const result = { ...counts };
  keys.forEach((key) => {
    result[key] = numberOrZero(result[key]);
  });
  return result;
}

function pickRuleSeverity(ruleIds, ruleLookup) {
  const rank = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return ruleIds
    .map((ruleId) => ruleLookup[ruleId]?.severity || "unknown")
    .sort((left, right) => rank[right] - rank[left])[0];
}

function classificationShort(value) {
  return CLASSIFICATION_COPY[value]?.short || stringValue(value);
}

function classificationCss(value) {
  return CLASSIFICATION_COPY[value]?.css || stringValue(value);
}

function tableCell(content, className = "") {
  const td = document.createElement("td");
  if (content instanceof Node) {
    td.append(content);
  } else {
    td.textContent = stringValue(content);
  }
  if (className) {
    td.className = className;
  }
  return td;
}

function emptyTableRow(message, colSpan) {
  const tr = element("tr", "empty-row");
  const td = tableCell(message);
  td.colSpan = colSpan;
  tr.append(td);
  return tr;
}

function pill(content, className) {
  return element("span", `pill ${className || ""}`, content);
}

function element(tag, className = "", content = "") {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (content instanceof Node) {
    node.append(content);
  } else if (content !== "") {
    node.textContent = String(content);
  }
  return node;
}

function text(selector, value) {
  const node = document.querySelector(selector);
  if (node) {
    node.textContent = stringValue(value);
  }
}

function listValue(value) {
  const values = arrayValue(value);
  return values.length ? values.join(", ") : "-";
}

function arrayValue(value) {
  if (Array.isArray(value)) {
    return value.filter((item) => item !== null && item !== undefined).map(String);
  }
  if (value === null || value === undefined || value === "") {
    return [];
  }
  return [String(value)];
}

function numberOrZero(value) {
  return Number.isFinite(Number(value)) ? Number(value) : 0;
}

function numberOrFallback(value, fallback) {
  return Number.isFinite(Number(value)) ? Number(value) : fallback;
}

function stringValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  return String(value);
}

function displayRealtimeApiBase(value) {
  return value ? value.replace(/^https?:\/\//, "") : "api";
}

function detailValue(value) {
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : "-";
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  return stringValue(value);
}

function alertId(alert) {
  return getPath(alert, "alert.id") || `${getPath(alert, "rule.id")}-${alert.timestamp || ""}`;
}

function evidenceSummary(alert) {
  const evidence = alert.evidence || {};
  return (
    evidence["process.command_line"] ||
    evidence["file.path"] ||
    evidence["registry.path"] ||
    networkSummary(alert) ||
    evidence["raw.message"] ||
    "-"
  );
}

function networkSummary(value) {
  const ip = getPath(value, "destination.ip") || getPath(value, "evidence.destination.ip");
  const port = getPath(value, "destination.port") || getPath(value, "evidence.destination.port");
  if (!ip && !port) {
    return "";
  }
  return port ? `${ip}:${port}` : ip;
}

function getPath(value, path) {
  return path.split(".").reduce((current, part) => {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    return current[part];
  }, value);
}

function getEvidence(alert, key) {
  return alert?.evidence?.[key];
}

boot();
