const { buildReportModel, nonApplicableMarkup, reportDurationMs, unavailableSummary, groupUnavailableLines, countsAsUnavailable, uniqueTools, verdictReasonLines } = require("../.extension-build/src/reportLayout.js");
const { parsePreparation } = require("../.extension-build/src/model.js");
const { unwiredReportActions, reportButtonCommand } = require("../.extension-build/src/reportActions.js");
const { engineVersionMismatch } = require("../.extension-build/src/engineVersion.js");
const { hasMachineConsent, shouldAskMachineConsent, machineConsentText, classifyProvisionError, selectManifestTools, missingToolCommands } = require("../.extension-build/src/toolProvision.js");
const fs = require("fs");
const pkg = require("../package.json");
const ver = fs.readFileSync("../core/internal/version/version.go", "utf8");
const checks = [];
const fail = (name) => checks.push(name);
if (!ver.includes('const Version = "' + pkg.version + '"')) fail("version");
if (engineVersionMismatch(pkg.version, pkg.version) || !engineVersionMismatch("2.0.2", pkg.version) || reportButtonCommand("pick") !== "compliance.openReportFile" || reportButtonCommand("raw") !== "compliance.openRawReport" || reportButtonCommand("folder") !== "compliance.openSessionFolder" || reportButtonCommand("provision") !== "compliance.provisionTools") fail("wiring");
const model = buildReportModel({ verdict: "PASS", coverage: { complete: false, executed_controls: 1, applicable_controls: 2 }, verdictReasons: ["Résultat partiel"], technologies: [{ technology: "javascript", status: "detected" }, { technology: "markdown", status: "detected" }, { technology: "terraform", status: "absent" }], controls: [{ id: "js", name: "eslint", technology: "javascript", resultStatus: "success", reasonCode: "", reasonMessage: "", stdout: "", stderr: "" }, { id: "gl", name: "gitleaks", technology: "javascript", resultStatus: "skipped", reasonCode: "tool_unavailable", reasonMessage: "Outil manquant : gitleaks.", stdout: "", stderr: "" }, { id: "tf", name: "fmt", technology: "terraform", resultStatus: "skipped", reasonCode: "technology_absent", reasonMessage: "absente", stdout: "", stderr: "" }] });
if (model.executed.some(control => control.technology === "terraform") || model.hiddenCount !== 1 || !model.gaps.some(gap => gap.startsWith("markdown")) || !model.gaps.some(gap => gap.startsWith("javascript")) || model.verdict.label !== "Partiel" || !model.coverageText.includes("Couverture partielle") || !model.coverageText.includes("couverte") || !model.executed[0].showOutput || !model.executed[0].compact) fail("model " + model.coverageText);
const emptyFail = buildReportModel({ verdict: "FAIL", coverage: {}, controls: [{ id: "gl", name: "gitleaks", technology: "javascript", resultStatus: "fail", reasonCode: "exit_nonzero", reasonMessage: "1 fuite", stdout: "", stderr: "" }] });
if (emptyFail.executed.length !== 1 || !emptyFail.executed[0].showOutput) fail("output button missing on empty fail");
if (reportDurationMs({ metrics: { total_duration_ms: 4321 }, controls: [] }) !== 4321 || reportDurationMs({ metrics: {}, controls: [{ resultStatus: "success", durationMs: 12 }, { resultStatus: "success", durationMs: 4 }] }) !== 16) fail("duration");
const absent = nonApplicableMarkup([{ id: "terraform/formatting/terraform/.", name: "fmt", technology: "terraform", resultStatus: "skipped", reasonCode: "technology_absent", reasonMessage: "absente", stdout: "", stderr: "" }]);
if (absent.includes("<details") || absent.includes("data-action") || !absent.includes("terraform")) fail("absent " + absent);
const executedTerraform = nonApplicableMarkup([{ id: "terraform/formatting/terraform/modules/vpc", name: "fmt", technology: "terraform", root: "modules/vpc", resultStatus: "success", reasonCode: "", reasonMessage: "", stdout: "", stderr: "" }, { id: "terraform/formatting/terraform/.", name: "fmt", technology: "terraform", root: ".", resultStatus: "skipped", reasonCode: "not_applicable", reasonMessage: "Aucune preuve du catalogue ne correspond a cette racine.", stdout: "", stderr: "" }]);
if (executedTerraform.includes("terraform")) fail("executed technology still listed " + executedTerraform);
const unwired = unwiredReportActions(absent + '<button type="button" data-action="pick"></button><button type="button" data-action="raw"></button><button type="button" data-action="folder"></button><button type="button" data-action="provision"></button><button type="button" data-action="output" data-control-id="a"></button><button type="button" data-action="finding" data-finding-index="0"></button><button type="button" data-action="bogus"></button>');
if (unwired.length !== 1 || unwired[0] !== "bogus") fail("unwired " + JSON.stringify(unwired));
if (hasMachineConsent(undefined) || hasMachineConsent({ schema_version: 1, decision: "refused" }) || !hasMachineConsent({ schema_version: 1, decision: "accepted" }) || !shouldAskMachineConsent(undefined) || shouldAskMachineConsent({ schema_version: 1, decision: "accepted" }) || shouldAskMachineConsent({ schema_version: 1, decision: "refused" }) || !machineConsentText().includes("cette machine")) fail("prompt");
if (classifyProvisionError("dial tcp: connection refused").code !== "network" || classifyProvisionError("téléchargement de l'outil bandit: code HTTP 404").code === "network" || !classifyProvisionError("téléchargement de l'outil bandit: code HTTP 404").message.includes("bandit") || selectManifestTools({ platforms: { "windows-x64": { tools: { gitleaks: { version: "8.30.1", archive_url: "https://example.invalid/gitleaks.zip" } } } } }, "windows-x64", ["gitleaks", "pre-commit"]).length !== 1) fail("provision");
const { validationPayload, maximumReportBytes } = require("../.extension-build/src/daemonClient.js");
const slim = validationPayload({ findings: [{ id: "x" }], execution_results: [{ control_id: "a", stdout: "x".repeat(1000), stderr: "e", status: "fail" }], keep: true });
if (Number.isFinite(maximumReportBytes) || slim.findings.length !== 0 || Object.prototype.hasOwnProperty.call(slim.execution_results[0], "stdout") || slim.execution_results[0].status !== "fail" || slim.keep !== true) fail("slim report");
const grouped = unavailableSummary([{ id: "python/linting/ruff/a", name: "ruff", technology: "python", resultStatus: "skipped", reasonCode: "tool_unavailable", reasonMessage: "Outil installable depuis le manifeste : ruff.", stdout: "", stderr: "" }, { id: "python/linting/ruff/b", name: "ruff", technology: "python", resultStatus: "skipped", reasonCode: "tool_unavailable", reasonMessage: "Outil installable depuis le manifeste : ruff.", stdout: "", stderr: "" }]);
if (grouped.length !== 1 || !grouped[0].includes("2 racines concernées") || groupUnavailableLines(["python/linting/ruff/a — Outil installable", "python/linting/ruff/b — Outil installable"]).length !== 1 || groupUnavailableLines(["terraform/security/checkov/a - Outil installable depuis le manifeste : checkov.", "terraform/security/checkov/b - Outil installable depuis le manifeste : checkov."]).length !== 1) fail("unavailable group");
const verdictLines = verdictReasonLines("Au moins un contrôle exécuté a échoué ou une erreur critique a interrompu l’évaluation.", ["Couverture complète : 5 technologie(s) couverte(s) sur 5 détectée(s).", "Au moins un controle de conformite echoue."]);
if (verdictLines.length !== 2 || verdictLines.some(line => line.includes("controle de conformite")) || !verdictLines[0].includes("échoué")) fail("verdict reasons " + JSON.stringify(verdictLines));
if (countsAsUnavailable("not_applicable") || countsAsUnavailable("platform_unsupported") || countsAsUnavailable("ambiguous") || countsAsUnavailable("alternative_not_selected") || countsAsUnavailable("") || !countsAsUnavailable("tool_unavailable") || !countsAsUnavailable("probe_failed") || !countsAsUnavailable("repository_unconfigured")) fail("unavailable classification");
const probeControls = [{ id: "docker/security/trivy/.", name: "trivy", technology: "docker", resultStatus: "skipped", reasonCode: "probe_failed", reasonMessage: "Qualification d'execution impossible: exit status 1 (stdout: aucune sortie ; stderr: aucune sortie)", stdout: "", stderr: "" }, { id: "terraform/security/checkov/.", name: "checkov", technology: "terraform", resultStatus: "skipped", reasonCode: "tool_unavailable", reasonMessage: "Outil installable depuis le manifeste : checkov.", stdout: "", stderr: "" }];
const probeModel = buildReportModel({ verdict: "PASS", coverage: {}, technologies: [{ technology: "docker", status: "detected" }, { technology: "terraform", status: "detected" }], controls: probeControls });
if (probeModel.tools.length !== 1 || probeModel.tools[0] !== "checkov" || uniqueTools(probeControls).join(",") !== "checkov" || !probeModel.gaps.some(gap => gap.startsWith("docker")) || !probeModel.gaps.some(gap => gap.startsWith("terraform"))) fail("probe provision " + JSON.stringify(probeModel.tools) + " " + JSON.stringify(probeModel.gaps));
const missing = missingToolCommands({ execution_plan: { controls: [{ id: "docker/security/trivy/.", tool: { command: "trivy" } }, { id: "terraform/security/checkov/.", tool: { command: "checkov" } }] }, execution_results: [{ control_id: "docker/security/trivy/.", diagnostics: [{ code: "probe_failed" }] }, { control_id: "terraform/security/checkov/.", diagnostics: [{ code: "tool_unavailable" }] }] });
if (missing.length !== 1 || missing[0] !== "checkov") fail("missing tools " + missing.join(","));
const aligned = buildReportModel({ verdict: "FAIL", coverage: { applicable_controls: 31, executed_controls: 23 }, controls: [{ id: "python/lint/ruff/.", name: "ruff", technology: "python", resultStatus: "fail", reasonCode: "exit_nonzero", reasonMessage: "1", stdout: "", stderr: "" }, { id: "javascript/linting/eslint/.", name: "eslint", technology: "javascript", resultStatus: "skipped", reasonCode: "repository_unconfigured", reasonMessage: "Configuration ESLint absente du dépôt.", stdout: "", stderr: "" }, { id: "kubernetes/security/trivy/.", name: "trivy", technology: "kubernetes", resultStatus: "skipped", reasonCode: "ambiguous", reasonMessage: "Le YAML contient des marqueurs de template Helm.", stdout: "", stderr: "" }, { id: "helm/security/trivy/.", name: "trivy", technology: "helm", resultStatus: "skipped", reasonCode: "alternative_not_selected", reasonMessage: "checkov retenu", stdout: "", stderr: "" }] });
const card = label => aligned.cards.find(item => item.label === label).value;
if (card("Applicables") !== 2 || card("Exécutés") !== 1 || card("Indisponibles") !== 1) fail("counters " + JSON.stringify(aligned.cards));
const alignedLines = unavailableSummary([{ id: "javascript/linting/eslint/.", name: "eslint", technology: "javascript", resultStatus: "skipped", reasonCode: "repository_unconfigured", reasonMessage: "Configuration ESLint absente du dépôt.", stdout: "", stderr: "" }, { id: "typescript/linting/eslint/.", name: "eslint", technology: "typescript", resultStatus: "skipped", reasonCode: "repository_unconfigured", reasonMessage: "Configuration ESLint absente du dépôt.", stdout: "", stderr: "" }, { id: "kubernetes/security/trivy/.", name: "trivy", technology: "kubernetes", resultStatus: "skipped", reasonCode: "ambiguous", reasonMessage: "template", stdout: "", stderr: "" }]);
if (alignedLines.length !== 2 || alignedLines.some(line => line.includes("template")) || !alignedLines.some(line => line.includes("javascript")) || !alignedLines.some(line => line.includes("typescript"))) fail("bottom " + JSON.stringify(alignedLines));
const target = fs.mkdtempSync(require("os").tmpdir() + require("path").sep + "compliance-plan-");
const accepted = {
    schema_version: 1, execution_status: "planned", verdict: null, repository: target,
    metadata: { run_id: "a".repeat(32), source_adapter: "VSCode" },
    discovery: { scan_complete: true, scan_errors: [], technologies: [{ technology: "ansible", status: "detected", roots: ["."], evidence: ["ansible.cfg"], ambiguities: [] }] },
    execution_plan: { repository: target, permissions: { network: false, code_execution: true }, controls: [{ id: "ansible/linting/ansible-lint/.", name: "ansible-lint", technology: "ansible", capability: "linting", root: ".", applicability: "platform_unsupported", reason: "reserve a Linux", reason_code: "platform_unsupported", execution_order: 1 }] },
    execution_results: []
};
try { parsePreparation(JSON.stringify(accepted), target, true); } catch (error) { fail("platform_unsupported rejected " + error.message); }
const escaped = JSON.parse(JSON.stringify(accepted));
escaped.execution_plan.controls[0].id = "ansible/linting/ansible-lint/../outside";
escaped.execution_plan.controls[0].root = "../outside";
try { parsePreparation(JSON.stringify(escaped), target, true); fail("escaping root accepted"); } catch (error) { if (!String(error.message).includes("ansible/linting/ansible-lint/../outside") || !String(error.message).includes("hors Target")) fail("opaque rejection " + error.message); }
const repeated = Array.from({ length: 12 }, (_, index) => ({ id: `terraform/security/checkov/root-${index}`, name: "checkov", technology: "terraform", resultStatus: "skipped", reasonCode: "tool_unavailable", reasonMessage: "Outil installable depuis le manifeste : checkov.", stdout: "", stderr: "" }));
const deduped = buildReportModel({ verdict: "PASS", coverage: {}, technologies: [{ technology: "terraform", status: "detected" }], controls: repeated });
if (deduped.tools.length !== 1 || deduped.tools[0] !== "checkov" || deduped.gaps.length !== 1 || (deduped.gaps[0].match(/checkov/g) || []).length !== 1) fail("dedupe " + JSON.stringify(deduped.tools) + " " + JSON.stringify(deduped.gaps));
const { applicationValue, sessionDirectory, parseSessionKeep } = require("../.extension-build/src/localSettings.js");
const { isOurDaemonImage, residualExtensionDirectories, shouldReplaceDaemon } = require("../.extension-build/src/daemonLifecycle.js");
if (parseSessionKeep(1).keep !== 1 || parseSessionKeep(1000).keep !== 1000 || !parseSessionKeep(1001).error || !parseSessionKeep(0).error) fail("keep");
if (sessionDirectory("D:\\reports", "D:\\env", "D:\\default") !== "D:\\reports" || sessionDirectory("", "D:\\env", "D:\\default") !== "D:\\env" || sessionDirectory(undefined, undefined, "D:\\default") !== "D:\\default") fail("session directory priority");
if (applicationValue({ workspaceValue: ["markdown"] }, []).length !== 0) fail("workspace setting was accepted");
if (applicationValue({ globalValue: ["markdown"], workspaceValue: ["python"] }, [])[0] !== "markdown") fail("global setting ignored");
if (!isOurDaemonImage("compliance-windows-amd64.exe") || isOurDaemonImage("code.exe")) fail("daemon image");
if (residualExtensionDirectories(["C:/ext/compliance-platform.compliance-pipelines-2.0.5", "C:/ext/other"], "C:/ext/compliance-platform.compliance-pipelines-2.0.6").length !== 1) fail("residuals");
if (!shouldReplaceDaemon("2.0.5", "2.0.6", "compliance.exe") || shouldReplaceDaemon("2.0.6", "2.0.6", "compliance.exe")) fail("daemon version");
if (checks.length) {
    console.error(checks.join("\n"));
    process.exit(1);
}
const { spawnSync } = require("child_process");
const path = require("path");
const py = process.platform === "win32" ? (spawnSync("where.exe", ["py"]).status === 0 ? "py" : "python") : "python3";
const go = path.join(__dirname, "..", "..", ".tools", "go", "bin", process.platform === "win32" ? "go.exe" : "go");
const bin = process.platform === "win32" ? path.join(__dirname, "..", "..", ".tools", "bin", "compliance.exe") : path.join(__dirname, "..", "..", ".tools", "bin", "compliance");
const gotest = spawnSync(go, ["test", "-count=1", "./internal/discovery/", "./internal/engine/", "./internal/server/", "./internal/logging/", "./internal/osutil/", "./internal/report/", "./internal/distribution/", "./internal/sessions/", "./internal/matrix/"], { cwd: path.join(__dirname, "..", "..", "core"), stdio: "inherit" });
if (gotest.status) process.exit(gotest.status || 1);
const built = spawnSync(go, ["build", "-o", bin, "./cmd/compliance"], { cwd: path.join(__dirname, "..", "..", "core"), stdio: "inherit" });
if (built.status) process.exit(built.status || 1);
const webview = spawnSync(process.execPath, [path.join(__dirname, "run-webview-test.js")], { stdio: "inherit", env: process.env });
if (webview.status) process.exit(webview.status || 1);
const check = spawnSync(py, ["package_vsix.py", "--check-vsix"], { cwd: path.join(__dirname, ".."), stdio: "inherit" });
if (check.status) process.exit(check.status);
const res = spawnSync(bin, ["selftest"], { stdio: "inherit" });
process.exit(res.status || 0);
