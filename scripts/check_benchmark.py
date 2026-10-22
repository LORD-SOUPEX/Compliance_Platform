"""Check a compliance report produced on the local demo folder
(devsecops-compliance-benchmark, one root per technology of the catalog).

Whatever tools are installed on this machine:

- every technology of the catalog is detected;
- no control ends in "error" (a crash of the engine, of a tool or of a parser);
- every control in "fail" carries at least one located finding: a failure the
  engine cannot place in a file means an output it did not read;
- every executed control records its processes (invocations[]).

Usage: python scripts/check_benchmark.py REPORT.json [--min-executed N]
"""

import argparse
import json
import sys
from collections import Counter

EXPECTED_TECHNOLOGIES = {
    "ansible",
    "css",
    "dependencies",
    "docker",
    "go",
    "helm",
    "html",
    "javascript",
    "kubernetes",
    "markdown",
    "opentofu",
    "powershell",
    "python",
    "secrets",
    "shell",
    "terraform",
    "terragrunt",
    "typescript",
    "yaml",
}


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument(
        "--min-executed",
        type=int,
        default=0,
        help="fail when fewer controls actually ran (tools missing)",
    )
    args = parser.parse_args(argv)
    with open(args.report, encoding="utf-8") as handle:
        report = json.load(handle)

    problems = []
    detected = {
        t["technology"]
        for t in report["discovery"]["technologies"]
        if t["status"] == "detected"
    }
    missing = EXPECTED_TECHNOLOGIES - detected
    if missing:
        problems.append(f"technologies non détectées : {sorted(missing)}")

    located = Counter(
        f.get("control_id") for f in report.get("findings", []) if f.get("file")
    )
    executed = 0
    statuses = Counter()
    for result in report["execution_results"]:
        control, status = result["control_id"], result["status"]
        statuses[status] += 1
        if status == "skipped":
            continue
        executed += 1
        if status == "error":
            reason = (result.get("diagnostics") or [{}])[0].get("message", "")
            problems.append(f"{control} : erreur d'exécution ({reason[:160]})")
        if status == "fail" and located[control] == 0:
            problems.append(
                f"{control} : échec sans anomalie localisée (sortie non analysée ?)"
            )
        # pip-audit with nothing pinned reports from the requirements file alone, without a process.
        static_only = any(
            d.get("code") == "unpinned_requirements"
            for d in result.get("diagnostics", [])
        )
        if (
            result.get("exit_code") is not None
            and not result.get("invocations")
            and not static_only
        ):
            problems.append(
                f"{control} : aucun processus enregistré dans invocations[]"
            )

    print(f"technologies détectées : {len(detected)}/{len(EXPECTED_TECHNOLOGIES)}")
    print(
        f"contrôles : {dict(statuses)} ; exécutés : {executed} ; anomalies : {sum(located.values())}"
    )
    if executed < args.min_executed:
        problems.append(
            f"{executed} contrôle(s) exécuté(s), {args.min_executed} attendu(s) au moins"
        )
    for problem in problems:
        print(f"ÉCART : {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
