import json
import sys

def normalize_string(s):
    if s is None:
        return ""
    # Normalize path separators
    return s.replace("\\", "/")

def compare_reports(ps_path, go_path):
    ps = json.load(open(ps_path, encoding='utf-8-sig'))
    go = json.load(open(go_path, encoding='utf-8-sig'))

    print("=================================================================")
    print("           PARITÉ D'EXÉCUTION RÉELLE (SECTION 8.2)")
    print("=================================================================")

    # 1. Verdict
    ps_verdict = ps.get("verdict")
    go_verdict = go.get("verdict")
    print(f"\n1. VERDICT :")
    print(f"   PowerShell : {ps_verdict}")
    print(f"   Go         : {go_verdict}")
    verdict_match = (ps_verdict == go_verdict)
    print(f"   --> Égalité stricte : {verdict_match}")

    # 2. Verdict Reasons
    ps_reasons = sorted(ps.get("verdict_reasons", []))
    go_reasons = sorted(go.get("verdict_reasons", []))
    print(f"\n2. VERDICT REASONS :")
    print(f"   PowerShell : {ps_reasons}")
    print(f"   Go         : {go_reasons}")
    reasons_match = (ps_reasons == go_reasons)
    print(f"   --> Égalité stricte : {reasons_match}")

    # 3. Execution Status & Advisory
    print(f"\n3. MÉTADONNÉES DE SESSION :")
    print(f"   Execution status : PS={ps.get('execution_status')} | Go={go.get('execution_status')}")
    print(f"   Advisory         : PS={ps.get('advisory')} | Go={go.get('advisory')}")

    # 4. Statut de chaque contrôle dans execution_results
    ps_results = {r["control_id"]: r for r in ps.get("execution_results", [])}
    go_results = {r["control_id"]: r for r in go.get("execution_results", [])}

    all_control_ids = sorted(set(ps_results.keys()) | set(go_results.keys()))
    print(f"\n4. CONTRÔLE PAR CONTRÔLE ({len(all_control_ids)} contrôles) :")
    
    diff_status_count = 0
    diff_exit_count = 0
    diff_diags_count = 0

    print(f"{'Contrôle':<45} | {'Statut PS':<10} | {'Statut Go':<10} | {'Exit PS':<7} | {'Exit Go':<7} | {'Match'}")
    print("-" * 95)
    for cid in all_control_ids:
        pr = ps_results.get(cid)
        gr = go_results.get(cid)
        p_status = pr.get("status") if pr else "MISSING"
        g_status = gr.get("status") if gr else "MISSING"
        p_exit = str(pr.get("exit_code")) if pr else "N/A"
        g_exit = str(gr.get("exit_code")) if gr else "N/A"
        
        status_match = (p_status == g_status)
        exit_match = (p_exit == g_exit)
        match_str = "OK" if (status_match and exit_match) else "DIFF"
        if not status_match:
            diff_status_count += 1
        if not exit_match:
            diff_exit_count += 1

        print(f"{cid:<45} | {p_status:<10} | {g_status:<10} | {p_exit:<7} | {g_exit:<7} | {match_str}")

    print(f"\n--> Bilan statuts contrôles : {len(all_control_ids) - diff_status_count}/{len(all_control_ids)} identiques")

    # 5. Findings
    ps_findings = {f["id"]: f for f in ps.get("findings", [])}
    go_findings = {f["id"]: f for f in go.get("findings", [])}
    all_finding_ids = sorted(set(ps_findings.keys()) | set(go_findings.keys()))

    print(f"\n5. FINDINGS ({len(all_finding_ids)} au total) :")
    print(f"{'Finding ID':<40} | {'Statut PS':<10} | {'Statut Go':<10} | {'Sév. PS':<8} | {'Sév. Go':<8} | {'Match'}")
    print("-" * 90)
    diff_findings = 0
    for fid in all_finding_ids:
        pf = ps_findings.get(fid)
        gf = go_findings.get(fid)
        p_st = pf.get("status") if pf else "MISSING"
        g_st = gf.get("status") if gf else "MISSING"
        p_sev = pf.get("severity") if pf else "N/A"
        g_sev = gf.get("severity") if gf else "N/A"
        match = (p_st == g_st and p_sev == g_sev)
        if not match:
            diff_findings += 1
        print(f"{fid:<40} | {p_st:<10} | {g_st:<10} | {p_sev:<8} | {g_sev:<8} | {'OK' if match else 'DIFF'}")

    print(f"\n--> Bilan findings : {len(all_finding_ids) - diff_findings}/{len(all_finding_ids)} identiques")

    # 6. Écarts détaillés
    print("\n=================================================================")
    print("                    DÉTAIL DES ÉCARTS OBSERVÉS")
    print("=================================================================")
    discrepancies = []
    for cid in all_control_ids:
        pr = ps_results.get(cid, {})
        gr = go_results.get(cid, {})
        p_status = pr.get("status")
        g_status = gr.get("status")
        if p_status != g_status:
            discrepancies.append(f"Statut contrôle {cid}: PS={p_status} vs Go={g_status}")
        p_diags = [d.get("code") for d in pr.get("diagnostics", [])]
        g_diags = [d.get("code") for d in gr.get("diagnostics", [])]
        if set(p_diags) != set(g_diags):
            discrepancies.append(f"Diagnostics {cid}: PS={p_diags} vs Go={g_diags}")

    for fid in all_finding_ids:
        pf = ps_findings.get(fid, {})
        gf = go_findings.get(fid, {})
        if pf.get("status") != gf.get("status") or pf.get("severity") != gf.get("severity"):
            discrepancies.append(f"Finding {fid}: PS status={pf.get('status')}/sev={pf.get('severity')} vs Go status={gf.get('status')}/sev={gf.get('severity')}")

    if not discrepancies:
        print("AUCUN ÉCART DÉTECTÉ ! Parité stricte 100% après normalisation.")
    else:
        for i, d in enumerate(discrepancies, 1):
            print(f"  {i}. {d}")

if __name__ == '__main__':
    compare_reports('core/testdata/ps_defect_report.json', 'core/testdata/go_defect_report.json')
