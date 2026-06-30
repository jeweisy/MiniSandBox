import json
import os
from datetime import datetime


def calculate_risk_score(vt_results, suspicious_strings, sections, guest_processes, guest_networks):
    """
    Evaluates static and dynamic telemetry artifacts using a weighted risk matrix
    to generate a finalized security score between 0 and 100.
    """
    score = 0

    # 1. VirusTotal Threat Intel Weight (Max 40)
    if vt_results and vt_results.get("status") == "success":
        positives = vt_results.get("positives", 0)
        if positives > 0:
            score += min(40, positives * 4)

    # 2. PE Section Entropy Weight (Max 20)
    if sections:
        suspicious_sections = [s for s in sections if s.get("flag") != "NORMAL"]
        score += min(20, len(suspicious_sections) * 10)

    # 3. Suspicious Static Strings Weight (Max 15)
    if suspicious_strings:
        score += min(15, len(suspicious_strings) * 1.5)

    # 4. Dynamic Guest Processes Weight (Max 15)
    if guest_processes:
        suspicious_procs = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "reg.exe"]
        spawned_suspicious = False
        for proc in guest_processes:
            if proc.get("name", "").lower() in suspicious_procs:
                spawned_suspicious = True
                break
        score += 15 if spawned_suspicious else min(10, len(guest_processes) * 2)

    # 5. Dynamic Guest Network Connections Weight (Max 10)
    if guest_networks:
        score += min(10, len(guest_networks) * 5)

    # Ensuring bounds
    final_score = min(100, int(score))

    # Determining Verdict
    if final_score <= 30:
        verdict = "CLEAN"
    elif final_score <= 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return final_score, verdict


def export_to_json(hashes, vt_results, pe_imports, suspicious_strings, sections, guest_processes, file_events,
                   guest_networks):
    """
    Compiles all intelligence metrics into a standardized, production-grade
    JSON security artifact.
    """
    if not os.path.exists("reports"):
        os.makedirs("reports")

    risk_score, verdict = calculate_risk_score(
        vt_results, suspicious_strings, sections, guest_processes, guest_networks
    )

    report_data = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "target_hashes": hashes,
            "threat_classification": {
                "risk_score": risk_score,
                "verdict": verdict
            }
        },
        "static_analysis": {
            "pe_imports": pe_imports,
            "flagged_strings": suspicious_strings,
            "section_entropy": sections
        },
        "threat_intelligence": vt_results,
        "dynamic_analysis": {
            "spawned_processes": guest_processes,
            "file_system_events": file_events,
            "network_connections": guest_networks
        }
    }

    report_filename = f"reports/report_{hashes['md5']}.json"

    try:
        with open(report_filename, "w") as f:
            json.dump(report_data, f, indent=4)
        return report_filename
    except Exception:
        return None