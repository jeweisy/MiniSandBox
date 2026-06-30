import json
import os
from datetime import datetime

def export_to_json(hashes, vt_results, pe_imports, suspicious_strings, section_entropy, output_dir="reports"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    report_data = {
        "analysis_timestamp": datetime.now().isoformat(),
        "file_hashes": hashes,
        "virus_total": vt_results if vt_results["status"] == "success" else {"error": vt_results["message"]},
        "pe_imports": pe_imports,
        "suspicious_strings": suspicious_strings,
        "section_entropy": section_entropy
    }

    filename = f"report_{hashes['md5']}.json"
    file_path = os.path.join(output_dir, filename)

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        return file_path
    except Exception as e:
        print(f"[-] Error writing report: {str(e)}")
        return None