import os
from core.hasher import calculate_hashes
from core.pe_analyzer import analyze_pe_imports
from core.vt_checker import check_hash_vt
from core.reporter import export_to_json
from core.analyzer import extract_strings, filter_suspicious_strings, analyze_sections


def main():
    sample_file = "samples/notepad.exe"
    api_key = os.environ.get("VT_API_KEY", "")

    print(f"[*] Starting Comprehensive Static Analysis for: {sample_file}\n")

    results = calculate_hashes(sample_file)
    if not results:
        print("[-] Hash calculation failed.")
        return

    print("[+] Hash Calculation Successful!")
    print("-" * 60)
    print(f"MD5    : {results['md5']}")
    print(f"SHA1   : {results['sha1']}")
    print(f"SHA256 : {results['sha256']}")
    print("-" * 60)

    print("\n[*] Querying Threat Intelligence (VirusTotal)...")
    vt_results = check_hash_vt(results["sha256"], api_key)
    if vt_results["status"] == "success":
        print("[+] VirusTotal Scan Results received.")
    else:
        print(f"[-] VirusTotal Query Info: {vt_results['message']}")

    print("\n[*] Parsing PE Import Address Table (IAT)...")
    pe_imports = analyze_pe_imports(sample_file)
    if pe_imports:
        print("[+] Import Analysis Successful!")
    else:
        print("[-] PE import analysis failed.")

    print("\n[*] Extracting Strings...")
    all_strings = extract_strings(sample_file)
    suspicious = filter_suspicious_strings(all_strings)
    print(f"[+] {len(all_strings)} strings found, {len(suspicious)} flagged as suspicious.")
    if suspicious:
        print("    |-- Sample suspicious strings found:")
        for s in suspicious[:5]:
            print(f"    |   [!] {s.strip()}")

    print("\n[*] Analyzing Section Entropy...")
    sections = analyze_sections(sample_file)
    if sections:
        for s in sections:
            print(f"    {s['name']:<12} entropy: {s['entropy']}  →  {s['flag']}")

    print("\n[*] Generating Comprehensive JSON Report...")
    report_file = export_to_json(results, vt_results, pe_imports, suspicious, sections)
    if report_file:
        print(f"[+] Static analysis complete! Report saved to: {report_file}")
    else:
        print("[-] Failed to generate report.")


if __name__ == "__main__":
    main()
