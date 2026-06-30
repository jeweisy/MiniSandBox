import os
import json
import time
from core.hasher import calculate_hashes
from core.pe_analyzer import analyze_pe_imports
from core.vt_checker import check_hash_vt
from core.reporter import export_to_json
from core.analyzer import extract_strings, filter_suspicious_strings, analyze_sections
from core.vm_automation import VMAutomation


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

    pe_imports = analyze_pe_imports(sample_file)
    all_strings = extract_strings(sample_file)
    suspicious = filter_suspicious_strings(all_strings)
    sections = analyze_sections(sample_file)

    print("\n" + "=" * 60)
    print("[*] INITIALIZING ISOLATED GUEST SANDBOX DETONATION")
    print("=" * 60)

    try:
        vm = VMAutomation()
    except PermissionError as env_error:
        print(str(env_error))
        return

    print("[*] Reverting Virtual Machine to 'Clean_Lab' Snapshot...")
    if not vm.revert_to_clean_snapshot():
        print("[-] Failed to revert VM snapshot.")
        return

    print("[*] Booting Virtual Machine in Headless Mode...")
    if not vm.start_vm():
        print("[-] Failed to start VM.")
        return

    print("[*] Waiting for Guest OS stabilization (15 Seconds)...")
    time.sleep(15)

    print("[*] Transferring payload into the isolated environment...")
    guest_target_path = r"C:\Sandbox\analyzed.exe"
    host_source_path = os.path.abspath(sample_file)

    if not vm.copy_file_to_guest(host_source_path, guest_target_path):
        print("[-] Failed to copy payload to Guest VM. Aborting.")
        vm.stop_vm()
        return

    print("[*] Deploying and Triggering Telemetry Agent inside Guest...")
    guest_agent_path = r"C:\Python313\python.exe"
    agent_script = r"C:\Sandbox\agent.py"

    vm.execute_program_in_guest(guest_agent_path, f"{agent_script} 5")
    time.sleep(1)

    print(f"[+] Detonating Target Malware Payload INSIDE the Guest VM...")
    if vm.execute_program_in_guest(guest_target_path):
        print("[+] Execution command dispatched successfully.")
    else:
        print("[-] Detonation command execution failed.")

    print("[*] Collecting dynamic telemetry artifacts (5 Seconds)...")
    time.sleep(5)

    print("[*] Extracting Telemetry Log File from Guest to Host...")
    guest_log_file = r"C:\Sandbox\guest_telemetry.json"
    host_extracted_log = os.path.join("reports", "extracted_telemetry.json")

    guest_processes = []
    guest_networks = []

    if vm.pull_file_from_guest(guest_log_file, os.path.abspath(host_extracted_log)):
        print("[+] Telemetry artifact successfully extracted.")
        try:
            with open(host_extracted_log, "r") as lf:
                telemetry_data = json.load(lf)
                guest_processes = telemetry_data.get("processes", [])
                guest_networks = telemetry_data.get("networks", [])
        except Exception:
            print("[-] Error reading extracted telemetry logs.")
    else:
        print("[-] Failed to extract telemetry artifacts from Guest VM.")

    print("[*] Securing Sandbox Environment (Executing Hard Shutdown)...")
    vm.stop_vm()

    print(f"\n[+] Dynamic Analysis Captured {len(guest_processes)} Guest Processes.")
    print(f"[+] Dynamic Analysis Captured {len(guest_networks)} Guest Network Connections.")

    print("\n[*] Generating Comprehensive JSON Report...")
    report_file = export_to_json(
        results, vt_results, pe_imports, suspicious, sections,
        guest_processes, [], guest_networks
    )
    print(f"[+] Sandbox Analysis Complete! Report saved to: {report_file}")


if __name__ == "__main__":
    main()