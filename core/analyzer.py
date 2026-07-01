import os
import math
import pefile


def extract_strings(file_path, min_len=4):
    MAX_FILE_SIZE = 100 * 1024 * 1024
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        print(f"[-] File too large for string extraction (max 100MB).")
        return []

    strings = []
    try:
        with open(file_path, "rb") as f:
            content = f.read()

        current_str = ""
        for byte in content:
            if 32 <= byte <= 126:
                current_str += chr(byte)
            else:
                if len(current_str) >= min_len:
                    strings.append(current_str)
                current_str = ""
        if len(current_str) >= min_len:
            strings.append(current_str)
    except Exception:
        pass
    return strings


def filter_suspicious_strings(strings):
    suspicious_keywords = [
        "http", "https", "ftp", ".exe", ".dll", ".ps1", ".bat",
        "CreateProcess", "VirtualAlloc", "WriteProcessMemory",
        "RegSetValueEx", "URLDownloadToFile", "ShellExecute",
        "cmd.exe", "powershell.exe", "sc.exe", "schtasks"
    ]
    found = []
    for s in strings:
        for key in suspicious_keywords:
            if key.lower() in s.lower() and s not in found:
                found.append(s)
    return found


def analyze_sections(file_path):
    sections_data = []
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            data = section.get_data()
            entropy = calculate_entropy(data)

            flag = "NORMAL"
            if entropy > 7.0:
                flag = "SUSPICIOUS (PACKED/ENCRYPTED)"

            sections_data.append({
                "name": name,
                "entropy": round(entropy, 2),
                "flag": flag
            })
    except Exception:
        pass
    return sections_data


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy