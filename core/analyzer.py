import math
import re
import pefile


def extract_strings(file_path, min_length=4):
    strings_list = []
    try:
        with open(file_path, "rb") as f:
            content = f.read()

        ascii_re = re.compile(b"[\x20-\x7E]{" + bytes(str(min_length), "utf-8") + b",}")
        for match in ascii_re.finditer(content):
            strings_list.append(match.group().decode("utf-8", errors="ignore"))

        unicode_re = re.compile(b"(?:[\x20-\x7E]\x00){" + bytes(str(min_length), "utf-8") + b",}")
        for match in unicode_re.finditer(content):
            strings_list.append(match.group().decode("utf-16le", errors="ignore"))

    except Exception:
        pass
    return strings_list


def filter_suspicious_strings(strings_list):
    suspicious = []
    patterns = [
        r"https?://", r"www\.", r"\.exe", r"\.dll", r"\.sys",
        r"cmd\.exe", r"powershell", r"RegSetValueEx", r"CreateRemoteThread",
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ]
    for s in strings_list:
        for pattern in patterns:
            if re.search(pattern, s, re.IGNORECASE) and s not in suspicious:
                suspicious.append(s)
    return suspicious


def analyze_sections(file_path):
    sections_data = []
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            data = section.get_data()
            if not data:
                entropy = 0.0
            else:
                entropy = 0.0
                length = len(data)
                occurences = [0] * 256
                for byte in data:
                    occurences[byte] += 1
                for count in occurences:
                    if count > 0:
                        p = float(count) / length
                        entropy -= p * math.log(p, 2)

            flag = "NORMAL"
            if entropy > 7.2:
                flag = "SUSPICIOUS (Packed/Encrypted)"
            elif entropy < 1.0 and len(data) > 0:
                flag = "SUSPICIOUS (Anormally Empty)"

            sections_data.append({
                "name": name,
                "entropy": round(entropy, 2),
                "flag": flag
            })
    except Exception:
        return None
    return sections_data

