# 🛡️ MiniSandBox

A lightweight, modular **static malware analysis engine** built in Python.  
MiniSandBox analyzes Windows PE (Portable Executable) files without executing them,
extracts threat indicators, queries VirusTotal, and produces a structured risk report.

---

## Features

- **Cryptographic Hashing** — MD5, SHA1, SHA256 fingerprinting
- **PE Import Analysis** — Parses the Import Address Table (IAT) to detect suspicious API calls
- **String Extraction** — Extracts ASCII & Unicode strings, filters for suspicious patterns (URLs, registry paths, dangerous APIs)
- **Section Entropy Analysis** — Detects packed or encrypted sections using Shannon Entropy
- **VirusTotal Integration** — Queries threat intelligence via VirusTotal v3 API
- **Risk Scoring Engine** — Produces a 0–100 threat score with a CLEAN / SUSPICIOUS / MALICIOUS verdict
- **Modern GUI** — Dark-themed interface built with CustomTkinter
- **JSON Reports** — All findings exported to structured JSON reports

---

## Screenshots

> GUI screenshot coming soon.

---

## Installation

**Requirements:** Python 3.10+, Windows (PE analysis is Windows-targeted)

```bash
git clone https://github.com/jeweisy/MiniSandBox.git
cd MiniSandBox
pip install -r requirements.txt
```

**Set your VirusTotal API key** (free at [virustotal.com](https://www.virustotal.com)):

```powershell
$env:VT_API_KEY = "your_api_key_here"
```

---

## Usage

**GUI Mode:**
```bash
python gui.py
```

**CLI Mode:**
```bash
python main.py
```

Place the target `.exe` file in the `samples/` directory and update the path in `main.py`.

---

## Project Structure

```
MiniSandBox/
├── core/
│   ├── hasher.py          # MD5, SHA1, SHA256 hashing
│   ├── pe_analyzer.py     # PE Import Address Table parser
│   ├── analyzer.py        # String extraction & section entropy
│   ├── vt_checker.py      # VirusTotal API integration
│   └── reporter.py        # Risk scoring engine & JSON export
├── gui.py                 # CustomTkinter GUI
├── main.py                # CLI entry point
├── requirements.txt
└── reports/               # Generated analysis reports (gitignored)
```

---

## Risk Scoring

| Score | Verdict |
|-------|---------|
| 0 – 30 | ✅ CLEAN |
| 31 – 60 | ⚠️ SUSPICIOUS |
| 61 – 100 | 🔴 MALICIOUS |

Scoring factors: VirusTotal detections, section entropy, suspicious strings, dynamic behavior (Phase 2).

---

## Roadmap

- [x] Static analysis engine (hashing, IAT, strings, entropy)
- [x] VirusTotal threat intelligence
- [x] Risk scoring & verdict system
- [x] Modern dark GUI
- [ ] Dynamic sandbox (Phase 2) — VMware-isolated behavioral analysis
- [ ] HTML report export
- [ ] YARA rule integration

---

## Disclaimer

This tool is intended for **educational and research purposes only**.  
Always analyze files in an isolated environment. Never run unknown executables on your host machine.

---

## Author

**jeweisy** — Cybersecurity Student, Ankara University  
[github.com/jeweisy](https://github.com/jeweisy)