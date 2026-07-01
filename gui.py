import os
import threading
import customtkinter as ctk
from tkinter import filedialog
from core.hasher import calculate_hashes
from core.pe_analyzer import analyze_pe_imports
from core.vt_checker import check_hash_vt
from core.analyzer import extract_strings, filter_suspicious_strings, analyze_sections
from core.reporter import calculate_risk_score, export_to_json

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class MiniSandboxGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("MiniSandBox Engine")
        self.geometry("900x620")
        self.minsize(800, 560)
        self.configure(fg_color="#0D0E12")

        self.selected_file_path = None
        self._build_ui()

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(pady=(24, 12), padx=36, fill="x")

        ctk.CTkLabel(
            header, text="MINISANDBOX",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            text_color="#FFFFFF"
        ).pack(side="left")

        ctk.CTkLabel(
            header, text=" // automated malware analytics",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#4B5563"
        ).pack(side="left", pady=(4, 0))

        # File selector card
        file_card = ctk.CTkFrame(self, fg_color="#16171D", corner_radius=10,
                                  border_width=1, border_color="#24262F")
        file_card.pack(pady=(0, 10), padx=36, fill="x")

        file_inner = ctk.CTkFrame(file_card, fg_color="transparent")
        file_inner.pack(pady=16, padx=20, fill="x")

        self.btn_browse = ctk.CTkButton(
            file_inner, text="＋  Select Binary",
            command=self.browse_file,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#1F6FEB", hover_color="#1558C0",
            text_color="#FFFFFF", height=38, width=140, corner_radius=6
        )
        self.btn_browse.pack(side="left")

        self.lbl_file = ctk.CTkLabel(
            file_inner, text="No file selected.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#6B7280"
        )
        self.lbl_file.pack(side="left", padx=16)

        # Score display
        score_card = ctk.CTkFrame(self, fg_color="#16171D", corner_radius=10,
                                   border_width=1, border_color="#24262F")
        score_card.pack(pady=(0, 10), padx=36, fill="x")

        score_inner = ctk.CTkFrame(score_card, fg_color="transparent")
        score_inner.pack(pady=16, padx=20, fill="x")

        self.score_label = ctk.CTkLabel(
            score_inner, text="--",
            font=ctk.CTkFont(family="Segoe UI", size=52, weight="bold"),
            text_color="#2D3748"
        )
        self.score_label.pack(side="left")

        verdict_col = ctk.CTkFrame(score_inner, fg_color="transparent")
        verdict_col.pack(side="left", padx=20)

        self.verdict_label = ctk.CTkLabel(
            verdict_col, text="AWAITING INGESTION",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#4B5563"
        )
        self.verdict_label.pack(anchor="w")

        self.lbl_status = ctk.CTkLabel(
            verdict_col, text="Core engine ready.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#374151"
        )
        self.lbl_status.pack(anchor="w", pady=(4, 0))

        self.btn_analyze = ctk.CTkButton(
            score_inner, text="Analyze",
            state="disabled",
            command=self.start_analysis_thread,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color="#10B981", hover_color="#059669",
            text_color="#FFFFFF", height=42, width=120, corner_radius=6
        )
        self.btn_analyze.pack(side="right")

        # Console
        console_frame = ctk.CTkFrame(self, fg_color="#16171D", corner_radius=10,
                                      border_width=1, border_color="#24262F")
        console_frame.pack(pady=(0, 20), padx=36, fill="both", expand=True)

        ctk.CTkLabel(
            console_frame, text="OUTPUT",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color="#374151"
        ).pack(anchor="w", padx=16, pady=(12, 0))

        self.txt_console = ctk.CTkTextbox(
            console_frame,
            fg_color="#0D0E12", border_color="#1F2028",
            border_width=1, corner_radius=6,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#A3AED0"
        )
        self.txt_console.pack(pady=(6, 16), padx=16, fill="both", expand=True)
        self.txt_console.configure(state="disabled")

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select Windows Portable Executable",
            filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
        )
        if path:
            self.selected_file_path = path
            self.lbl_file.configure(
                text=os.path.basename(path), text_color="#9CA3AF"
            )
            self.btn_analyze.configure(state="normal")
            self.log(f"[+] Loaded: {path}")

    def log(self, text):
        self.txt_console.configure(state="normal")
        self.txt_console.insert("end", text + "\n")
        self.txt_console.see("end")
        self.txt_console.configure(state="disabled")

    def start_analysis_thread(self):
        self.btn_analyze.configure(state="disabled")
        self.btn_browse.configure(state="disabled")
        self.lbl_status.configure(text="Processing artifact...")
        threading.Thread(target=self.run_pipeline, daemon=True).start()

    def run_pipeline(self):
        api_key = os.environ.get("VT_API_KEY", "")
        sample = self.selected_file_path

        self.log("[*] Calculating hashes...")
        hashes = calculate_hashes(sample)
        if not hashes:
            self.log("[-] Hash calculation failed.")
            self._reset_buttons()
            return

        self.log(f"    MD5    : {hashes['md5']}")
        self.log(f"    SHA1   : {hashes['sha1']}")
        self.log(f"    SHA256 : {hashes['sha256']}")

        self.log("[*] Querying VirusTotal...")
        vt = check_hash_vt(hashes["sha256"], api_key)
        if vt["status"] == "success":
            self.log(f"    Malicious: {vt['malicious']}  Suspicious: {vt['suspicious']}")
        else:
            self.log(f"    VT: {vt.get('message', 'No data')}")

        self.log("[*] Parsing PE imports...")
        imports = analyze_pe_imports(sample)
        if imports:
            self.log(f"    {len(imports)} DLL(s) found.")
        else:
            self.log("    Not a PE file or no imports found.")

        self.log("[*] Extracting strings...")
        strings = extract_strings(sample)
        suspicious = filter_suspicious_strings(strings)
        self.log(f"    {len(strings)} strings, {len(suspicious)} suspicious.")

        self.log("[*] Analyzing section entropy...")
        sections = analyze_sections(sample)
        if sections:
            for s in sections:
                self.log(f"    {s['name']:<12} entropy: {s['entropy']}  {s['flag']}")

        self.log("[*] Calculating risk score...")
        score, verdict = calculate_risk_score(vt, suspicious, sections, [], [])
        export_to_json(hashes, vt, imports, suspicious, sections, [], [], [])

        self.log(f"\n[+] VERDICT: {verdict}  |  SCORE: {score}/100\n")

        color = {"CLEAN": "#10B981", "SUSPICIOUS": "#F59E0B", "MALICIOUS": "#EF4444"}.get(verdict, "#FFFFFF")
        self.score_label.configure(text=str(score), text_color=color)
        self.verdict_label.configure(text=verdict, text_color=color)
        self.lbl_status.configure(text="Analysis complete.")
        self._reset_buttons()

    def _reset_buttons(self):
        self.btn_browse.configure(state="normal")
        self.btn_analyze.configure(state="normal")

if __name__ == "__main__":
    app = MiniSandboxGUI()
    app.mainloop()