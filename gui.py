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


class MiniSandboxGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("MiniSandBox Engine")
        self.geometry("760x540")
        self.resizable(False, False)
        self.configure(fg_color="#0D0E12")

        self.selected_file_path = None

        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(pady=(30, 20), padx=40, fill="x")

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="MINISANDBOX",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color="#FFFFFF"
        )
        self.title_label.pack(side="left")

        self.subtitle_label = ctk.CTkLabel(
            self.header_frame,
            text=" // automated malware analytics",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#4B5563"
        )
        self.subtitle_label.pack(side="left", padx=5, pady=(4, 0))

        self.main_frame = ctk.CTkFrame(self, fg_color="#16171D", corner_radius=8, border_width=1,
                                       border_color="#24262F")
        self.main_frame.pack(pady=10, padx=40, fill="both", expand=True)

        self.file_section = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.file_section.pack(pady=(25, 15), padx=30, fill="x")

        self.btn_browse = ctk.CTkButton(
            self.file_section,
            text="Select Binary",
            command=self.browse_file,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#24262F",
            hover_color="#2D303B",
            text_color="#E5E7EB",
            height=36,
            width=120,
            corner_radius=4
        )
        self.btn_browse.pack(side="left")

        self.lbl_file_path = ctk.CTkLabel(
            self.file_section,
            text="No artifact ingested.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#6B7280"
        )
        self.lbl_file_path.pack(side="left", padx=15)

        self.score_display_frame = ctk.CTkFrame(self.main_frame, fg_color="#1C1D24", corner_radius=6, border_width=1,
                                                border_color="#2A2C36")
        self.score_display_frame.pack(pady=10, padx=30, fill="x")

        self.score_label = ctk.CTkLabel(
            self.score_display_frame,
            text="--",
            font=ctk.CTkFont(family="Segoe UI", size=48, weight="bold"),
            text_color="#374151"
        )
        self.score_label.pack(pady=(15, 2))

        self.verdict_label = ctk.CTkLabel(
            self.score_display_frame,
            text="AWAITING INGESTION",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#4B5563"
        )
        self.verdict_label.pack(pady=(0, 15))

        self.txt_console = ctk.CTkTextbox(
            self.main_frame,
            fg_color="#0D0E12",
            border_color="#24262F",
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#A3AED0"
        )
        self.txt_console.pack(pady=(10, 25), padx=30, fill="both", expand=True)
        self.txt_console.configure(state="disabled")

        self.footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.footer_frame.pack(pady=(10, 20), padx=40, fill="x")

        self.lbl_status = ctk.CTkLabel(
            self.footer_frame,
            text="System status: Core engine ready.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#4B5563"
        )
        self.lbl_status.pack(side="left")

        self.btn_analyze = ctk.CTkButton(
            self.footer_frame,
            text="Analyze",
            state="disabled",
            fg_color="#10B981",
            hover_color="#059669",
            text_color="#FFFFFF",
            height=36,
            width=100,
            corner_radius=4,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            command=self.start_analysis_thread
        )
        self.btn_analyze.pack(side="right")

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Windows Portable Executable",
            filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
        )
        if file_path:
            self.selected_file_path = file_path
            self.lbl_file_path.configure(text=os.path.basename(file_path), text_color="#9CA3AF")
            self.btn_analyze.configure(state="normal")
            self.update_console(f"[+] Loaded payload successfully: {file_path}")

    def update_console(self, text):
        self.txt_console.configure(state="normal")
        self.txt_console.insert("end", text + "\n")
        self.txt_console.see("end")
        self.txt_console.configure(state="disabled")

    def start_analysis_thread(self):
        self.btn_analyze.configure(state="disabled")
        self.btn_browse.configure(state="disabled")
        self.lbl_status.configure(text="System status: Processing artifact...")

        analysis_thread = threading.Thread(target=self.run_sandbox_pipeline)
        analysis_thread.start()

    def run_sandbox_pipeline(self):
        api_key = os.environ.get("VT_API_KEY", "")
        sample = self.selected_file_path

        self.update_console("[*] Initializing static heuristic inspection...")
        hashes = calculate_hashes(sample)

        self.update_console("[*] Dispatching signature queries to threat feed...")
        vt_results = check_hash_vt(hashes["sha256"], api_key)

        pe_imports = analyze_pe_imports(sample)
        all_strings = extract_strings(sample)
        suspicious_strings = filter_suspicious_strings(all_strings)
        sections = analyze_sections(sample)

        self.update_console("[*] Correlating indicator matrices...")
        risk_score, verdict = calculate_risk_score(vt_results, suspicious_strings, sections, [], [])

        export_to_json(hashes, vt_results, pe_imports, suspicious_strings, sections, [], [], [])

        self.lbl_status.configure(text="System status: Integrity analysis complete.")
        self.score_label.configure(text=f"{risk_score}")
        self.verdict_label.configure(text=verdict)

        if verdict == "CLEAN":
            self.score_label.configure(text_color="#10B981")
            self.verdict_label.configure(text_color="#10B981")
        elif verdict == "SUSPICIOUS":
            self.score_label.configure(text_color="#F59E0B")
            self.verdict_label.configure(text_color="#F59E0B")
        else:
            self.score_label.configure(text_color="#EF4444")
            self.verdict_label.configure(text_color="#EF4444")

        self.update_console(f"[+] Execution pipeline finished. Verdict: {verdict}")

        self.btn_browse.configure(state="normal")
        self.btn_analyze.configure(state="normal")


if __name__ == "__main__":
    app = MiniSandboxGUI()
    app.mainloop()