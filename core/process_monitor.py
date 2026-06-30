import psutil
import threading
import time


class ProcessMonitor(threading.Thread):
    def __init__(self, interval=0.1):
        super().__init__()
        self.interval = interval
        self.running = False
        self.monitored_processes = []
        self.initial_pids = set()

    def get_current_pids(self):
        """
        Queries the operating system to retrieve all currently active
        Process IDs (PIDs) paired with their corresponding executable names.
        """
        pids = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pids[proc.info['pid']] = proc.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return pids

    def run(self):
        """
        Executes the background asynchronous monitoring loop.
        Calculates set differences between snapshot states every 100ms
        to detect newly spawned processes.
        """
        self.running = True
        current_snapshot = self.get_current_pids()
        self.initial_pids = set(current_snapshot.keys())

        while self.running:
            try:
                latest_snapshot = self.get_current_pids()
                latest_pids = set(latest_snapshot.keys())
                new_pids = latest_pids - self.initial_pids

                for pid in new_pids:
                    if not any(p['pid'] == pid for p in self.monitored_processes):
                        proc_name = latest_snapshot[pid]
                        is_suspicious = proc_name.lower() in [
                            "cmd.exe", "powershell.exe", "wscript.exe",
                            "cscript.exe", "whoami.exe"
                        ]

                        self.monitored_processes.append({
                            "pid": pid,
                            "name": proc_name,
                            "status": "SUSPICIOUS_SPAWN" if is_suspicious else "NEW_PROCESS"
                        })

                time.sleep(self.interval)
            except Exception:
                continue

    def stop(self):
        """
        Gracefully terminates the background monitoring loop.
        """
        self.running = False