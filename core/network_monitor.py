import psutil
import threading
import time


class NetworkMonitor(threading.Thread):
    def __init__(self, interval=0.1):
        super().__init__()
        self.interval = interval
        self.running = False
        self.captured_connections = []
        self.initial_connections = set()

    def _get_connection_fingerprint(self, conn):
        """
        Creates a unique string fingerprint for a given network connection
        based on local and remote address structures.
        """
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "NONE"
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "NONE"
        return f"{conn.pid}_{conn.type}_{laddr}_{raddr}"

    def get_active_connections(self):
        """
        Queries the operating system network stack to track all current
        established or listening TCP/UDP socket connections.
        """
        connections = {}
        try:
            for conn in psutil.net_connections(kind='all'):
                if conn.pid is not None:
                    fingerprint = self._get_connection_fingerprint(conn)
                    connections[fingerprint] = conn
        except (psutil.AccessDenied, PermissionError):
            pass
        return connections

    def run(self):
        """
        Executes the background asynchronous network socket tracking loop.
        Appends any newly established outward network connections to the log.
        """
        self.running = True
        current_snapshot = self.get_active_connections()
        self.initial_connections = set(current_snapshot.keys())

        while self.running:
            try:
                latest_snapshot = self.get_active_connections()
                latest_connections = set(latest_snapshot.keys())
                new_connections = latest_connections - self.initial_connections

                for conn_id in new_connections:
                    if not any(c['connection_id'] == conn_id for c in self.captured_connections):
                        conn_obj = latest_snapshot[conn_id]
                        remote_ip = conn_obj.raddr.ip if conn_obj.raddr else "NONE"
                        remote_port = conn_obj.raddr.port if conn_obj.raddr else "NONE"

                        try:
                            proc_name = psutil.Process(conn_obj.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "UNKNOWN"

                        self.captured_connections.append({
                            "connection_id": conn_id,
                            "pid": conn_obj.pid,
                            "process_name": proc_name,
                            "type": "TCP" if conn_obj.type == 1 else "UDP",
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "status": conn_obj.status
                        })

                time.sleep(self.interval)
            except Exception:
                continue

    def stop(self):
        """
        Gracefully terminates the background network monitoring thread.
        """
        self.running = False
