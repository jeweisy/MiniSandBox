import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class SandboxFileHandler(FileSystemEventHandler):
    def __init__(self, events_list):
        self.events_list = events_list

    def on_created(self, event):
        if not event.is_directory:
            self.events_list.append({
                "path": event.src_path,
                "action": "CREATED"
            })

    def on_modified(self, event):
        if not event.is_directory:
            self.events_list.append({
                "path": event.src_path,
                "action": "MODIFIED"
            })

    def on_deleted(self, event):
        if not event.is_directory:
            self.events_list.append({
                "path": event.src_path,
                "action": "DELETED"
            })


class FileMonitor:
    def __init__(self, watch_dir=None):
        if watch_dir is None:
            self.watch_dir = os.path.join(os.getcwd(), "samples")
        else:
            self.watch_dir = watch_dir

        self.captured_events = []
        self.handler = SandboxFileHandler(self.captured_events)
        self.observer = Observer()

    def start(self):
        """
        Initializes and starts the asynchronous file system monitoring
        thread on the designated target directory.
        """
        if not os.path.exists(self.watch_dir):
            os.makedirs(self.watch_dir)
        self.observer.schedule(self.handler, path=self.watch_dir, recursive=True)
        self.observer.start()

    def stop(self):
        """
        Gracefully stops the file system observer and joins the thread execution.
        """
        self.observer.stop()
        self.observer.join()