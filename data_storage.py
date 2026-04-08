import threading

class LogStorage:
    def __init__(self):
        self.logs = []
        self.lock = threading.RLock()

    def add_entries(self, entries):
        self.logs.extend(entries)
        print(f"[DEBUG] Added {len(entries)} entries. Total: {len(self.logs)}")

    def get_all(self):
        return list(self.logs)

    def clear_all(self):
        with self.lock:
            count = len(self.logs)
            self.logs.clear()
            print(f"[DEBUG] Cleared {count} logs.")
            return count
