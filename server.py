#!/usr/bin/env python3
import socket
import threading
import re
import traceback

# ==============================
# Global Shared State & Lock
# ==============================
LOG_STORAGE = []
STATE_LOCK = threading.RLock()

# ==============================
# Regex Parser (RFC 3164/5424 hybrid)
# ==============================
# Example log: Feb  7 16:03:34 SYSSVR1 sshd[1032662]: Accepted password for user...
SYSLOG_REGEX = re.compile(
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>[A-Za-z0-9\-_]+)\s+'
    r'(?P<daemon>[A-Za-z0-9\-\_\/]+)(?:\[\d+\])?:\s+'
    r'(?P<message>.*)'
)

def infer_severity(message: str) -> str:
    msg_upper = message.upper()
    if "ERROR" in msg_upper or "FAIL" in msg_upper:
        return "ERROR"
    elif "WARN" in msg_upper or "INVALID" in msg_upper:
        return "WARN"
    else:
        return "INFO"

def parse_syslog(content: str):
    parsed_entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        m = SYSLOG_REGEX.match(line)
        if m:
            entry = m.groupdict()
            entry["severity"] = infer_severity(entry["message"])
            parsed_entries.append(entry)
    return parsed_entries

# ==============================
# Query Engine
# ==============================
def query_engine(command, value):
    if command == "SEARCH_DATE":
        return [e for e in LOG_STORAGE if e["timestamp"].startswith(value)]
    elif command == "SEARCH_HOST":
        return [e for e in LOG_STORAGE if e["hostname"] == value]
    elif command == "SEARCH_DAEMON":
        return [e for e in LOG_STORAGE if e["daemon"] == value]
    elif command == "SEARCH_SEVERITY":
        return [e for e in LOG_STORAGE if e["severity"] == value.upper()]
    elif command == "SEARCH_KEYWORD":
        return [e for e in LOG_STORAGE if value in e["message"]]
    elif command == "COUNT_KEYWORD":
        count = sum(value in e["message"] for e in LOG_STORAGE)
        return count
    else:
        return []

def format_results(command, results, filter_val):
    if command == "COUNT_KEYWORD":
        return f"The keyword '{filter_val}' appears {results} times."
    if not results:
        return f"No matching entries found for {filter_val}"
    lines = [f"Found {len(results)} matching entries for {filter_val}:"]
    for i, e in enumerate(results, 1):
        lines.append(f"{i}. {e['timestamp']} {e['hostname']} {e['daemon']}: {e['message']}")
    return "\n".join(lines)

# ==============================
# Client Handler Thread
# ==============================
def handle_client(conn, addr):
    try:
        request = conn.recv(10 * 1024 * 1024).decode(errors='replace')
        parts = request.split("|")
        cmdtype = parts[0]

        if cmdtype == "UPLOAD":
            filesize = parts[1]
            file_content = "|".join(parts[2:])
            with STATE_LOCK:
                parsed = parse_syslog(file_content)
                LOG_STORAGE.extend(parsed)
            conn.sendall(f"SUCCESS: File received and {len(parsed)} syslog entries parsed and indexed.".encode())

        elif cmdtype == "QUERY":
            subcmd = parts[1]
            filter_val = parts[2]
            with STATE_LOCK:
                results = query_engine(subcmd, filter_val)
            conn.sendall(format_results(subcmd, results, filter_val).encode())

        elif cmdtype == "ADMIN":
            action = parts[1]
            if action == "PURGE":
                with STATE_LOCK:
                    count = len(LOG_STORAGE)
                    LOG_STORAGE.clear()
                conn.sendall(f"SUCCESS: {count} indexed log entries have been erased.".encode())
            else:
                conn.sendall(b"UNKNOWN ADMIN REQUEST")

        else:
            conn.sendall(b"ERROR: Unknown Command Type")

    except Exception:
        err = traceback.format_exc()
        conn.sendall(f"SERVER ERROR:\n{err}".encode())
    finally:
        conn.close()

# ==============================
# Server Loop
# ==============================
def start_server(ip="0.0.0.0", port=8080):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(10)
    print(f"[+] Mini-Splunk Server listening on {ip}:{port}")

    while True:
        try:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("\nServer shutting down.")
            break
        except Exception:
            traceback.print_exc()

if __name__ == "__main__":
    start_server()
