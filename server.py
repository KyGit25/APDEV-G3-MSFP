#!/usr/bin/env python3

import socket
import threading
import re
import sys
from typing import List, Dict

LOG_STORAGE: List[Dict[str, str]] = []
STATE_LOCK = threading.RLock()

SYSLOG_PATTERN = re.compile(
    r"^"
    r"(?P<timestamp>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<daemon>[^\s:]+(?:\[\d+\])?)"
    r":\s*"
    r"(?P<message>.*)$"
)

SEVERITY_KEYWORDS = {
    "ERROR": ["error", "failed", "fatal", "critical", "exception", "panic"],
    "WARN": ["warn", "warning", "deprecated", "invalid"],
    "INFO": ["info", "started", "stopped", "opened", "closed", "accepted"],
}


def infer_severity(message: str) -> str:
    msg = message.lower()
    for word in SEVERITY_KEYWORDS["ERROR"]:
        if word in msg:
            return "ERROR"
    for word in SEVERITY_KEYWORDS["WARN"]:
        if word in msg:
            return "WARN"
    for word in SEVERITY_KEYWORDS["INFO"]:
        if word in msg:
            return "INFO"
    return "INFO"


# 🔥 FIXED: parse ONE LINE at a time
def parse_syslog(line: str) -> List[Dict[str, str]]:
    match = SYSLOG_PATTERN.match(line.strip())
    if not match:
        return []

    daemon_full = match.group("daemon")
    daemon_name = re.sub(r"\[\d+\]", "", daemon_full)

    return [{
        "timestamp": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "daemon": daemon_name,
        "severity": infer_severity(match.group("message")),
        "message": match.group("message"),
        "raw_line": line
    }]


def recv_until_newline(sock: socket.socket) -> bytes:
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


# 🔥 REAL-TIME STREAMING INGEST
def handle_upload(sock: socket.socket, header_line: str) -> str:
    try:
        parts = header_line.strip().split("|")
        if len(parts) != 2:
            return "ERROR: Invalid upload header"

        _, file_size_str = parts
        expected_size = int(file_size_str)

        buffer = ""
        total_received = 0
        parsed_count = 0

        while total_received < expected_size:
            chunk = sock.recv(4096)

            if not chunk:
                print("[INGEST] Client disconnected early. Partial data saved.")
                break

            total_received += len(chunk)
            text = chunk.decode("utf-8", errors="replace")
            buffer += text

            # PROCESS LINE BY LINE
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)

                parsed = parse_syslog(line)
                if parsed:
                    with STATE_LOCK:
                        LOG_STORAGE.extend(parsed)
                    parsed_count += 1

        return f"SUCCESS: Stream processed. Parsed {parsed_count} entries."

    except Exception as e:
        return f"ERROR: Failed streaming upload: {e}"


def handle_query(request: str) -> str:
    try:
        parts = request.split("|")
        if len(parts) < 3:
            return "ERROR: Invalid QUERY command"

        _, subcommand, filter_value = parts[0], parts[1].upper(), "|".join(parts[2:])

        with STATE_LOCK:
            logs_copy = LOG_STORAGE.copy()

        if subcommand == "SEARCH_DATE":
            results = [log for log in logs_copy if log["timestamp"].startswith(filter_value)]
            label = "date"

        elif subcommand == "SEARCH_HOST":
            results = [log for log in logs_copy if log["hostname"].lower() == filter_value.lower()]
            label = "host"

        elif subcommand == "SEARCH_DAEMON":
            results = [log for log in logs_copy if log["daemon"].lower() == filter_value.lower()]
            label = "daemon"

        elif subcommand == "SEARCH_SEVERITY":
            results = [log for log in logs_copy if log["severity"].upper() == filter_value.upper()]
            label = "severity"

        elif subcommand == "SEARCH_KEYWORD":
            results = [log for log in logs_copy if filter_value.lower() in log["message"].lower()]
            label = "keyword"

        elif subcommand == "COUNT_KEYWORD":
            count = sum(1 for log in logs_copy if filter_value.lower() in log["message"].lower())
            return f"The keyword '{filter_value}' appears in {count} indexed log entry/entries."

        else:
            return f"ERROR: Unknown query subcommand '{subcommand}'"

        if not results:
            return f"Found 0 matching entries for {label} '{filter_value}'"

        response = f"Found {len(results)} matching entries for {label} '{filter_value}':\n"
        for i, log in enumerate(results[:50], 1):
            response += f"{i}. {log['raw_line']}\n"

        return response.strip()

    except Exception as e:
        return f"ERROR: Query execution failed: {e}"


def handle_admin(request: str) -> str:
    try:
        parts = request.split("|")
        operation = parts[1].upper()

        if operation == "PURGE":
            with STATE_LOCK:
                removed = len(LOG_STORAGE)
                LOG_STORAGE.clear()
            return f"SUCCESS: {removed} indexed log entries have been erased."

        return "ERROR: Unknown admin operation"

    except Exception as e:
        return f"ERROR: Admin command failed: {e}"


def handle_client(client_socket: socket.socket, client_address: tuple) -> None:
    try:
        client_socket.settimeout(300)

        first_line = recv_until_newline(client_socket)
        if not first_line:
            return

        decoded = first_line.decode("utf-8", errors="replace")

        if decoded.startswith("UPLOAD|"):
            response = handle_upload(client_socket, decoded)

        else:
            remaining = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                remaining += chunk

            full_request = decoded + remaining.decode("utf-8", errors="replace")

            if full_request.startswith("QUERY|"):
                response = handle_query(full_request)
            elif full_request.startswith("ADMIN|"):
                response = handle_admin(full_request)
            else:
                response = "ERROR: Unknown command"

        client_socket.sendall(response.encode("utf-8"))

    except Exception as e:
        try:
            client_socket.sendall(f"ERROR: {e}".encode())
        except:
            pass
    finally:
        client_socket.close()


def start_server(host="0.0.0.0", port=5000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((host, port))
    server_socket.listen(20)

    print(f"[Server] Listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[Server] Connection from {addr}")

        threading.Thread(
            target=handle_client,
            args=(client_socket, addr),
            daemon=True
        ).start()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    start_server(port=port)
