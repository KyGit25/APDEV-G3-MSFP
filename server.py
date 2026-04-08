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


def parse_syslog(content: str) -> List[Dict[str, str]]:
    parsed_logs = []

    for line in content.splitlines():
        if not line.strip():
            continue

        match = SYSLOG_PATTERN.match(line)
        if not match:
            continue

        daemon_full = match.group("daemon")
        daemon_name = re.sub(r"\[\d+\]", "", daemon_full)

        parsed_logs.append({
            "timestamp": match.group("timestamp"),
            "hostname": match.group("hostname"),
            "daemon": daemon_name,
            "severity": infer_severity(match.group("message")),
            "message": match.group("message"),
            "raw_line": line
        })

    return parsed_logs


def recv_until_newline(sock: socket.socket) -> bytes:
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def recv_exact(sock: socket.socket, total_bytes: int) -> bytes:
    data = bytearray()
    while len(data) < total_bytes:
        chunk = sock.recv(min(8192, total_bytes - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def handle_upload(sock: socket.socket, header_line: str) -> str:
    try:
        parts = header_line.strip().split("|")
        if len(parts) != 2:
            return "ERROR: Invalid upload header"

        _, file_size_str = parts
        file_size = int(file_size_str)

        file_bytes = recv_exact(sock, file_size)

        if len(file_bytes) != file_size:
            return f"ERROR: Incomplete file received. Expected {file_size} bytes, got {len(file_bytes)} bytes."

        content = file_bytes.decode("utf-8", errors="replace")
        parsed_logs = parse_syslog(content)

        if not parsed_logs:
            return "ERROR: No valid syslog entries found in file"

        with STATE_LOCK:
            LOG_STORAGE.extend(parsed_logs)
            total_count = len(LOG_STORAGE)

        return f"SUCCESS: File received and {len(parsed_logs)} syslog entries parsed and indexed. Total entries: {total_count}"

    except Exception as e:
        return f"ERROR: Failed to process upload: {e}"


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

        preview = results[:50]
        response = f"Found {len(results)} matching entries for {label} '{filter_value}':\n"
        for i, log in enumerate(preview, 1):
            response += f"{i}. {log['raw_line']}\n"

        if len(results) > 50:
            response += f"... showing first 50 of {len(results)} results"

        return response.strip()

    except Exception as e:
        return f"ERROR: Query execution failed: {e}"


def handle_admin(request: str) -> str:
    try:
        parts = request.split("|")
        if len(parts) < 2:
            return "ERROR: Invalid ADMIN command"

        operation = parts[1].upper()

        if operation == "PURGE":
            with STATE_LOCK:
                removed = len(LOG_STORAGE)
                LOG_STORAGE.clear()
            return f"SUCCESS: {removed} indexed log entries have been erased."

        return f"ERROR: Unknown admin operation '{operation}'"

    except Exception as e:
        return f"ERROR: Admin command failed: {e}"


def handle_client(client_socket: socket.socket, client_address: tuple) -> None:
    try:
        client_socket.settimeout(300)

        first_line = recv_until_newline(client_socket)
        if not first_line:
            client_socket.close()
            return

        decoded_first_line = first_line.decode("utf-8", errors="replace")

        if decoded_first_line.startswith("UPLOAD|"):
            response = handle_upload(client_socket, decoded_first_line)

        else:
            remaining = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                remaining += chunk

            full_request = decoded_first_line + remaining.decode("utf-8", errors="replace")

            if full_request.startswith("QUERY|"):
                response = handle_query(full_request)
            elif full_request.startswith("ADMIN|"):
                response = handle_admin(full_request)
            else:
                response = "ERROR: Unknown command type"

        client_socket.sendall(response.encode("utf-8"))

    except Exception as e:
        try:
            client_socket.sendall(f"ERROR: Server error: {e}".encode("utf-8"))
        except Exception:
            pass
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


def start_server(host: str = "127.0.0.1", port: int = 5000) -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(20)
        print(f"[Server] Listening on {host}:{port}")
        print("[Server] Waiting for client connections...")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"[Server] New client connected from {client_address[0]}:{client_address[1]}")

            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")
    except OSError as e:
        print(f"[Server] Failed to bind to {host}:{port}: {e}")
    finally:
        server_socket.close()
        print("[Server] Server stopped")


if __name__ == "__main__":
    try:
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        start_server(host, port)
    except ValueError:
        print("[Server] Invalid port number")
