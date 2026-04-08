import socket
import threading
from parser_module import parse_syslog_lines
from data_storage import LogStorage
from query_engine import QueryEngine
from protocol import *

HOST = "0.0.0.0"
PORT = 65432

storage = LogStorage()
query_engine = QueryEngine(storage)

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    try:
        data = conn.recv(1024).decode(errors="ignore")
        if not data:
            return

        parts = data.split("|")
        command_type = parts[0]

        if command_type == "UPLOAD":  # INGEST command
            try:
                # Expect UPLOAD|<filesize>|<file_content>
                file_content = "|".join(parts[2:])  # in case content has '|'
                logs = parse_syslog_lines(file_content.splitlines())
                with storage.lock:
                    storage.add_entries(logs)
                conn.sendall(b"SUCCESS: Logs Indexed")
            except Exception as e:
                conn.sendall(f"ERROR: {e}".encode())

        elif command_type == "QUERY":
            try:
                subcommand = parts[1]
                value = parts[2] if len(parts) > 2 else ""
                with storage.lock:
                    response = query_engine.handle_query(subcommand, value)
                conn.sendall(response.encode(errors="ignore"))
            except Exception as e:
                conn.sendall(f"ERROR: {e}".encode())

        elif command_type == "ADMIN":  # PURGE
            try:
                storage.clear_all()
                conn.sendall(b"SUCCESS: Memory Purged")
            except Exception as e:
                conn.sendall(f"ERROR: {e}".encode())
        else:
            conn.sendall(b"ERROR: Unknown Command")

    except Exception as e:
        print(f"[!] Client {addr} error: {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected {addr}")

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"[*] Log Server listening on {HOST}:{PORT}")

    while True:
        try:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("[-] Server shutting down")
            break
        except Exception as e:
            print(f"[!] Error accepting: {e}")

if __name__ == "__main__":
    start_server()
