import socket
import sys
from protocol import *

BUFFER_SIZE = 4096

def send_command(cmd_args):
    try:
        cmd = cmd_args[0].upper()

        if cmd == "INGEST" and len(cmd_args) >= 3:
            file_path = cmd_args[1]
            ip, port = cmd_args[2].split(":")
            data = open(file_path, "r", errors="ignore").read()
            payload = f"UPLOAD|{len(data)}|{data}"
            send_payload(payload, ip, int(port))

        elif cmd in ("QUERY", "PURGE") and len(cmd_args) >= 3:
            ip_port = cmd_args[1]
            ip, port = ip_port.split(":")
            sub_cmd = cmd_args[2]
            value = cmd_args[3] if len(cmd_args) > 3 else ""
            if cmd == "PURGE":
                payload = "ADMIN|PURGE|NONE"
            else:
                payload = f"QUERY|{sub_cmd}|{value}"
            send_payload(payload, ip, int(port))
        else:
            print("Usage:")
            print("  INGEST <file_path> <ip>:<port>")
            print("  QUERY <ip>:<port> <SUBCOMMAND> [VALUE]")
            print("  PURGE <ip>:<port>")
    except Exception as e:
        print(f"[Client Error] {e}")

def send_payload(payload, ip, port):
    print(f"[System Message] Connecting to {ip}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, port))
        s.sendall(payload.encode(errors="ignore"))
        response = s.recv(BUFFER_SIZE).decode(errors="ignore")
        print(f"[Server Response] {response}")
    finally:
        s.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Command required. Example: python client.py INGEST syslog.txt 127.0.0.1:65432")
    else:
        send_command(sys.argv[1:])
