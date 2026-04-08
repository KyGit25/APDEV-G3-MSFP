#!/usr/bin/env python3
import socket
import sys
import os

SERVER_IP = "103.231.240.136"
SERVER_PORT = 11304

def send_payload(payload: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, SERVER_PORT))
    s.sendall(payload.encode())
    data = s.recv(10 * 1024 * 1024).decode(errors='replace')
    print(f"[Server Response] {data}")
    s.close()

def ingest(filepath):
    if not os.path.exists(filepath):
        print("File not found:", filepath)
        return
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    print(f"[System Message] Uploading {filepath}...")
    payload = f"UPLOAD|{len(content)}|{content}"
    send_payload(payload)

def query(sub_cmd, param):
    payload = f"QUERY|{sub_cmd}|{param}"
    send_payload(payload)

def purge():
    payload = "ADMIN|PURGE|NONE"
    send_payload(payload)

def print_help():
    print("""
Mini-Splunk CLI Commands
------------------------
INGEST <file_path>
QUERY SEARCH_DATE "<date>"
QUERY SEARCH_HOST <hostname>
QUERY SEARCH_DAEMON <daemon_name>
QUERY SEARCH_SEVERITY <severity>
QUERY SEARCH_KEYWORD <keyword>
QUERY COUNT_KEYWORD <keyword>
PURGE
exit
    """)

def main():
    print("Mini-Splunk CLI Client Connected to:", SERVER_IP, SERVER_PORT)
    while True:
        try:
            cmd = input("client> ").strip()
            if not cmd: 
                continue
            if cmd.lower() in ["exit", "quit"]:
                break
            if cmd.lower() == "help":
                print_help()
                continue

            args = cmd.split()
            if args[0] == "INGEST" and len(args) == 2:
                ingest(args[1])
            elif args[0] == "QUERY" and len(args) >= 3:
                query(args[1], " ".join(args[2:]).strip('"'))
            elif args[0] == "PURGE":
                purge()
            else:
                print("Invalid command. Type 'help' for usage.")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
