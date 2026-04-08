#!/usr/bin/env python3

import socket
import os
from typing import Tuple


class SyslogClient:
    def parse_address(self, address: str) -> Tuple[str, int]:
        if ":" not in address:
            raise ValueError("Invalid address format. Use IP:Port")

        host, port_str = address.rsplit(":", 1)
        port = int(port_str)
        return host, port

    def connect_to_server(self, host: str, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(120)
        sock.connect((host, port))
        return sock

    def receive_response(self, sock: socket.socket) -> str:
        response = b""
        sock.settimeout(120)

        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        return response.decode("utf-8", errors="replace")

    def cmd_ingest(self, args: list) -> None:
        if len(args) < 2:
            print("[Error] Usage: INGEST <file_path> <IP>:<Port>")
            return

        file_path = args[0]
        address = args[1]

        if not os.path.exists(file_path):
            print(f"[Error] File not found: {file_path}")
            return

        try:
            host, port = self.parse_address(address)
            file_size = os.path.getsize(file_path)
            file_size_mb = file_size / (1024 * 1024)

            print("[System Message] Reading local file...")
            print(f"[System Message] Connecting to {host}:{port}...")
            print(f"[System Message] Uploading syslog ({file_size_mb:.1f} MB)...")

            with self.connect_to_server(host, port) as sock:
                header = f"UPLOAD|{file_size}\n".encode("utf-8")
                sock.sendall(header)

                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        sock.sendall(chunk)

                sock.shutdown(socket.SHUT_WR)
                response = self.receive_response(sock)

            print(f"[Server Response] {response}")

        except Exception as e:
            print(f"[Error] {e}")

    def cmd_query(self, args: list) -> None:
        if len(args) < 3:
            print("[Error] Usage: QUERY <IP>:<Port> <SEARCH_TYPE> <value>")
            return

        address = args[0]
        search_type = args[1].upper()
        value = " ".join(args[2:])

        try:
            host, port = self.parse_address(address)

            print("[System Message] Sending query...")

            with self.connect_to_server(host, port) as sock:
                command = f"QUERY|{search_type}|{value}".encode("utf-8")
                sock.sendall(command)
                sock.shutdown(socket.SHUT_WR)

                response = self.receive_response(sock)

            print(f"[Server Response] {response}")

        except Exception as e:
            print(f"[Error] {e}")

    def cmd_purge(self, args: list) -> None:
        if len(args) < 1:
            print("[Error] Usage: PURGE <IP>:<Port>")
            return

        address = args[0]

        try:
            host, port = self.parse_address(address)

            print(f"[System Message] Connecting to {host}:{port} to purge records...")

            with self.connect_to_server(host, port) as sock:
                sock.sendall(b"ADMIN|PURGE|NONE")
                sock.shutdown(socket.SHUT_WR)

                response = self.receive_response(sock)

            print(f"[Server Response] {response}")

        except Exception as e:
            print(f"[Error] {e}")

    def print_help(self) -> None:
        print("\nAvailable commands:")
        print("  INGEST <file_path> <IP>:<Port>")
        print("  QUERY <IP>:<Port> SEARCH_DATE <date_string>")
        print("  QUERY <IP>:<Port> SEARCH_HOST <hostname>")
        print("  QUERY <IP>:<Port> SEARCH_DAEMON <daemon_name>")
        print("  QUERY <IP>:<Port> SEARCH_SEVERITY <severity_level>")
        print("  QUERY <IP>:<Port> SEARCH_KEYWORD <keyword>")
        print("  QUERY <IP>:<Port> COUNT_KEYWORD <keyword>")
        print("  PURGE <IP>:<Port>")
        print("  HELP")
        print("  EXIT\n")

    def run(self) -> None:
        print("=== Mini-Splunk Syslog Analytics Client ===")
        print("Type 'HELP' for available commands or 'EXIT' to quit\n")

        while True:
            try:
                user_input = input("client> ").strip()
                if not user_input:
                    continue

                parts = user_input.split()
                command = parts[0].upper()
                args = parts[1:]

                if command == "INGEST":
                    self.cmd_ingest(args)
                elif command == "QUERY":
                    self.cmd_query(args)
                elif command == "PURGE":
                    self.cmd_purge(args)
                elif command == "HELP":
                    self.print_help()
                elif command == "EXIT":
                    print("[System Message] Goodbye!")
                    break
                else:
                    print("[Error] Unknown command")

            except KeyboardInterrupt:
                print("\n[System Message] Goodbye!")
                break
            except Exception as e:
                print(f"[Error] {e}")


if __name__ == "__main__":
    SyslogClient().run()
