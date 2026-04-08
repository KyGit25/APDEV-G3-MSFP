#!/usr/bin/env python3
"""
Mini-Splunk Syslog Analytics Client
A command-line interface for uploading syslog files and querying a remote analytics server.
"""

import socket
import sys
import os
from typing import Tuple, Optional


class SyslogClient:
    """Client for communicating with the syslog analytics server."""
    
    def __init__(self):
        self.server_ip = "103.231.240.136"
        self.server_port = 11304
    
    def parse_address(self, address: str) -> Tuple[str, int]:
        """
        Parse an address string in format IP:Port or DNS:Port.
        
        Args:
            address: Address string like '192.168.1.100:65432' or 'localhost:8080'
            
        Returns:
            Tuple of (IP/DNS, Port)
            
        Raises:
            ValueError: If format is invalid
        """
        if ':' not in address:
            raise ValueError(f"Invalid address format: {address}. Expected IP/DNS:Port")
        
        parts = address.rsplit(':', 1)
        ip_or_dns = parts[0]
        
        try:
            port = int(parts[1])
        except ValueError:
            raise ValueError(f"Invalid port number: {parts[1]}")
        
        if port < 1 or port > 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {port}")
        
        return ip_or_dns, port
    
    def connect_to_server(self, ip: str, port: int) -> socket.socket:
        """
        Connect to the server.
        
        Args:
            ip: Server IP or DNS
            port: Server port
            
        Returns:
            Connected socket
            
        Raises:
            ConnectionError: If connection fails
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, port))
            return sock
        except socket.timeout:
            raise ConnectionError(f"Connection timeout to {ip}:{port}")
        except socket.gaierror:
            raise ConnectionError(f"Failed to resolve hostname: {ip}")
        except ConnectionRefusedError:
            raise ConnectionError(f"Connection refused by {ip}:{port}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {ip}:{port}: {e}")
    
    def send_command(self, sock: socket.socket, command: str) -> str:
        """
        Send a command to the server and receive response.
        
        Args:
            sock: Connected socket
            command: Command string
            
        Returns:
            Server response
        """
        try:
            # Send the complete command
            sock.sendall(command.encode('utf-8'))
            
            # Signal that we're done sending - close write side
            try:
                sock.shutdown(socket.SHUT_WR)
            except:
                pass
            
            # Now receive response with robust timeout handling
            response = b""
            sock.settimeout(120)  # 2 minutes to receive response
            
            while True:
                try:
                    chunk = sock.recv(16384)  # 16KB buffer
                    if not chunk:
                        # Server closed connection - we got all data
                        break
                    response += chunk
                except socket.timeout:
                    # Timeout while waiting for data - we got what we could
                    break
                except Exception as e:
                    # Connection issues
                    break
            
            result = response.decode('utf-8', errors='replace')
            if not result:
                return "ERROR: No response from server - file may not have been processed"
            return result
            
        except Exception as e:
            raise Exception(f"Communication error: {e}")
    
    def cmd_ingest(self, args: list) -> None:
        """
        INGEST command: Upload a syslog file to the server.
        
        Usage: INGEST <file_path> [IP:Port]
        
        Args:
            args: Command arguments
        """
        if len(args) < 1:
            print("[Error] INGEST command requires: INGEST <file_path> [IP:Port]")
            return
        
        file_path = args[0]
        address = args[1] if len(args) > 1 else f"{self.server_ip}:{self.server_port}"
        
        # Validate file exists
        if not os.path.exists(file_path):
            print(f"[Error] File not found: {file_path}")
            return
        
        if not os.path.isfile(file_path):
            print(f"[Error] Path is not a file: {file_path}")
            return
        
        try:
            # Parse server address
            ip, port = self.parse_address(address)
            
            # Read file
            print("[System Message] Reading local file...")
            sys.stdout.flush()
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                file_content = f.read()
            
            file_size = len(file_content)
            file_size_mb = file_size / (1024 * 1024)
            
            # Connect to server
            print(f"[System Message] Connecting to {ip}:{port}...")
            sys.stdout.flush()
            sock = self.connect_to_server(ip, port)
            
            # Build protocol message: UPLOAD|<filesize>|<file_content>
            print(f"[System Message] Uploading syslog ({file_size_mb:.1f} MB)...")
            sys.stdout.flush()
            command = f"UPLOAD|{file_size}|{file_content}"
            
            # Send and receive
            response = self.send_command(sock, command)
            sock.close()
            
            print(f"[Server Response] {response}")
            sys.stdout.flush()
        
        except ValueError as e:
            print(f"[Error] {e}")
        except ConnectionError as e:
            print(f"[Error] {e}")
        except Exception as e:
            print(f"[Error] {e}")
        
        sys.stdout.flush()
    
    def cmd_query(self, args: list) -> None:
        """
        QUERY command: Execute search and count operations on the server.
        
        Usage: QUERY <SEARCH_TYPE> <filter_value> [IP:Port]
        Supported search types: SEARCH_DATE, SEARCH_HOST, SEARCH_DAEMON, 
                               SEARCH_SEVERITY, SEARCH_KEYWORD, COUNT_KEYWORD
        
        Args:
            args: Command arguments
        """
        if len(args) < 2:
            print("[Error] QUERY command requires: QUERY <SEARCH_TYPE> <value> [IP:Port]")
            print("Supported search types:")
            print("  - SEARCH_DATE <date_string>")
            print("  - SEARCH_HOST <hostname>")
            print("  - SEARCH_DAEMON <daemon_name>")
            print("  - SEARCH_SEVERITY <level>")
            print("  - SEARCH_KEYWORD <keyword>")
            print("  - COUNT_KEYWORD <keyword>")
            return
        
        search_type = args[0].upper()
        # Find if last arg is an IP:Port format or part of filter value
        potential_address = args[-1]
        if ':' in potential_address and len(args) > 2:
            address = args[-1]
            filter_value = ' '.join(args[1:-1])
        else:
            address = f"{self.server_ip}:{self.server_port}"
            filter_value = ' '.join(args[1:])  # Join remaining args for multi-word filters
        
        # Validate search type
        valid_types = ['SEARCH_DATE', 'SEARCH_HOST', 'SEARCH_DAEMON', 
                      'SEARCH_SEVERITY', 'SEARCH_KEYWORD', 'COUNT_KEYWORD']
        if search_type not in valid_types:
            print(f"[Error] Unknown search type: {search_type}")
            print(f"Valid types: {', '.join(valid_types)}")
            return
        
        try:
            # Parse server address
            ip, port = self.parse_address(address)
            
            # Connect to server
            print("[System Message] Sending query...")
            sys.stdout.flush()
            sock = self.connect_to_server(ip, port)
            
            # Build protocol message: QUERY|<search_type>|<filter_value>
            command = f"QUERY|{search_type}|{filter_value}"
            
            # Send and receive
            response = self.send_command(sock, command)
            sock.close()
            
            print(f"[Server Response] {response}")
            sys.stdout.flush()
        
        except ValueError as e:
            print(f"[Error] {e}")
        except ConnectionError as e:
            print(f"[Error] {e}")
        except Exception as e:
            print(f"[Error] {e}")
        
        sys.stdout.flush()
    
    def cmd_purge(self, args: list) -> None:
        """
        PURGE command: Delete all indexed logs from the server.
        
        Usage: PURGE [IP:Port]
        
        Args:
            args: Command arguments
        """
        address = args[0] if len(args) > 0 else f"{self.server_ip}:{self.server_port}"
        
        try:
            # Parse server address
            ip, port = self.parse_address(address)
            
            # Connect to server
            print(f"[System Message] Connecting to {ip}:{port} to purge records...")
            sys.stdout.flush()
            sock = self.connect_to_server(ip, port)
            
            # Build protocol message: ADMIN|PURGE|NONE
            command = "ADMIN|PURGE|NONE"
            
            # Send and receive
            response = self.send_command(sock, command)
            sock.close()
            
            print(f"[Server Response] {response}")
            sys.stdout.flush()
        
        except ValueError as e:
            print(f"[Error] {e}")
        except ConnectionError as e:
            print(f"[Error] {e}")
        except Exception as e:
            print(f"[Error] {e}")
        
        sys.stdout.flush()
    
    def print_help(self) -> None:
        """Print help message."""
        print("\n=== Mini-Splunk Syslog Analytics Client ===\n")
        print(f"Default Server: {self.server_ip}:{self.server_port}\n")
        print("Available Commands:\n")
        print("1. INGEST <file_path> [IP:Port]")
        print("   Upload and parse a local syslog file to the server")
        print("   Example: INGEST /var/log/syslog")
        print("   Example: INGEST /var/log/syslog 192.168.1.100:65432\n")
        print("2. QUERY <SEARCH_TYPE> <filter> [IP:Port]")
        print("   Execute search and count operations")
        print("   Search types:")
        print("     - SEARCH_DATE <date_string>    (e.g., 'Feb 22')")
        print("     - SEARCH_HOST <hostname>       (e.g., 'SYSSVR1')")
        print("     - SEARCH_DAEMON <daemon>       (e.g., 'sshd')")
        print("     - SEARCH_SEVERITY <level>      (e.g., 'ERROR')")
        print("     - SEARCH_KEYWORD <keyword>     (e.g., 'Failed password')")
        print("     - COUNT_KEYWORD <keyword>      (e.g., 'Deactivated')")
        print("   Examples:")
        print("     QUERY SEARCH_DATE Feb 22")
        print("     QUERY SEARCH_HOST SYSSVR1")
        print("     QUERY SEARCH_HOST SYSSVR1 192.168.1.100:65432\n")
        print("3. PURGE [IP:Port]")
        print("   Delete all indexed logs from the server")
        print("   Example: PURGE")
        print("   Example: PURGE 192.168.1.100:65432\n")
        print("4. HELP")
        print("   Show this help message\n")
        print("5. EXIT")
        print("   Quit the client\n")
    
    def run(self) -> None:
        """Run the interactive CLI loop."""
        print("\n=== Mini-Splunk Syslog Analytics Client ===")
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
                    sys.stdout.flush()
                    break
                else:
                    print(f"[Error] Unknown command: {command}")
                    print("[System Message] Type 'HELP' for available commands")
                    sys.stdout.flush()
            
            except KeyboardInterrupt:
                print("\n[System Message] Goodbye!")
                sys.stdout.flush()
                break
            except Exception as e:
                print(f"[Error] Unexpected error: {e}")
                sys.stdout.flush()


def main():
    """Main entry point."""
    client = SyslogClient()
    client.run()


if __name__ == "__main__":
    main()
