#!/usr/bin/env python3
"""
Mini-Splunk Syslog Analytics Server
A multithreaded log management and analytics server that ingests, parses,
and analyzes standard syslog files.
"""

import socket
import threading
import re
from typing import List, Dict, Optional
import sys

# Global shared state
LOG_STORAGE: List[Dict[str, str]] = []
STATE_LOCK = threading.RLock()

# Regex pattern for RFC 3164 syslog format
# Pattern: Timestamp Hostname Process[PID]: Message
SYSLOG_PATTERN = re.compile(
    r'^'
    r'(?P<timestamp>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
    r'(?P<hostname>\S+)\s+'  # Hostname
    r'(?P<daemon>[a-zA-Z0-9_\-\.\/]+(?:\[\d+\])?)'  # Daemon/Process
    r':\s*'
    r'(?P<message>.*)$'  # Message (rest of line)
)

# Severity keywords for inference
SEVERITY_KEYWORDS = {
    'ERROR': ['error', 'failed', 'fatal', 'critical', 'exception', 'panic'],
    'WARN': ['warn', 'warning', 'deprecated', 'throttled'],
    'INFO': ['info', 'started', 'stopped', 'listening', 'connected'],
}


def infer_severity(message: str) -> str:
    """
    Infer severity level from message content.
    
    Args:
        message: The syslog message text
        
    Returns:
        Severity level: ERROR, WARN, or INFO
    """
    message_lower = message.lower()
    
    # Check for ERROR keywords first (highest priority)
    for keyword in SEVERITY_KEYWORDS['ERROR']:
        if keyword in message_lower:
            return 'ERROR'
    
    # Check for WARN keywords
    for keyword in SEVERITY_KEYWORDS['WARN']:
        if keyword in message_lower:
            return 'WARN'
    
    # Check for INFO keywords
    for keyword in SEVERITY_KEYWORDS['INFO']:
        if keyword in message_lower:
            return 'INFO'
    
    # Default to INFO
    return 'INFO'


def parse_syslog(content: str) -> List[Dict[str, str]]:
    """
    Parse syslog file content into structured log entries.
    
    Args:
        content: Raw syslog file content
        
    Returns:
        List of parsed log dictionaries
    """
    parsed_logs = []
    lines = content.strip().split('\n')
    
    for line in lines:
        if not line.strip():
            continue
            
        match = SYSLOG_PATTERN.match(line)
        if match:
            daemon = match.group('daemon')
            # Extract process name without PID
            daemon_name = re.sub(r'\[\d+\]', '', daemon).strip()
            
            log_entry = {
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'daemon': daemon_name,
                'message': match.group('message'),
                'severity': infer_severity(match.group('message')),
                'raw_line': line
            }
            parsed_logs.append(log_entry)
    
    return parsed_logs


def handle_upload_command(parts: List[str]) -> str:
    """
    Handle UPLOAD command: receive and parse syslog file.
    
    Protocol: UPLOAD|<filesize>|<file_content>
    
    Args:
        parts: Split command parts
        
    Returns:
        Response message
    """
    if len(parts) < 3:
        return "ERROR: Invalid UPLOAD command format"
    
    try:
        filesize = int(parts[1])
        file_content = '|'.join(parts[2:])  # Rejoin in case message contains |
        
        if len(file_content) != filesize:
            return f"ERROR: File size mismatch. Expected {filesize}, got {len(file_content)}"
        
        # Parse the syslog content
        parsed_logs = parse_syslog(file_content)
        
        if not parsed_logs:
            return "ERROR: No valid syslog entries found in file"
        
        # Acquire lock and add to storage
        with STATE_LOCK:
            LOG_STORAGE.extend(parsed_logs)
            total_count = len(LOG_STORAGE)
        
        return f"SUCCESS: File received and {len(parsed_logs)} syslog entries parsed and indexed. Total entries: {total_count}"
    
    except ValueError as e:
        return f"ERROR: Invalid file size format: {e}"
    except Exception as e:
        return f"ERROR: Failed to process upload: {e}"


def handle_query_command(parts: List[str]) -> str:
    """
    Handle QUERY command: execute various search and count operations.
    
    Protocol: QUERY|<subcommand>|<filter_value>
    
    Args:
        parts: Split command parts
        
    Returns:
        Formatted query results
    """
    if len(parts) < 3:
        return "ERROR: Invalid QUERY command format"
    
    subcommand = parts[1]
    filter_value = '|'.join(parts[2:])  # Rejoin in case filter contains |
    
    try:
        with STATE_LOCK:
            logs_copy = LOG_STORAGE.copy()
    
        if subcommand == "SEARCH_DATE":
            results = [log for log in logs_copy if log['timestamp'].startswith(filter_value)]
            if not results:
                return f"Found 0 matching entries for date '{filter_value}'"
            
            response = f"Found {len(results)} matching entries for date '{filter_value}':\n"
            for i, log in enumerate(results, 1):
                response += f"{i}. {log['raw_line']}\n"
            return response.strip()
        
        elif subcommand == "SEARCH_HOST":
            results = [log for log in logs_copy if log['hostname'] == filter_value]
            if not results:
                return f"Found 0 matching entries for host '{filter_value}'"
            
            response = f"Found {len(results)} matching entries for host '{filter_value}':\n"
            for i, log in enumerate(results, 1):
                response += f"{i}. {log['raw_line']}\n"
            return response.strip()
        
        elif subcommand == "SEARCH_DAEMON":
            results = [log for log in logs_copy if log['daemon'] == filter_value]
            if not results:
                return f"Found 0 matching entries for daemon '{filter_value}'"
            
            response = f"Found {len(results)} matching entries for daemon '{filter_value}':\n"
            for i, log in enumerate(results, 1):
                response += f"{i}. {log['raw_line']}\n"
            return response.strip()
        
        elif subcommand == "SEARCH_SEVERITY":
            results = [log for log in logs_copy if log['severity'] == filter_value.upper()]
            if not results:
                return f"Found 0 matching entries for severity '{filter_value}'"
            
            response = f"Found {len(results)} matching entries for severity '{filter_value}':\n"
            for i, log in enumerate(results, 1):
                response += f"{i}. {log['raw_line']}\n"
            return response.strip()
        
        elif subcommand == "SEARCH_KEYWORD":
            results = [log for log in logs_copy if filter_value.lower() in log['message'].lower()]
            if not results:
                return f"Found 0 matching entries for keyword '{filter_value}'"
            
            response = f"Found {len(results)} matching entries for keyword '{filter_value}':\n"
            for i, log in enumerate(results, 1):
                response += f"{i}. {log['raw_line']}\n"
            return response.strip()
        
        elif subcommand == "COUNT_KEYWORD":
            count = sum(1 for log in logs_copy if filter_value.lower() in log['message'].lower())
            return f"The keyword '{filter_value}' appears in {count} indexed log entry/entries."
        
        else:
            return f"ERROR: Unknown query subcommand '{subcommand}'"
    
    except Exception as e:
        return f"ERROR: Query execution failed: {e}"


def handle_admin_command(parts: List[str]) -> str:
    """
    Handle ADMIN command: administrative operations like PURGE.
    
    Protocol: ADMIN|<operation>|<optional_param>
    
    Args:
        parts: Split command parts
        
    Returns:
        Response message
    """
    if len(parts) < 2:
        return "ERROR: Invalid ADMIN command format"
    
    operation = parts[1]
    
    if operation == "PURGE":
        try:
            with STATE_LOCK:
                removed_count = len(LOG_STORAGE)
                LOG_STORAGE.clear()
            return f"SUCCESS: {removed_count} indexed log entries have been erased."
        except Exception as e:
            return f"ERROR: Failed to purge logs: {e}"
    else:
        return f"ERROR: Unknown admin operation '{operation}'"


def handle_client(client_socket: socket.socket, client_address: tuple) -> None:
    """
    Handle individual client connection in a worker thread.
    
    Args:
        client_socket: Connected client socket
        client_address: Client address tuple (IP, port)
    """
    try:
        # Set a reasonable timeout for receiving data
        client_socket.settimeout(30)
        
        # Receive the request
        request_data = b""
        while True:
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
            except socket.timeout:
                break
        
        if not request_data:
            client_socket.close()
            return
        
        request = request_data.decode('utf-8', errors='replace')
        parts = request.split('|')
        
        if not parts:
            response = "ERROR: Empty request"
        else:
            command_type = parts[0].upper()
            
            if command_type == "UPLOAD":
                response = handle_upload_command(parts)
            elif command_type == "QUERY":
                response = handle_query_command(parts)
            elif command_type == "ADMIN":
                response = handle_admin_command(parts)
            else:
                response = f"ERROR: Unknown command type '{command_type}'"
        
        # Send response
        client_socket.sendall(response.encode('utf-8'))
    
    except Exception as e:
        try:
            error_msg = f"ERROR: Server error: {e}"
            client_socket.sendall(error_msg.encode('utf-8'))
        except:
            pass
    
    finally:
        try:
            client_socket.close()
        except:
            pass


def start_server(host: str = 'localhost', port: int = 65432) -> None:
    """
    Start the syslog server and listen for client connections.
    
    Args:
        host: Server host to bind to
        port: Server port to listen on
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[Server] Listening on {host}:{port}")
        print(f"[Server] Waiting for client connections...")
        
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                print(f"[Server] New client connected from {client_address[0]}:{client_address[1]}")
                
                # Spawn a worker thread for this client
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
            
            except KeyboardInterrupt:
                print("\n[Server] Shutting down...")
                break
            except Exception as e:
                print(f"[Server] Error accepting connection: {e}")
                continue
    
    except OSError as e:
        print(f"[Server] Failed to bind to {host}:{port}: {e}")
        sys.exit(1)
    finally:
        server_socket.close()
        print("[Server] Server stopped")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 65432
    
    if len(sys.argv) > 2:
        host = sys.argv[2]
    else:
        host = 'localhost'
    
    start_server(host, port)
