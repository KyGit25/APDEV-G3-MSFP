# Mini-Splunk Syslog Analytics Server - Implementation Guide

## Overview

This project implements a lightweight, centralized log management and analytics system consisting of:
- **Server (server.py)**: Multithreaded TCP server that ingests, parses, and queries syslog files
- **Client (client.py)**: Interactive CLI client for uploading files and executing analytical queries

## Architecture

### Threading Model

The server implements a **thread-per-connection** architecture:
- Main listener thread runs in a loop accepting new client connections
- Each accepted connection spawns a dedicated worker thread via `threading.Thread()`
- Worker threads are daemon threads, allowing graceful shutdown
- This enables truly concurrent handling of multiple clients without blocking

### Concurrency & Locking

All access to shared data (LOG_STORAGE) is protected by a **threading.RLock()**:
```python
LOG_STORAGE: List[Dict[str, str]] = []
STATE_LOCK = threading.RLock()

# Usage in critical sections:
with STATE_LOCK:
    LOG_STORAGE.extend(parsed_logs)
    total_count = len(LOG_STORAGE)
```

The RLock allows recursive locking (future-proofing) and ensures:
- No race conditions during concurrent INGEST operations
- Safe reads during QUERY operations
- Exclusive writes during PURGE operations

### Syslog Parsing

RFC 3164-compliant regex pattern:
```python
SYSLOG_PATTERN = re.compile(
    r'^'
    r'(?P<timestamp>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<daemon>[a-zA-Z0-9_\-\.\/]+(?:\[\d+\])?)'
    r':\s*'
    r'(?P<message>.*)$'
)
```

Parses syslog lines into components:
- **timestamp**: "Mar 12 05:26:34"
- **hostname**: "WEB-SRV-01"
- **daemon**: "apache2"
- **message**: "failed to open stream: No such file or directory"
- **severity**: Inferred from message content

### Communication Protocol

Client-Server protocol uses pipe-delimited format:

| Command | Format | Direction |
|---------|--------|-----------|
| INGEST | `UPLOAD\|<filesize>\|<file_content>` | Client → Server |
| SEARCH_* | `QUERY\|<subcommand>\|<filter_value>` | Client → Server |
| COUNT_KEYWORD | `QUERY\|COUNT_KEYWORD\|<keyword>` | Client → Server |
| PURGE | `ADMIN\|PURGE\|NONE` | Client → Server |

## Server Implementation

### Key Components

#### 1. Parse Module
- `parse_syslog()`: Parses raw syslog content using regex
- `infer_severity()`: Determines severity (ERROR/WARN/INFO) from message keywords
- Returns list of structured log dictionaries

#### 2. Storage Module
- Global `LOG_STORAGE` list protected by `STATE_LOCK`
- Thread-safe add, retrieve, and clear operations
- In-memory storage for fast queries

#### 3. Query Engine
- `handle_query_command()`: Routes to appropriate filter function
- Filters implemented using Python list comprehensions for performance:
  - `SEARCH_DATE`: Prefix match on timestamp
  - `SEARCH_HOST`: Exact match on hostname
  - `SEARCH_DAEMON`: Exact match on daemon name
  - `SEARCH_SEVERITY`: Match on inferred severity level
  - `SEARCH_KEYWORD`: Substring search in message (case-insensitive)
  - `COUNT_KEYWORD`: Count occurrences

#### 4. Network Module
- `handle_client()`: Worker thread function for each client
- Receives chunked data with 4KB buffer size
- Sends response back to client
- Robust cleanup in finally block

#### 5. Main Server Loop
- `start_server()`: Binds socket, listens for connections
- Graceful shutdown on Ctrl+C
- SO_REUSEADDR socket option for quick restart

### Error Handling

The server handles:
- Invalid file size format
- Malformed protocol messages
- Missing command parameters
- Socket timeouts and disconnections
- Abrupt client disconnects (cleaned up in finally blocks)

## Client Implementation

### Features

#### 1. Interactive CLI
- Command loop with prompt-based input
- Support for multi-word parameters with proper argument joining
- Help command with usage examples

#### 2. INGEST Command
- Validates file exists and is readable
- Reads entire file (with error handling for encoding)
- Connects to server with address validation
- Sends file in one protocol message
- Displays human-readable file size (MB)
- Shows success/error response from server

#### 3. QUERY Command
- Flexible argument parsing for multi-word filters
- 6 search types supported: SEARCH_DATE, SEARCH_HOST, SEARCH_DAEMON, SEARCH_SEVERITY, SEARCH_KEYWORD, COUNT_KEYWORD
- Validates search type before sending
- Formats and displays results from server

#### 4. PURGE Command
- Requires destination address
- Confirms deletion with returned count
- Uses ADMIN command type

#### 5. Error Handling
- Connection timeout handling
- DNS resolution errors
- Port validation (1-65535)
- File access errors
- Invalid address format detection
- Graceful fallback to help on command errors

## Usage Instructions

### Starting the Server

```bash
# Start on default port 65432
python server.py

# Start on custom port
python server.py 8080

# Start on custom host and port
python server.py 8080 192.168.1.100
```

Output:
```
[Server] Listening on localhost:65432
[Server] Waiting for client connections...
```

### Starting the Client

```bash
python client.py
```

Interactive CLI session:
```
=== Mini-Splunk Syslog Analytics Client ===
Type 'HELP' for available commands or 'EXIT' to quit

client> HELP
```

### Example Usage

#### 1. Upload a Syslog File

```
client> INGEST /path/to/syslog.txt localhost:65432
[System Message] Reading local file...
[System Message] Connecting to localhost:65432...
[System Message] Uploading syslog (0.5 MB)...
[Server Response] SUCCESS: File received and 245 syslog entries parsed and indexed. Total entries: 245
```

#### 2. Search by Date

```
client> QUERY localhost:65432 SEARCH_DATE "Feb 22"
[System Message] Sending query...
[Server Response] Found 3 matching entries for date 'Feb 22':
1. Feb 22 00:05:38 SYSSVR1 systemd[1]: Started OpenBSD Secure Shell server
2. Feb 22 00:05:54 SYSSVR1 systemd[1]: Started OpenBSD Secure Shell server
3. Feb 22 00:05:57 SYSSVR1 systemd[1]: ssh@125339 Deactivated successfully
```

#### 3. Search by Host

```
client> QUERY localhost:65432 SEARCH_HOST SYSSVR1
[System Message] Sending query...
[Server Response] Found 2 matching entries for host 'SYSSVR1':
1. Feb 22 00:05:38 SYSSVR1 systemd[1]: Started OpenBSD Secure Shell server
2. Feb 22 00:05:57 SYSSVR1 systemd[1]: ssh@125339 Deactivated successfully
```

#### 4. Search by Daemon

```
client> QUERY localhost:65432 SEARCH_DAEMON sshd
[System Message] Sending query...
[Server Response] Found 1 matching entry for daemon 'sshd':
1. Feb 22 01:14:22 SYSSVR1 sshd[4421]: Failed password for invalid user admin
```

#### 5. Search by Severity

```
client> QUERY localhost:65432 SEARCH_SEVERITY ERROR
[System Message] Sending query...
[Server Response] Found 1 matching entry for severity 'ERROR':
1. Feb 22 02:10:05 SYSSVR1 kernel: [ 1234.567890] ERROR: Disk quota exceeded
```

#### 6. Search by Keyword

```
client> QUERY localhost:65432 SEARCH_KEYWORD "Failed password"
[System Message] Sending query...
[Server Response] Found 1 matching entry for keyword 'Failed password':
1. Feb 22 01:14:22 SYSSVR1 sshd[4421]: Failed password for invalid user admin from 10.0.0.9
```

#### 7. Count Keyword Occurrences

```
client> QUERY localhost:65432 COUNT_KEYWORD Deactivated
[System Message] Sending query...
[Server Response] The keyword 'Deactivated' appears in 5 indexed log entry/entries.
```

#### 8. Purge All Logs

```
client> PURGE localhost:65432
[System Message] Connecting to localhost:65432 to purge records...
[Server Response] SUCCESS: 245 indexed log entries have been erased.
```

## Testing with Concurrent Clients

To test concurrent operations, run multiple client instances in different terminals:

**Terminal 1 (Server):**
```bash
python server.py
```

**Terminal 2 (Client 1):**
```bash
python client.py
client> INGEST test_logs1.txt localhost:65432
client> QUERY localhost:65432 SEARCH_HOST server1
```

**Terminal 3 (Client 2):**
```bash
python client.py
client> INGEST test_logs2.txt localhost:65432
client> QUERY localhost:65432 SEARCH_SEVERITY ERROR
```
