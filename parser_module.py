import re

# Example RFC3164 line:
# "Feb 22 00:05:38 SYSSVR1 sshd[4421]: Failed password for invalid user admin"

SYSLOG_REGEX = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<daemon>[a-zA-Z0-9_\-\/]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)

def infer_severity(message):
    msg_upper = message.upper()
    if "ERROR" in msg_upper:
        return "ERROR"
    elif "WARN" in msg_upper:
        return "WARN"
    elif "INFO" in msg_upper:
        return "INFO"
    else:
        return "DEBUG"

def parse_syslog_lines(lines):
    parsed = []
    for line in lines:
        m = SYSLOG_REGEX.match(line.strip())
        if not m:
            continue
        d = m.groupdict()
        entry = {
            "timestamp": d["timestamp"],
            "hostname": d["hostname"],
            "daemon": d["daemon"],
            "severity": infer_severity(d["message"]),
            "message": d["message"],
        }
        parsed.append(entry)
    return parsed
