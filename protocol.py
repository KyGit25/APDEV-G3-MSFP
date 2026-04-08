"""
Protocol Reference Table (Simplified)
-------------------------------------

Client Command | Data Sent                     | Server Action / Expected Response
---------------------------------------------------------------------------------
INGEST          | UPLOAD|<filesize>|<content>   | Parses log lines and indexes entries.
SEARCH_DATE     | QUERY|SEARCH_DATE|<date>      | Returns logs by date.
SEARCH_HOST     | QUERY|SEARCH_HOST|<hostname>  | Returns logs by host.
SEARCH_DAEMON   | QUERY|SEARCH_DAEMON|<daemon>  | Returns logs by daemon.
SEARCH_SEVERITY | QUERY|SEARCH_SEVERITY|<level> | Returns logs by severity.
SEARCH_KEYWORD  | QUERY|SEARCH_KEYWORD|<word>   | Returns logs by message keyword.
COUNT_KEYWORD   | QUERY|COUNT_KEYWORD|<word>    | Returns count of keyword occurrences.
PURGE           | ADMIN|PURGE|NONE              | Clears log memory.

All server responses are plain UTF-8 text strings.
"""
