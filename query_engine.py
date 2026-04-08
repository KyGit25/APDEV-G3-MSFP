class QueryEngine:
    def __init__(self, storage):
        self.storage = storage

    def handle_query(self, subcommand, value):
        logs = self.storage.get_all()

        if subcommand == "SEARCH_DATE":
            res = [x for x in logs if x["timestamp"].startswith(value)]
            return self.format_results(res, f"date '{value}'")

        elif subcommand == "SEARCH_HOST":
            res = [x for x in logs if x["hostname"] == value]
            return self.format_results(res, f"host '{value}'")

        elif subcommand == "SEARCH_DAEMON":
            res = [x for x in logs if x["daemon"] == value]
            return self.format_results(res, f"daemon '{value}'")

        elif subcommand == "SEARCH_SEVERITY":
            res = [x for x in logs if x["severity"] == value.upper()]
            return self.format_results(res, f"severity '{value}'")

        elif subcommand == "SEARCH_KEYWORD":
            res = [x for x in logs if value.lower() in x["message"].lower()]
            return self.format_results(res, f"keyword '{value}'")

        elif subcommand == "COUNT_KEYWORD":
            count = sum(value.lower() in x["message"].lower() for x in logs)
            return f"The keyword '{value}' appears in {count} indexed log entries."

        else:
            return "ERROR: Unknown Query Command"

    def format_results(self, results, label):
        if not results:
            return f"No matching entries for {label}."
        s = [f"Found {len(results)} matching entries for {label}:"]
        for i, r in enumerate(results, 1):
            s.append(f"{i}. {r['timestamp']} {r['hostname']} {r['daemon']}: {r['message']}")
        return "\n".join(s)
