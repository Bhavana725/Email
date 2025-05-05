import re
from typing import List, Dict

class InsecureDefaultsScanner:
    def __init__(self):
        self.vulnerable_patterns = {
            'infinite_loop': r'while\s+True:|for\s+.*\s+in\s+range\(.*\):',
            'recursive_calls': r'def\s+(\w+)\(.*\).*:.*\1\(.*\)',
            'large_memory_allocation': r'(list|dict|set|array)\(.*\*.*\)',
            'unbounded_growth': r'append|extend|add|update|insert',
            'thread_creation': r'Thread\(|Process\(',
            'file_operations': r'open\(|read\(|write\(',
            'network_connections': r'socket\(|connect\(|listen\(',
            'database_queries': r'execute\(|query\(|find\(',
            'regex_operations': r'match\(|search\(|findall\(',
            'cpu_intensive': r'sort\(|sorted\(|map\(|filter\('
        }

        self.remediation_tips = {
            'infinite_loop': "Add break condition, implement timeout",
            'recursive_calls': "Add depth limit, use iteration instead",
            'large_memory_allocation': "Implement chunking, use generators",
            'unbounded_growth': "Set max size limit, clear unused data",
            'thread_creation': "Use thread pool, limit max threads",
            'file_operations': "Close files, use context managers",
            'network_connections': "Implement timeouts, connection pooling",
            'database_queries': "Use LIMIT, pagination, connection pooling",
            'regex_operations': "Limit input size, use proper patterns",
            'cpu_intensive': "Use batch processing, implement throttling"
        }

    def analyze_file(self, file_path: str) -> List[Dict]:
        found_vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

            for line_no, line in enumerate(lines, start=1):
                for vuln_type, pattern in self.vulnerable_patterns.items():
                    if re.search(pattern, line):
                        found_vulnerabilities.append({
                            "type": vuln_type,
                            "line": line_no,
                            "content": line.strip(),
                            "remediation": self.remediation_tips[vuln_type]
                        })

            return found_vulnerabilities

        except Exception as e:
            print(f"Error while running InsecureDefaultsScanner: {e}")
            return []  # Return an empty list on error

    def display_results(self, vulnerabilities: List[Dict]) -> None:
        if not vulnerabilities:
            print("No resource exhaustion vulnerabilities found.")
            return

        print("\n=== Resource Exhaustion Detection Results ===\n")
        for vuln in sorted(vulnerabilities, key=lambda x: x["line"]):
            print(f"Type: {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['content']}")
            print(f"Remediation: {vuln['remediation']}")
            print("-" * 50 + "\n")