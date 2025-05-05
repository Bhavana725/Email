import re
from typing import List, Dict

class ResourceExhaustionScanner:
    def __init__(self):
        # Define patterns for resource exhaustion vulnerabilities
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

        # Define remediation messages for each vulnerability type
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
        """
        Analyze a Python file for resource exhaustion vulnerabilities.
        :param file_path: Path to the file to analyze
        :return: List of vulnerabilities found
        """
        vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

            for line_no, line in enumerate(lines, start=1):
                for vuln_type, pattern in self.vulnerable_patterns.items():
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            "type": vuln_type,
                            "line": line_no,
                            "content": line.strip(),
                            "remediation": self.remediation_tips[vuln_type]
                        })

            return vulnerabilities

        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return []
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return []

    def display_results(self, vulnerabilities: List[Dict]) -> None:
        """
        Display the results of the vulnerability scan.
        :param vulnerabilities: List of vulnerabilities found
        """
        if not vulnerabilities:
            print("No resource exhaustion vulnerabilities found.")
            return

        print("\n=== Resource Exhaustion Detection Results ===\n")
        for vuln in sorted(vulnerabilities, key=lambda x: x["line"]):
            print(f"Type: {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['content']}")
            print(f"Remediation: {vuln['remediation']}")
            print("-" * 50 + "\n")