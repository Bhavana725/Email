import os
import re
import sys
from typing import List

class LoggingRiskResult:
    def __init__(self, line_no: int, line: str, flaw: str, remediation: str):
        self.line_no = line_no
        self.line = line.strip()
        self.flaw = flaw
        self.remediation = remediation

    def __str__(self):
        return f"Line {self.line_no}: {self.flaw} - {self.line}"

    def __repr__(self):
        return self.__str__()

class LoggingSecurityScanner:
    def __init__(self):
        """ Define risky logging patterns and recommended fixes """
        self.logging_risks = {
            r'\b(logging\.\w+)\(.*(password|secret|apikey|token|private_key)': 
                'Sensitive data logged',
            r'\bprint\s*\(\s*e\s*\)': 
                'Exposing exception details via print()',
            r'\blogging\.info\s*\(\s*["\']Exception.*["\']': 
                'Logging full exception message (potential information leakage)',
            r'["\'](/tmp/|/var/www/|/public/|/etc/|/root/)': 
                'Logging to insecure locations (may expose logs to attackers)',
            r'\blogging\.debug\s*\(': 
                'Debug logs enabled in production (may expose sensitive data)',
            r'\beval\s*\(\s*.*logging\.\w+.*\s*\)': 
                'Logging function uses eval() (can lead to RCE)',
            r'\blogging\.\w+\(.*\bSELECT\b.*\)': 
                'Logging raw SQL queries (may expose database structure)',
            r'\blogging\.\w+\(.*\b/sys/\b.*\)': 
                'Logging internal system paths (exposes infrastructure details)',
            r'\blogging\.\w+\(.*\b(?:123456|password|admin)\b.*\)': 
                'Hardcoded credentials logged (serious security risk)',
            r'\blogging\.\w+\(.*\b(jwt|session_token)\b.*\)': 
                'Logging authentication tokens (can expose user sessions)',
            r'\blogging\.\w+\(.*\b(\d{3}-?\d{2}-?\d{4})\b.*\)': 
                'Logging Social Security Numbers (SSNs) (privacy risk)',
            r'\blogging\.\w+\(.*\b(\d{16})\b.*\)': 
                'Logging credit card numbers (PCI compliance issue)',
            r'\blogging\.\w+\(.*\b(?:GET|POST|DELETE|PUT) /api/\b.*\)': 
                'Logging API requests with sensitive parameters',
        }

        self.remediations = {
            'Sensitive data logged': 'Do not log sensitive data. Use masking or omit logging.',
            'Exposing exception details via print()': 'Use print("Error occurred") instead of exposing raw exceptions.',
            'Logging full exception message (potential information leakage)': 'Log generic messages instead of full stack traces.',
            'Logging to insecure locations (may expose logs to attackers)': 'Store logs in secure directories with proper permissions.',
            'Debug logs enabled in production (may expose sensitive data)': 'Disable debug logs in production. Use environment-based logging levels.',
            'Logging function uses eval() (can lead to RCE)': 'Avoid eval(). Use safer alternatives like json.loads() or ast.literal_eval().',
            'Logging raw SQL queries (may expose database structure)': 'Sanitize and avoid logging raw SQL queries. Use parameterized queries.',
            'Logging internal system paths (exposes infrastructure details)': 'Avoid logging absolute system paths.',
            'Hardcoded credentials logged (serious security risk)': 'Remove hardcoded credentials from logs immediately.',
            'Logging authentication tokens (can expose user sessions)': 'Mask or hash JWT/session tokens before logging.',
            'Logging Social Security Numbers (SSNs) (privacy risk)': 'Anonymize or redact SSNs in logs.',
            'Logging credit card numbers (PCI compliance issue)': 'Use tokenization instead of logging credit card numbers.',
            'Logging API requests with sensitive parameters': 'Remove sensitive query parameters before logging API requests.',
        }

    def scan_file(self, file_path: str) -> List[LoggingRiskResult]:
        """ Scan a given file for potential logging security flaws """
        if not os.path.exists(file_path):
            print(f" Error: File not found -> {file_path}")
            return []

        results = []
        seen_flaws = set()

        print(f" Scanning file: {file_path}")

        try:
            with open(file_path, 'r', encoding="utf-8") as file:
                for line_no, line in enumerate(file, 1):
                    stripped_line = line.strip()

                    if stripped_line.startswith("#"):
                        continue

                    for pattern, flaw in self.logging_risks.items():
                        if re.search(pattern, stripped_line, re.IGNORECASE):
                            unique_key = f"{line_no}:{flaw}"
                            if unique_key not in seen_flaws:
                                seen_flaws.add(unique_key)
                                remediation = self.remediations.get(flaw, 'Follow best security practices.')
                                results.append(LoggingRiskResult(line_no, line, flaw, remediation))

                                # Print detected issues instead of logging to a file
                                print(f"\n Issue Found at Line {line_no}: {flaw}")
                                print(f"    Code: {line.strip()}")
                                print(f"    Remediation: {remediation}")

        except Exception as e:
            print(f" Error scanning file {file_path}: {str(e)}")
            return []

        return results

if __name__ == "__main__":
    scanner = LoggingSecurityScanner()
    file_path = sys.argv[1] if len(sys.argv) > 1 else "test_logging.py"

    try:
        results = scanner.scan_file(file_path)
        if results:
            print(f"\n Found {len(results)} potential logging security issues.\n")
        else:
            print(" No security issues detected.")
    except Exception as e:
        print(f"Fatal error occurred: {str(e)}")
