import re
from typing import List

class VulnerabilityResult:
    def __init__(self, line_no: int, line: str, vulnerability: str, remediation: str):
        self.line_no = line_no
        self.line = line
        self.vulnerability = vulnerability
        self.remediation = remediation

class ImproperErrorHandlingScanner:
    def __init__(self):
        self.vulnerable_patterns = {
            'bare_except': {
                'description': 'Using bare except clause',
                'remediation': '''
- Specify the exact exception type(s) to catch
- Avoid using bare except clauses
- Handle specific exceptions separately
- Consider logging exceptions
- Don't silently pass exceptions'''
            },
            'pass_in_except': {
                'description': 'Using pass in except block',
                'remediation': '''
- Don't silently ignore exceptions
- Log or handle the exception properly
- Consider re-raising the exception
- Add error handling logic
- Document why exception is ignored if necessary'''
            },
            'print_only': {
                'description': 'Only printing exception message',
                'remediation': '''
- Add proper exception handling logic
- Log exceptions with stack trace
- Consider error recovery steps
- Implement fallback behavior
- Add cleanup code if needed'''
            },
            'broad_except': {
                'description': 'Catching too broad exception types',
                'remediation': '''
- Catch specific exception types
- Handle different exceptions separately
- Add exception type hierarchy
- Consider exception chaining
- Document exception handling strategy'''
            }
        }

    def analyze_file(self, file_path: str) -> List[VulnerabilityResult]:
        vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                lines = content.splitlines()

                for line_no, line in enumerate(lines, start=1):
                    # Check for bare except
                    if re.match(r'^\s*except\s*:', line):
                        vulnerabilities.append(VulnerabilityResult(
                            line_no=line_no,
                            line=line.strip(),
                            vulnerability='bare_except',
                            remediation=self.vulnerable_patterns['bare_except']['remediation']
                        ))

                    # Check for pass in except
                    if re.match(r'^\s*except\s+.*:', line):
                        next_line_no = line_no + 1
                        if next_line_no <= len(lines):
                            next_line = lines[next_line_no - 1]
                            if re.match(r'^\s*pass\s*$', next_line):
                                vulnerabilities.append(VulnerabilityResult(
                                    line_no=next_line_no,
                                    line=next_line.strip(),
                                    vulnerability='pass_in_except',
                                    remediation=self.vulnerable_patterns['pass_in_except']['remediation']
                                ))

                    # Check for print-only except blocks
                    if re.match(r'^\s*except\s+.*:', line):
                        next_line_no = line_no + 1
                        if next_line_no <= len(lines):
                            next_line = lines[next_line_no - 1]
                            if re.match(r'^\s*print\s*\(.*\)\s*$', next_line):
                                vulnerabilities.append(VulnerabilityResult(
                                    line_no=next_line_no,
                                    line=next_line.strip(),
                                    vulnerability='print_only',
                                    remediation=self.vulnerable_patterns['print_only']['remediation']
                                ))

                    # Check for broad exception types
                    if re.match(r'^\s*except\s+(Exception|BaseException)\s*:', line):
                        vulnerabilities.append(VulnerabilityResult(
                            line_no=line_no,
                            line=line.strip(),
                            vulnerability='broad_except',
                            remediation=self.vulnerable_patterns['broad_except']['remediation']
                        ))

        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
        return vulnerabilities

    def display_results(self, vulnerabilities: List[VulnerabilityResult]) -> None:
        if not vulnerabilities:
            print("No improper error handling issues found.")
            return

        print("\n=== Improper Error Handling Detection Results ===\n")

        for result in vulnerabilities:
            print(f"Issue: {self.vulnerable_patterns[result.vulnerability]['description']}")
            print(f"Line {result.line_no}: {result.line}")
            print("\nRemediation:")
            print(result.remediation)
            print("-" * 60 + "\n")