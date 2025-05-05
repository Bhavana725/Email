import os
import re
from typing import List, Dict
from dataclasses import dataclass

@dataclass
class VulnerabilityInfo:
    line_no: int
    vulnerability: str
    code: str
    pattern_type: str  # Added to track the type of pattern

class TOCTOUDetector:
    def __init__(self):
        # Define patterns for TOCTOU vulnerability detection
        self.toctou_patterns = {
            'file_operations': [
                (r'os\.path\.exists\s*\(', r'open\s*\('),
                (r'os\.access\s*\(', r'open\s*\('),
                (r'os\.stat\s*\(', r'open\s*\('),
                (r'os\.path\.isfile\s*\(', r'open\s*\('),
                (r'os\.path\.isdir\s*\(', r'os\.mkdir\s*\('),
                (r'os\.path\.islink\s*\(', r'os\.unlink\s*\(')
            ],
            'dangerous_functions': [
                r'os\.remove\s*\(',
                r'os\.unlink\s*\(',
                r'os\.rmdir\s*\(',
                r'os\.rename\s*\(',
                r'os\.chmod\s*\(',
                r'os\.chown\s*\('
            ]
        }
        
        # Define specific remediation for each pattern
        self.pattern_remediation = {
            # File operations patterns
            (r'os\.path\.exists\s*\(', r'open\s*\('): """
                - Use atomic operations with os.O_CREAT | os.O_EXCL flags
                - Implement file locking with fcntl.flock()
                - Use try-except blocks to handle race conditions
            """,
            (r'os\.access\s*\(', r'open\s*\('): """
                - Replace with direct try-except pattern on the open operation
                - Use proper permission checks during file opening
                - Consider using temporary files with random names
            """,
            (r'os\.stat\s*\(', r'open\s*\('): """
                - Combine operations and use proper error handling
                - Use file locking mechanisms where appropriate
                - Consider using context managers for file operations
            """,
            (r'os\.path\.isfile\s*\(', r'open\s*\('): """
                - Use direct try-except with appropriate error handling
                - Consider using with open() context manager
                - Implement proper logging for failures
            """,
            (r'os\.path\.isdir\s*\(', r'os\.mkdir\s*\('): """
                - Use os.makedirs() with exist_ok=True for atomic operations
                - Implement proper error handling for all possible cases
                - Use temporary directory approaches where appropriate
            """,
            (r'os\.path\.islink\s*\(', r'os\.unlink\s*\('): """
                - Use direct try-except pattern on the unlink operation
                - Consider safer alternatives to direct link manipulation
                - Implement proper permission verification
            """,
            
            # Dangerous functions
            r'os\.remove\s*\(': """
                - Wrap in try-except blocks with specific error handling
                - Verify permissions before attempting removal
                - Consider safer alternatives like moving to backup location
            """,
            r'os\.unlink\s*\(': """
                - Implement appropriate error handling
                - Verify file existence and permissions atomically
                - Consider using safer wrappers or libraries
            """,
            r'os\.rmdir\s*\(': """
                - Check for empty directory with appropriate error handling
                - Consider using shutil.rmtree() with error handlers
                - Implement proper logging and recovery
            """,
            r'os\.rename\s*\(': """
                - Use atomic operations where possible
                - Implement rollback mechanisms for failures
                - Verify target doesn't exist before renaming
            """,
            r'os\.chmod\s*\(': """
                - Verify file ownership before changing permissions
                - Use appropriate permission masks
                - Implement proper privilege dropping
            """,
            r'os\.chown\s*\(': """
                - Verify current process has appropriate privileges
                - Implement proper permission validation
                - Use principle of least privilege
            """
        }

    def analyze_file(self, file_path: str) -> List[VulnerabilityInfo]:
        """Analyze a Python file for TOCTOU vulnerabilities."""
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return []

        vulnerabilities = []
        checked_paths = set()

        with open(file_path, 'r') as file:
            lines = file.readlines()

        for line_no, line in enumerate(lines, start=1):
            # Check for dangerous function calls
            for pattern in self.toctou_patterns['dangerous_functions']:
                if re.search(pattern, line):
                    vulnerabilities.append(
                        VulnerabilityInfo(
                            line_no=line_no,
                            vulnerability=f"Potentially dangerous function: {pattern}",
                            code=line.strip(),
                            pattern_type=pattern  # Store the specific function as pattern
                        )
                    )

            # Check for TOCTOU patterns in file operations
            for check_func, use_func in self.toctou_patterns['file_operations']:
                if re.search(check_func, line):
                    # Extract the path argument (simplified for this example)
                    path_match = re.search(r'\(([^)]+)\)', line)
                    if path_match:
                        checked_paths.add(path_match.group(1).strip())
                elif re.search(use_func, line):
                    path_match = re.search(r'\(([^)]+)\)', line)
                    if path_match and path_match.group(1).strip() in checked_paths:
                        vulnerabilities.append(
                            VulnerabilityInfo(
                                line_no=line_no,
                                vulnerability=f"TOCTOU vulnerability: {check_func} followed by {use_func}",
                                code=line.strip(),
                                pattern_type=(check_func, use_func)  # Store the pattern tuple
                            )
                        )

        return vulnerabilities

    def display_results(self, vulnerabilities: List[VulnerabilityInfo]):
        """Display detected vulnerabilities and remediation advice."""
        if not vulnerabilities:
            print("No TOCTOU vulnerabilities detected.")
            return

        print("\n=== TOCTOU Vulnerability Report ===")

        # Group vulnerabilities by line number
        vulnerabilities_by_line = {}
        for vuln in vulnerabilities:
            if vuln.line_no not in vulnerabilities_by_line:
                vulnerabilities_by_line[vuln.line_no] = []
            vulnerabilities_by_line[vuln.line_no].append(vuln)
        
        # Track which patterns we've seen to show remediation only once per pattern
        seen_patterns = set()
        
        # Display vulnerabilities grouped by line
        for line_no, vulns in sorted(vulnerabilities_by_line.items()):
            print(f"\nLine {line_no}:")
            
            # Display all vulnerabilities for this line
            for vuln in vulns:
                print(f"- {vuln.vulnerability}")
                # Add pattern to seen patterns
                seen_patterns.add(vuln.pattern_type)
            
            # Display the code only once per line
            print(f"Vulnerable code: {vulns[0].code}")
        
        # Display specific remediation advice for each pattern found
        print("\n=== Pattern-Specific Remediation Advice ===")
        
        # Get unique patterns with their remediation
        for vuln in vulnerabilities:
            pattern = vuln.pattern_type
            if pattern in seen_patterns:
                # Find the remediation for this pattern
                remediation = self.pattern_remediation.get(pattern, "No specific remediation available.")
                # Print pattern-specific remediation and remove from seen patterns
                print(f"\nRemediation for {pattern}:")
                print(remediation)
                seen_patterns.remove(pattern)