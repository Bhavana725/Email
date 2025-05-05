import os
import re
import sys
from typing import List

class FilePathRiskResult:
    def __init__(self, line_no: int, line: str, flaw: str, remediation: str):
        self.line_no = line_no
        self.line = line.strip()
        self.flaw = flaw
        self.remediation = remediation

    def __str__(self):
        return f"Line {self.line_no}: {self.flaw} - {self.line}"

    def __repr__(self):
        return self.__str__()

class FilePathSecurityScanner:
    def __init__(self):
        """ Define risky patterns and remediations """
        self.file_path_risks = {
            #  Path Traversal & Directory Traversal
            r'(\.\./|\.\.\\\\)': 'Possible path traversal vulnerability',
            r'\bos\.path\.join\s*\(': 'Potential directory traversal vulnerability (sanitize user input)',

            #  Insecure File Handling
            r'\bopen\s*\(': 'File opened without validation (could lead to unauthorized access)',
            r'\bos\.remove\s*\(': 'Unvalidated file deletion (may allow arbitrary file deletion)',
            r'\bshutil\.rmtree\s*\(': 'Unvalidated directory deletion (potential security risk)',

            #  Insecure File Uploads
            r'\brequest\.files\b': 'Directly handling uploaded files without validation (RCE risk)',
            r'\bfile\.save\s*\(': 'Saving uploaded files without sanitization (could overwrite critical files)',

            #  File Permission Risks
            r'\bos\.chmod\s*\(': 'Changing file permissions without validation (could create security holes)',
            r'\bstat\.S_IWOTH\b': 'Making a file world-writable (high security risk)',

            #  Hardcoded File Paths & Insecure Temp Files
            r'["\'](/tmp/|C:\\\\|/var/|/home/|/etc/|/root/)': 'Hardcoded file path detected (use os.path.join())',

            #  Insecure File Execution
            r'\bsubprocess\.Popen\s*\(': 'Executing files without input validation (command injection risk)',
            r'\bexec\s*\(': 'Use of exec() can lead to arbitrary code execution',

            #  Insecure Downloads
            r'\brequests\.get\s*\(': 'Downloading files without validation (could lead to malicious execution)',
            r'\burllib\.request\.urlretrieve\s*\(': 'Unvalidated file download (could download malicious content)',

            #  Resource Exhaustion (Large File Processing)
            r'\bf\.read\s*\(': 'Reading large files without chunking (can cause memory exhaustion)',
            r'\bf\.write\s*\(': 'Writing large files without checking available space (disk exhaustion risk)',

            # Symbolic Link (Symlink) Attacks
            r'\bos\.symlink\s*\(': 'Creating symbolic links without validation (can be abused for privilege escalation)',
            r'\bos\.readlink\s*\(': 'Following symbolic links without validation (can lead to unintended access)',
        }

        # Recommended Remediations
        self.remediations = {
            'Possible path traversal vulnerability': 'Use `os.path.abspath()` and validate input to prevent traversal.',
            'Potential directory traversal vulnerability (sanitize user input)': 'Sanitize user input and restrict path usage.',

            'File opened without validation (could lead to unauthorized access)': 'Use `with open()` to ensure proper closure.',
            'Unvalidated file deletion (may allow arbitrary file deletion)': 'Ensure file deletion is restricted to authorized locations.',
            'Unvalidated directory deletion (potential security risk)': 'Restrict directory deletions to prevent accidental or malicious removals.',

            'Directly handling uploaded files without validation (RCE risk)': 'Use `secure_filename()` from werkzeug.utils.',
            'Saving uploaded files without sanitization (could overwrite critical files)': 'Store uploaded files in a secure location.',

            'Changing file permissions without validation (could create security holes)': 'Avoid world-writable permissions.',
            'Making a file world-writable (high security risk)': 'Use secure permissions like `0o600` for sensitive files.',

            'Hardcoded file path detected (use os.path.join())': 'Use environment variables or `os.path.join()` instead.',

            'Executing files without input validation (command injection risk)': 'Use `shlex.quote()` to sanitize inputs.',
            'Use of exec() can lead to arbitrary code execution': 'Avoid `exec()`, use safer alternatives like `json.loads()`.',

            'Downloading files without validation (could lead to malicious execution)': 'Validate downloaded files before execution.',
            'Unvalidated file download (could download malicious content)': 'Only allow downloads from trusted sources.',

            'Reading large files without chunking (can cause memory exhaustion)': 'Use `for line in file` instead of `f.read()`.',
            'Writing large files without checking available space (disk exhaustion risk)': 'Ensure sufficient disk space before writing.',

            'Creating symbolic links without validation (can be abused for privilege escalation)': 'Restrict symlink creation.',
            'Following symbolic links without validation (can lead to unintended access)': 'Validate symlink targets before accessing.',
        }

    def scan_file(self, file_path: str) -> List[FilePathRiskResult]:
        """ Scan a given file for potential security flaws """
        if not os.path.exists(file_path):
            print(f" Error: File not found -> {file_path}")
            return []

        results = []
        seen_flaws = set()

        print(f"🔍 Scanning: {file_path}")

        try:
            with open(file_path, 'r', encoding="utf-8") as file:
                for line_no, line in enumerate(file, 1):
                    stripped_line = line.strip()

                    # ✅ Skip commented lines (Python `#` comments)
                    if stripped_line.startswith("#"):
                        continue

                    for pattern, flaw in self.file_path_risks.items():
                        if re.search(pattern, stripped_line):
                            unique_key = f"{line_no}:{flaw}"
                            if unique_key not in seen_flaws:
                                seen_flaws.add(unique_key)
                                remediation = self.remediations.get(flaw, 'Follow best practices for security.')
                                results.append(FilePathRiskResult(line_no, line, flaw, remediation))
        except Exception as e:
            print(f" Error scanning file: {e}")
            return []

        return results

    def analyze_file(self, file_path: str) -> List[FilePathRiskResult]:
        """ Wrapper function to analyze a file and handle errors gracefully """
        try:
            return self.scan_file(file_path)
        except Exception as e:
            print(f" Error analyzing file: {str(e)}")
            return []

if __name__ == "__main__":
    scanner = FilePathSecurityScanner()
    file_path = sys.argv[1] if len(sys.argv) > 1 else "test_file_risks.py"

    try:
        results = scanner.analyze_file(file_path)
        if results:
            print(f"\nFound {len(results)} potential file/path security issues:\n")
            for i, result in enumerate(results, 1):
                print(f"{i}. Line {result.line_no}: {result.flaw}")
                print(f" Code: {result.line}")
                print(f" Remediation: {result.remediation}\n")
        else:
            print("✅ No security issues detected.")
    except Exception as e:
        print(f" Error: {str(e)}")
