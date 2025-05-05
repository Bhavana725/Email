import os
from typing import List

class VulnerabilityResult:
    def __init__(self, line_no: int, line: str, vulnerability: str, remediation: str):
        self.line_no = line_no
        self.line = line
        self.vulnerability = vulnerability
        self.remediation = remediation
    
    # Add __getitem__ method to make VulnerabilityResult subscriptable
    def __getitem__(self, key):
        if key == 'line_no':
            return self.line_no
        elif key == 'line':
            return self.line
        elif key == 'vulnerability':
            return self.vulnerability
        elif key == 'remediation':
            return self.remediation
        else:
            raise KeyError(f"'{key}' is not a valid attribute")
    
    # Add a string representation for better debugging
    def __str__(self):
        return f"Line {self.line_no}: {self.vulnerability} - {self.line}"
    
    def __repr__(self):
        return self.__str__()

class SubprocessVulnerabilityScanner:
    def __init__(self):
        # Patterns of dangerous subprocess calls
        self.dangerous_patterns = {
            'subprocess.call': 'Direct command execution',
            'subprocess.Popen': 'Direct process creation',
            'subprocess.run': 'Direct command execution',
            'subprocess.check_call': 'Direct command execution',
            'subprocess.check_output': 'Direct command output execution',
            'os.system': 'Direct system command execution',
            'os.popen': 'Direct pipe creation',
            'os.spawn': 'Direct process spawning',
            'commands.getoutput': 'Legacy command execution',
            'commands.getstatusoutput': 'Legacy command execution with status',
            'popen2.Popen3': 'Legacy process creation',
            'popen2.Popen4': 'Legacy process creation',
            'shell=True': 'Shell injection risk'
        }

        # Remediation messages for different vulnerability types
        self.remediations = {
            'Direct command execution': 'Use subprocess.run() with shell=False and pass commands as list of arguments',
            'Direct process creation': 'Use subprocess.run() with shell=False and proper argument list',
            'Direct system command execution': 'Replace with subprocess.run() using proper argument list',
            'Direct pipe creation': 'Use subprocess.run() with capture_output=True',
            'Direct process spawning': 'Use subprocess.run() with appropriate security controls',
            'Legacy command execution': 'Update to subprocess.run() with proper security controls',
            'Legacy command execution with status': 'Update to subprocess.run() with proper security controls',
            'Legacy process creation': 'Update to modern subprocess.run() with security controls',
            'Shell injection risk': 'Remove shell=True and use proper argument list'
        }

    def scan_file(self, file_path: str) -> List[VulnerabilityResult]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        results = []
        seen_vulnerabilities = set()

        with open(file_path, 'r') as file:
            for line_no, line in enumerate(file, 1):
                for pattern, vulnerability in self.dangerous_patterns.items():
                    if pattern in line:
                        unique_key = f"{line_no}:{vulnerability}"
                        if unique_key not in seen_vulnerabilities:
                            seen_vulnerabilities.add(unique_key)
                            results.append(VulnerabilityResult(
                                line_no=line_no,
                                line=line.strip(),
                                vulnerability=vulnerability,
                                remediation=self.remediations.get(vulnerability, 'Apply proper security controls')
                            ))
        return results
    
    def analyze_file(self, file_path: str) -> List[VulnerabilityResult]:
        try:
            return self.scan_file(file_path)  # Ensure this is a list
        except Exception as e:
            print(f"Error analyzing file: {str(e)}")
            return []  # Return an empty list on error

# Example usage
if __name__ == "__main__":
    scanner = SubprocessVulnerabilityScanner()
    
    # Get the file path from command-line arguments or use a default
    import sys
    file_path = sys.argv[1] if len(sys.argv) > 1 else "test_file.py"
    
    try:
        results = scanner.analyze_file(file_path)
        if results:
            print(f"Found {len(results)} potential vulnerabilities:")
            for i, result in enumerate(results, 1):
                print(f"{i}. Line {result.line_no}: {result.vulnerability}")
                print(f"   Code: {result.line}")
                print(f"   Remediation: {result.remediation}")
                print()
        else:
            print("No subprocess vulnerabilities found.")
    except Exception as e:
        print(f"Error: {str(e)}")