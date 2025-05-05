import re
from typing import List, Dict

class InputValidationScanner:
    def __init__(self):
        # Define dangerous patterns for input validation vulnerabilities
        self.dangerous_patterns = {
            'direct_input': r'(?i)(input|raw_input|sys\.stdin\.read|input\(|getpass\.|readline\()',
            'eval_exec': r'(eval|exec)\(.*\)',
            'shell_commands': r'(os\.system|subprocess\.run|subprocess\.call|subprocess\.Popen)',
            'sql_queries': r'execute\(.*\)|cursor\.execute\(.*\)',
            'file_operations': r'open\(.*\)|file\(.*\)',
            'pickle_loads': r'pickle\.loads\(.*\)|pickle\.load\(.*\)',
            'yaml_load': r'yaml\.load\(.*\)',
            'request_params': r'request\.(args|form|values|get|post)',
            'template_strings': r'f\".*{.*}.*\"|Template\(.*\)',
            'json_loads': r'json\.loads\(.*\)',
            'xml_parse': r'(xml\.etree|xmlrpc|minidom).*parse\(.*\)',
            'marshal_loads': r'marshal\.loads\(.*\)',
            'shelve_open': r'shelve\.open\(.*\)',
            'unvalidated_redirect': r'redirect\(.*\)',
            'command_injection': r'(commands|popen2|popen3|popen4)\..*\(.*\)',
            'crypto_weak': r'(md5|sha1)\..*\(.*\)',
            'temp_file': r'mktemp\(.*\)',
            'random_weak': r'random\..*\(.*\)',
            'deserialization': r'(pickle|yaml|marshal)\.load',
        }

    def analyze_file(self, file_path: str) -> List[Dict]:
        """
        Analyze a file for input validation vulnerabilities.
        :param file_path: Path to the file to analyze
        :return: List of vulnerabilities found
        """
        vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

            for line_no, line in enumerate(lines, start=1):
                for vuln_type, pattern in self.dangerous_patterns.items():
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'line': line_no,
                            'content': line.strip()
                        })

            return vulnerabilities

        except FileNotFoundError:
            print(f"Error: File not found - {file_path}")
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
            print("No input validation vulnerabilities found.")
            return

        print("\n=== Input Validation Vulnerability Detection Results ===\n")
        for vuln in sorted(vulnerabilities, key=lambda x: x["line"]):
            print(f"Type: {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['content']}")
            print("Remediation:")
            self._print_remediation(vuln['type'])
            print("-" * 50 + "\n")

    def _print_remediation(self, vuln_type: str) -> None:
        """
        Print remediation tips for a specific vulnerability type.
        :param vuln_type: Type of vulnerability
        """
        remediation_tips = {
            'direct_input': """
- Validate and sanitize all user input
- Use input type checking
- Implement input length limits
- Consider using input validation libraries""",

            'eval_exec': """
- Avoid using eval() and exec()
- Use safer alternatives like ast.literal_eval()
- Implement strict input validation
- Consider using a configuration file instead""",

            'shell_commands': """
- Use subprocess.run with shell=False
- Validate and sanitize command arguments
- Use command argument lists instead of strings
- Implement proper error handling""",

            'sql_queries': """
- Use parameterized queries
- Implement proper SQL escaping
- Use an ORM when possible
- Validate input before using in queries""",

            'file_operations': """
- Validate file paths
- Use os.path.abspath() to resolve paths
- Implement proper permission checks
- Sanitize file names""",

            'pickle_loads': """
- Avoid using pickle with untrusted data
- Use safer serialization formats (JSON, XML)
- Implement proper input validation
- Consider using digital signatures""",

            'yaml_load': """
- Use yaml.safe_load() instead
- Validate YAML input
- Implement proper error handling
- Consider using JSON instead""",

            'request_params': """
- Validate all request parameters
- Implement proper type checking
- Use input sanitization
- Consider using form validation libraries""",

            'template_strings': """
- Validate template variables
- Use template escaping
- Implement proper error handling
- Consider using a template engine""",

            'json_loads': """
- Validate JSON structure
- Implement proper error handling
- Use JSON schema validation
- Consider size limits""",

            'xml_parse': """
- Use defusedxml for safer parsing
- Implement XXE prevention
- Validate XML input
- Consider using JSON instead""",

            'marshal_loads': """
- Avoid using marshal with untrusted data
- Use safer serialization formats
- Implement proper validation
- Consider using JSON""",

            'shelve_open': """
- Validate file paths
- Implement proper error handling
- Use proper file permissions
- Consider using a database""",

            'unvalidated_redirect': """
- Validate redirect URLs
- Use whitelisting
- Implement proper error handling
- Consider using relative URLs""",

            'command_injection': """
- Avoid shell command injection
- Use subprocess with arguments
- Implement proper validation
- Consider using APIs instead""",

            'crypto_weak': """
- Use strong cryptographic functions
- Implement proper key management
- Use proper salt and pepper
- Consider using cryptography library""",

            'temp_file': """
- Use tempfile.mkstemp()
- Implement proper file cleanup
- Use secure permissions
- Consider using memory instead""",

            'random_weak': """
- Use secrets module for security
- Implement proper entropy
- Use cryptographically secure RNG
- Consider using system RNG""",

            'deserialization': """
- Avoid deserializing untrusted data
- Use safe deserialization methods
- Implement proper validation
- Consider using JSON"""
        }

        print(remediation_tips.get(vuln_type, "- Implement proper input validation\n- Use input sanitization"))