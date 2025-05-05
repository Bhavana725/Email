import re
from typing import List, Dict, Set, Tuple

class ReflectionVulnerabilityScanner:
    def __init__(self):
        # Define patterns for reflection vulnerabilities
        self.patterns = {
            'eval': r'eval\s*\(',
            'exec': r'exec\s*\(',
            'import_module': r'__import__\s*\(|importlib\.import_module\s*\(',
            'getattr': r'getattr\s*\(',
            'globals': r'globals\s*\(\)',
            'locals': r'locals\s*\(\)',
            'compile': r'compile\s*\(',
            'pickle_loads': r'pickle\.loads\s*\(',
            'yaml_load': r'yaml\.load\s*\(',
            'marshal_loads': r'marshal\.loads\s*\(',
            'json_loads': r'json\.loads\s*\(',
            'unsafe_deserialization': r'(pickle|yaml|marshal|json)\.loads?\s*\(',
            'dynamic_code': r'(exec|eval|compile)\s*\(',
            'dynamic_import': r'(__import__|importlib\.import_module)\s*\(',
            'dynamic_attr': r'(getattr|setattr|delattr|hasattr)\s*\(',
            'type_creation': r'type\s*\([^,]+,\s*[^,]+,\s*{',
            'metaclass': r'__metaclass__\s*=|metaclass\s*=',
            'unsafe_format': r'format\s*\(.*\)|{}\.format\(',
            'template_string': r'Template\s*\(|string\.Template\s*\(',
            'dynamic_function': r'(globals|locals)\s*\(\)\.get\s*\([^)]*\)'
        }

        # Define remediation messages for each vulnerability type
        self.remediations = {
            'eval': 'Use ast.literal_eval() for safe evaluation or implement proper parsing',
            'exec': 'Avoid exec(). Use proper module imports and function calls',
            'import_module': 'Use whitelist of allowed modules and validate imports',
            'getattr': 'Implement whitelist of allowed attributes/methods',
            'globals': 'Avoid using globals(). Use proper scope management',
            'locals': 'Avoid using locals(). Use proper scope management',
            'compile': 'Avoid compile(). Use proper module imports',
            'pickle_loads': 'Use json or other secure serialization methods',
            'yaml_load': 'Use yaml.safe_load() instead',
            'marshal_loads': 'Use json or other secure serialization methods',
            'json_loads': 'Validate JSON schema before loading',
            'unsafe_deserialization': 'Use secure alternatives or validate data before deserialization',
            'dynamic_code': 'Avoid dynamic code execution. Use proper validation',
            'dynamic_import': 'Implement whitelist of allowed modules',
            'dynamic_attr': 'Use whitelist of allowed attributes',
            'type_creation': 'Avoid dynamic type creation. Use proper class definitions',
            'metaclass': 'Carefully validate metaclass usage',
            'unsafe_format': 'Use f-strings or validated format strings',
            'template_string': 'Validate template inputs before processing',
            'dynamic_function': 'Avoid dynamic function lookup. Use proper imports'
        }

        # Store found vulnerabilities
        self.found_vulnerabilities: Set[Tuple[str, int, str]] = set()

    def analyze_file(self, file_path: str) -> List[Dict]:
        """
        Analyze a Python file for reflection vulnerabilities.
        :param file_path: Path to the file to analyze
        :return: List of vulnerabilities found
        """
        try:
            with open(file_path, 'r') as file:
                content = file.read()

            lines = content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                for vuln_type, pattern in self.patterns.items():
                    if re.search(pattern, line):
                        self.found_vulnerabilities.add((vuln_type, line_no, line.strip()))

            return self._format_results()
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return []
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return []

    def _format_results(self) -> List[Dict]:
        """
        Format the found vulnerabilities into a list of dictionaries.
        :return: List of vulnerabilities in dictionary format
        """
        results = []
        for vuln_type, line_no, line_content in self.found_vulnerabilities:
            results.append({
                'type': vuln_type,
                'line': line_no,
                'code': line_content,
                'remediation': self.remediations.get(vuln_type, "Implement proper security controls")
            })
        return results

    def display_results(self, vulnerabilities: List[Dict]) -> None:
        """
        Display the results of the vulnerability scan.
        :param vulnerabilities: List of vulnerabilities found
        """
        if not vulnerabilities:
            print("No reflection vulnerabilities found.")
            return

        print("\n=== Reflection Vulnerability Detection Results ===\n")
        for vuln in sorted(vulnerabilities, key=lambda x: x["line"]):
            print(f"Type: {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['code']}")
            print("Remediation:", vuln['remediation'])
            print("-" * 50 + "\n")