import ast
import os
import sys
from typing import List

class SecurityIssueResult:
    def __init__(self, line_no: int, line: str, issue: str, remediation: str):
        self.line_no = line_no
        self.line = line
        self.issue = issue
        self.remediation = remediation

    def __getitem__(self, key):
        if key == 'line_no':
            return self.line_no
        elif key == 'line':
            return self.line
        elif key == 'issue':
            return self.issue
        elif key == 'remediation':
            return self.remediation
        else:
            raise KeyError(f"'{key}' is not a valid attribute")

    def __str__(self):
        return f"Line {self.line_no}: {self.issue} - {self.line}"

    def __repr__(self):
        return self.__str__()

class APISecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.results = []
        self.security_risks = {
            # API Security Issues
            "requests.get": "Potential insecure API request (no timeout, possible SSRF)",
            "requests.post": "Potential insecure API request (no timeout, possible SSRF)",
            "requests.put": "Potential insecure API request (no timeout, possible SSRF)",
            "requests.delete": "Potential insecure API request (no timeout, possible SSRF)",
            "flask.jsonify": "Possible excessive data exposure in API response",
            "django.http.JsonResponse": "Possible excessive data exposure in API response",
            "rest_framework.response.Response": "Potential excessive data exposure in API response",

            # Insecure Serialization & Deserialization Risks
            "pickle.load": "Untrusted deserialization (can lead to RCE)",
            "pickle.loads": "Untrusted deserialization (can lead to RCE)",
            "marshal.load": "Unsafe deserialization (can lead to arbitrary code execution)",
            "marshal.loads": "Unsafe deserialization (can lead to arbitrary code execution)",
            "yaml.load": "Unsafe YAML deserialization (use yaml.safe_load instead)",
            "jsonpickle.decode": "Potential unsafe deserialization",

            # CSRF Risks
            "csrf_exempt": "CSRF protection is disabled for this endpoint",

            # CORS Misconfiguration
            "CORS": "CORS is allowing all origins (potential security risk)",

            # API Key & Token Leakage
            "Authorization": "Hardcoded API token found (consider using environment variables)",
            "api_key": "Hardcoded API key found (store in environment variables instead)",
            "client_secret": "Hardcoded client secret found (should not be in source code)",

            # Insecure JWT Handling
            "jwt.decode": "JWT verification may be missing (ensure verify=True)",
            "jwt.encode": "Ensure strong signing algorithm (avoid HS256 for public APIs)",
            "SECRET_KEY": "Hardcoded secret key found (use environment variables)",

            # Improper Error Handling
            "traceback.print_exc": "Stack trace exposure (can reveal system details)"
        }

        self.remediations = {
            "Potential insecure API request (no timeout, possible SSRF)": "Always set a timeout when making requests: `requests.get(url, timeout=5)`",
            "Possible excessive data exposure in API response": "Ensure that sensitive data is not included in API responses",
            "Untrusted deserialization (can lead to RCE)": "Use json instead of pickle for untrusted data",
            "Unsafe deserialization (can lead to arbitrary code execution)": "Avoid using marshal with untrusted data",
            "Unsafe YAML deserialization (use yaml.safe_load instead)": "Use `yaml.safe_load()` instead of `yaml.load()`",
            "Potential unsafe deserialization": "Ensure that jsonpickle is only used with trusted sources",
            "CSRF protection is disabled for this endpoint": "Do not use `@csrf_exempt`. Enable CSRF protection.",
            "CORS is allowing all origins (potential security risk)": "Restrict allowed origins in CORS configuration",
            "Hardcoded API token found (consider using environment variables)": "Store API tokens in environment variables instead of hardcoding them",
            "Hardcoded API key found (store in environment variables instead)": "Use `os.getenv('API_KEY')` instead of hardcoding",
            "Hardcoded client secret found (should not be in source code)": "Use environment variables for secrets to avoid exposure",
            "JWT verification may be missing (ensure verify=True)": "Ensure that JWTs are verified using `jwt.decode(token, verify=True)`",
            "Ensure strong signing algorithm (avoid HS256 for public APIs)": "Use RS256 for JWTs instead of HS256 for better security",
            "Hardcoded secret key found (use environment variables)": "Move SECRET_KEY to environment variables to avoid leaks",
            "Stack trace exposure (can reveal system details)": "Log errors securely instead of exposing stack traces"
        }

    def visit_Call(self, node):
        """Check function calls for security risks"""
        if isinstance(node.func, ast.Attribute):  # e.g., requests.get, flask.jsonify
            function_name = f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else None
        elif isinstance(node.func, ast.Name):  # e.g., eval, exec
            function_name = node.func.id
        else:
            function_name = None

        if function_name in self.security_risks:
            issue = self.security_risks[function_name]
            remediation = self.remediations.get(issue, "Apply proper security controls")
            self.results.append(SecurityIssueResult(node.lineno, function_name, issue, remediation))

        self.generic_visit(node)

    def visit_Assign(self, node):
        """Detect insecure hardcoded secrets"""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):  # Check if value is a string
            for insecure_key in ["api_key", "client_secret", "SECRET_KEY", "Authorization"]:
                if insecure_key in ast.dump(node):
                    issue = self.security_risks.get(insecure_key, "Hardcoded secret found")
                    remediation = self.remediations.get(issue, "Store secrets in environment variables")
                    self.results.append(SecurityIssueResult(node.lineno, insecure_key, issue, remediation))
        self.generic_visit(node)

    def scan_file(self, file_path: str) -> List[SecurityIssueResult]:
        """Scans the given file for API security vulnerabilities"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as file:
            try:
                tree = ast.parse(file.read(), filename=file_path)
                self.visit(tree)
            except SyntaxError as e:
                print(f"Syntax error in {file_path}: {e}")

        return self.results

if __name__ == "__main__":
    scanner = APISecurityScanner()
    
    file_path = sys.argv[1] if len(sys.argv) > 1 else "/home/hamzsec/swiftsafe/sdlc/target3.py"

    try:
        results = scanner.scan_file(file_path)
        if results:
            print(f"Found {len(results)} potential API security risks:")
            for i, result in enumerate(results, 1):
                print(f"{i}. Line {result.line_no}: {result.issue}")
                print(f"   Code: {result.line}")
                print(f"   Remediation: {result.remediation}\n")
        else:
            print("No API security risks detected.")
    except Exception as e:
        print(f"Error: {str(e)}")
