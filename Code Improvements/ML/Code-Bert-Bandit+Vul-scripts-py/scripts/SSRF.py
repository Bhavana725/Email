import re
from typing import List, Dict, Set, Tuple

class SSRFAnalyzer:
    def __init__(self):
        # Define patterns for SSRF vulnerabilities
        self.patterns: Dict[str, List[str]] = {
            'requests': ['get', 'post', 'request', 'put', 'delete', 'head', 'patch', 'options'],
            'urllib.request': ['urlopen', 'urlretrieve', 'Request', 'build_opener', 'install_opener'],
            'httpx': ['get', 'post', 'request', 'put', 'delete', 'head', 'patch', 'options'],
            'aiohttp': ['request', 'get', 'post', 'put', 'delete', 'head', 'patch', 'options'],
            'http.client': ['HTTPConnection', 'HTTPSConnection', 'HTTPResponse', 'HTTPMessage'],
            'urllib3': ['request', 'PoolManager', 'ProxyManager', 'connection_from_url'],
            'flask': ['url_for', 'redirect', 'render_template_string']  # Special cases for URL generation and redirection
        }

        # Define remediation messages for each vulnerability type
        self.remediations: Dict[str, List[str]] = {
            'requests': [
                "Validate and sanitize all user-provided URLs",
                "Use an allowlist of permitted domains",
                "Disable redirects with allow_redirects=False"
            ],
            'urllib.request': [
                "Use urlparse to validate URL components",
                "Restrict access to internal network ranges",
                "Block file:// and other dangerous schemas"
            ],
            'httpx': [
                "Implement strict URL validation",
                "Use allowed_hosts configuration",
                "Sanitize redirect targets"
            ],
            'aiohttp': [
                "Validate URLs before making requests",
                "Use restricted DNS resolution",
                "Configure connector with allowed IP ranges"
            ],
            'http.client': [
                "Validate host/IP against allowed destinations",
                "Implement port validation",
                "Avoid direct user input in connection parameters"
            ],
            'flask': [
                "Validate url_for parameters carefully",
                "Avoid user-controlled endpoint names",
                "Use static URL generation where possible"
            ]
        }

        # Store found vulnerabilities
        self.vulnerabilities: Set[Tuple[str, int, str, str]] = set()

    def analyze_file(self, file_path: str) -> List[Dict]:
        """
        Analyze a Python file for SSRF vulnerabilities.
        :param file_path: Path to the file to analyze
        :return: List of vulnerabilities found
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            for line_no, line in enumerate(lines, start=1):
                for lib, funcs in self.patterns.items():
                    for func in funcs:
                        # Match patterns like "requests.get(" or "urllib.request.urlopen("
                        pattern = rf'{lib}\.{func}\('
                        if re.search(pattern, line):
                            self.vulnerabilities.add((
                                file_path,
                                line_no,
                                lib,
                                func
                            ))

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
        for file_path, line_no, lib, func in self.vulnerabilities:
            results.append({
                'file_path': file_path,
                'line': line_no,
                'library': lib,
                'function': func,
                'remediation': self.remediations.get(lib, ["Implement proper URL validation"])
            })
        return results

    def display_results(self, vulnerabilities: List[Dict]) -> None:
        """
        Display the results of the vulnerability scan.
        :param vulnerabilities: List of vulnerabilities found
        """
        if not vulnerabilities:
            print("No SSRF vulnerabilities found!")
            return

        print(f"\nFound {len(vulnerabilities)} potential SSRF vulnerabilities:")
        for vuln in sorted(vulnerabilities, key=lambda x: (x['file_path'], x['line'])):
            print(f"\n[!] Vulnerability in {vuln['file_path']}:{vuln['line']}")
            print(f"    Library: {vuln['library']} | Method: {vuln['function']}()")
            print("    Recommended fixes:")
            for fix in vuln['remediation']:
                print(f"    - {fix}")

        print("\nGeneral SSRF Prevention Tips:")
        print("- Validate all user-provided URLs")
        print("- Use allowlists instead of blocklists")
        print("- Disable unnecessary URL schemas")
        print("- Implement network segmentation")
        print("- Monitor outgoing network traffic")