import re
import os
from typing import List, Dict

class XSSDetector:
    def __init__(self):
        # Python-specific XSS vulnerability patterns
        self.xss_patterns = {
            'flask_render': r'render_template\(.*?\)|render_template_string\(.*?\)',
            'django_render': r'render\(.*?\)|render_to_response\(.*?\)',
            'html_response': r'HTMLResponse\(.*?\)|HtmlResponse\(.*?\)',
            'direct_response': r'Response\(.*?html.*?\)|Response\(.*?text.*?\)',
            'template_string': r'Template\(.*?\)\.render\(|Markup\(.*?\)',
            'mark_safe': r'mark_safe\(.*?\)|safe\(.*?\)',
            'escape_html': r'escape\(.*?\)|unescape\(.*?\)',
            'jinja_template': r'jinja2\.Template\(.*?\)',
            'format_string': r'format\(.*?\)|f\".*?\"|f\'.*?\'',
            'html_write': r'write\(.*?html.*?\)|writelines\(.*?html.*?\)',
            'direct_print': r'print\(.*?html.*?\)',
            'http_response': r'HttpResponse\(.*?\)',
            'json_response': r'JsonResponse\(.*?,\s*safe=False\)',
            'template_loader': r'template\.loader\.render_to_string\(',
            'send_file': r'send_file\(.*?\)|send_from_directory\(.*?\)',
            'fastapi_response': r'HTMLResponse\(.*?\)|Response\(.*?html.*?\)',
            'aiohttp_response': r'web\.Response\(text=.*?,\s*content_type=\'text/html\'\)',
            'werkzeug_response': r'Response\(.*?\)',
            'bottle_template': r'template\(.*?\)',
            'pyramid_response': r'Response\(.*?html.*?\)'
        }

        # Python-specific remediation messages
        self.remediations = {
            'flask_render': 'Use escape() or |safe filter explicitly. Implement CSP headers. Sanitize user input before rendering.',
            'django_render': 'Use Django\'s built-in template escaping. Enable CSRF protection. Validate user input.',
            'html_response': 'Ensure content is properly escaped. Use framework\'s built-in sanitizers.',
            'direct_response': 'Use framework\'s escape mechanisms. Sanitize content before sending response.',
            'template_string': 'Use autoescape in templates. Sanitize variables before template rendering.',
            'mark_safe': 'Avoid mark_safe() with user input. Use HTML sanitizer library.',
            'escape_html': 'Use framework\'s built-in escape mechanisms instead of manual escaping.',
            'jinja_template': 'Enable autoescape in Jinja2. Use |escape filter for variables.',
            'format_string': 'Sanitize input before string formatting. Use HTML escape functions.',
            'html_write': 'Escape HTML content before writing. Use secure write methods.',
            'direct_print': 'Escape HTML content before printing. Use secure output methods.',
            'http_response': 'Use Django\'s template system instead of direct HTML response.',
            'json_response': 'Enable safe mode in JsonResponse. Validate JSON data.',
            'template_loader': 'Use template engine\'s escape mechanisms. Validate template variables.',
            'send_file': 'Validate file paths. Implement proper content security headers.',
            'fastapi_response': 'Use templates or proper HTML escaping. Implement security headers.',
            'aiohttp_response': 'Sanitize HTML content. Use templating engine with autoescape.',
            'werkzeug_response': 'Use framework\'s escape mechanisms. Implement proper security headers.',
            'bottle_template': 'Enable template autoescape. Sanitize template variables.',
            'pyramid_response': 'Use framework\'s template system with proper escaping.'
        }

    def analyze_file(self, file_path: str) -> List[Dict]:
        """
        Analyze a Python file for potential XSS vulnerabilities.
        :param file_path: Path to the file to analyze
        :return: List of vulnerabilities found
        """
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return []

        if not file_path.endswith('.py'):
            print("Error: Not a Python file. Please provide a .py file.")
            return []

        results = []
        seen_vulnerabilities = set()

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            for line_num, line in enumerate(lines, 1):
                line = line.strip()

                # Skip comments and empty lines
                if line.startswith('#') or not line:
                    continue

                for pattern_name, pattern in self.xss_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln_id = f"{pattern_name}:{line.strip()}"

                        if vuln_id not in seen_vulnerabilities:
                            seen_vulnerabilities.add(vuln_id)
                            results.append({
                                'line_number': line_num,
                                'line_content': line,
                                'vulnerability_type': pattern_name,
                                'remediation': self.remediations[pattern_name]
                            })

        except Exception as e:
            print(f"Error analyzing file: {e}")
            return []

        return results

    def display_results(self, results: List[Dict]) -> None:
        """
        Display the results of the vulnerability scan.
        :param results: List of vulnerabilities found
        """
        if not results:
            print("\n✅ No XSS vulnerabilities detected.")
            return

        print("\n=== XSS Vulnerability Analysis Results ===")
        for i, result in enumerate(results, 1):
            print(f"\nVulnerability #{i}")
            print(f"Line {result['line_number']}: {result['line_content']}")
            print(f"Type: {result['vulnerability_type']}")
            print(f"Remediation: {result['remediation']}")
            print("-" * 50)

        print(f"\nTotal vulnerabilities found: {len(results)}")