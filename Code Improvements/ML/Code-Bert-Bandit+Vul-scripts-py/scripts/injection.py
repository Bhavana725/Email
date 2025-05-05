import re
from typing import List, Dict

class CodeInjectionDetector:
    def __init__(self):
        # Existing patterns (with XML-related patterns removed)
        self.suspicious_patterns = {
            'eval': r'eval\s*\(',
            'exec': r'exec\s*\(',
            'subprocess.call': r'subprocess\.call\s*\(',
            'subprocess.Popen': r'subprocess\.Popen\s*\(',
            'os.system': r'os\.system\s*\(',
            'pickle.loads': r'pickle\.loads\s*\(',
            'yaml.load': r'yaml\.load\s*\(',
            'input': r'input\s*\(',
            'marshal.loads': r'marshal\.loads\s*\(',
            'sqlite3.execute': r'execute\s*\(',
            'bash_command': r'bash\s*\(',
            'shell_exec': r'shell_exec\s*\(',
            'system': r'system\s*\(',
            'passthru': r'passthru\s*\(',
            'popen': r'popen\s*\(',
            'proc_open': r'proc_open\s*\(',
            'pcntl_exec': r'pcntl_exec\s*\(',
            'assert': r'assert\s*\(',
            'unserialize': r'unserialize\s*\(',
            'import_module': r'import_module\s*\(',
            'importlib.import_module': r'importlib\.import_module\s*\(',
            '__import__': r'__import__\s*\(',
            'globals': r'globals\s*\(',
            'locals': r'locals\s*\(',
            'getattr': r'getattr\s*\(',
            'setattr': r'setattr\s*\(',
            'delattr': r'delattr\s*\(',
            'hasattr': r'hasattr\s*\(',
            'compile': r'compile\s*\(',
            'execfile': r'execfile\s*\(',
            'shelve.open': r'shelve\.open\s*\(',
            'tempfile.mktemp': r'mktemp\s*\(',
            'commands.getoutput': r'commands\.getoutput\s*\(',
            'commands.getstatusoutput': r'commands\.getstatusoutput\s*\(',
            'commands.getstatus': r'commands\.getstatus\s*\(',
            'pdb.run': r'pdb\.run\s*\(',
            'code.interact': r'code\.interact\s*\(',
            'code.compile_command': r'code\.compile_command\s*\(',
            'cgi.escape': r'cgi\.escape\s*\(',
            'urllib.urlopen': r'urllib\.urlopen\s*\(',
            'urllib2.urlopen': r'urllib2\.urlopen\s*\(',
            'urllib.request.urlopen': r'urllib\.request\.urlopen\s*\(',
            'urllib.parse.parse_qs': r'urllib\.parse\.parse_qs\s*\(',
            'urlparse.parse_qs': r'urlparse\.parse_qs\s*\(',
            'cPickle.loads': r'cPickle\.loads\s*\(',
            'dill.loads': r'dill\.loads\s*\(',
            'shelve.loads': r'shelve\.loads\s*\(',
            'sqlite3.connect': r'sqlite3\.connect\s*\(',
            'mysql.connector.connect': r'mysql\.connector\.connect\s*\(',
            'psycopg2.connect': r'psycopg2\.connect\s*\(',
            'pymongo.MongoClient': r'pymongo\.MongoClient\s*\(',
            'redis.Redis': r'redis\.Redis\s*\(',
            'paramiko.SSHClient': r'paramiko\.SSHClient\s*\(',
            'ftplib.FTP': r'ftplib\.FTP\s*\(',
            'telnetlib.Telnet': r'telnetlib\.Telnet\s*\(',
            'smtplib.SMTP': r'smtplib\.SMTP\s*\(',
            'poplib.POP3': r'poplib\.POP3\s*\(',
            'imaplib.IMAP4': r'imaplib\.IMAP4\s*\(',
            'serial.Serial': r'serial\.Serial\s*\(',
            'socket.socket': r'socket\.socket\s*\(',
            'ssl.wrap_socket': r'ssl\.wrap_socket\s*\(',
            'subprocess.getoutput': r'subprocess\.getoutput\s*\(',
            'subprocess.getstatusoutput': r'subprocess\.getstatusoutput\s*\(',
            'subprocess.check_output': r'subprocess\.check_output\s*\(',
            'subprocess.check_call': r'subprocess\.check_call\s*\(',
            'subprocess.run': r'subprocess\.run\s*\(',
            'os.popen': r'os\.popen\s*\(',
            'os.spawn': r'os\.spawn\s*\(',
            'os.fork': r'os\.fork\s*\(',
            'os.execl': r'os\.execl\s*\(',
            'os.execle': r'os\.execle\s*\(',
            'os.execlp': r'os\.execlp\s*\(',
            'os.execlpe': r'os\.execlpe\s*\(',
            'os.execv': r'os\.execv\s*\(',
            'os.execve': r'os\.execve\s*\(',
            'os.execvp': r'os\.execvp\s*\(',
            'os.execvpe': r'os\.execvpe\s*\(',
            
            # SQL Injection patterns
            'raw_sql_concat': r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+.*',
            'raw_sql_format': r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*%.*',
            'raw_sql_f_string': r'f["\']SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*["\']',
            'raw_sql_insert': r'INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\+.*\)',
            'raw_sql_update': r'UPDATE\s+.*\s+SET\s+.*\s+=\s+.*\+.*',
            'string_concat_sql': r'.*\.execute\s*\(.*\+.*\)',
            'string_format_sql': r'.*\.execute\s*\(.*%.+\)',
            'string_f_string_sql': r'.*\.execute\s*\(f["\'].*["\'].*\)',
            'executescript': r'executescript\s*\(',
            'cursor.executemany': r'executemany\s*\(',
            'raw_connection.cursor': r'connection\.cursor\s*\(\)',
            'raw_connection.execute': r'connection\.execute\s*\(',
            
            # NoSQL Injection patterns
            'mongodb_no_filter': r'find\s*\(\s*\{\s*\$where\s*:',
            'mongodb_js_eval': r'\$where\s*:\s*["\']function\(\)',
            'mongoose_query': r'mongoose.*\.where\s*\(',
            'pymongo_eval': r'\.eval\s*\(',
            'pymongo_command': r'\.command\s*\(',
            
            # LDAP Injection
            'ldap_search': r'ldap\.search\s*\(',
            'ldapconnection_search': r'ldapconnection\.search\s*\(',
            'ldap_filter_raw': r'ldap\.filter\s*\(',
            
            # OS Command Injection (additional patterns)
            'command_with_vars': r'(os\.system|subprocess\.call|subprocess\.Popen)\s*\(["\'].*(\$|\{|\%|\+).*["\']',
            'backtick_exec': r'`.*\$.*`',
            
            # Template Injection
            'jinja2_template': r'jinja2\.Template\s*\(',
            'render_template_string': r'render_template_string\s*\(',
            'template_from_string': r'template_from_string\s*\(',
            'from_string': r'from_string\s*\(',
            'flask_render_template': r'render_template\s*\(',
            'mako_template': r'mako\.template\s*\(',
            'template_render': r'template\.render\s*\(',
            
            # Deserialization
            'pyyaml_load': r'yaml\.load\s*\(.*,\s*Loader\s*=\s*Loader\)',
            'json_loads': r'json\.loads\s*\(',
            
            # Path traversal
            'open_file': r'open\s*\(.*\+.*\)',
            'read_file': r'read\s*\(.*\+.*\)',
            'file_operations': r'(copy|move|rename|unlink|remove)\s*\(.*\+.*\)',
            'path_join_with_var': r'os\.path\.join\s*\(.*\+.*\)',
            
            # Server Side Request Forgery (SSRF)
            'requests_get': r'requests\.get\s*\(',
            'requests_post': r'requests\.post\s*\(',
            'urllib_request': r'urllib\.request\s*\(',
            'httplib_request': r'httplib\..*request\s*\(',
            'http_client_request': r'http\.client\..*request\s*\(',
            'aiohttp_request': r'aiohttp\..*request\s*\(',
            
            # Code/Expression Injection
            'string_as_code': r'(compile|eval)\s*\(.*\+.*\)',
            'expression_eval': r'(ast\.)?literal_eval\s*\(',
            
            # Format String Vulnerability
            'format_string': r'%[^scdfg%]*[scdfg]',
            'string_format': r'\.format\s*\(',
            
            # Buffer Overflow (for C/C++ extensions)
            'strcpy': r'strcpy\s*\(',
            'strcat': r'strcat\s*\(',
            'gets': r'gets\s*\(',
            
            # Regex Injection (ReDoS)
            're_compile_from_var': r're\.compile\s*\(.*\+.*\)',
            're_search_from_var': r're\.search\s*\(.*\+.*\)',
            
            # HTTP Response Splitting
            'set_header': r'set_header\s*\(',
            'add_header': r'add_header\s*\('
        }

        # Add remediation advice for the patterns (with XML-related remediations removed)
        self.remediations = {
            'eval': 'Use ast.literal_eval() for safe string parsing or implement custom parsing logic',
            'exec': 'Avoid using exec(). Use safer alternatives like importing modules or defined functions',
            'subprocess.call': 'Validate and sanitize all inputs. Use subprocess.run() with shell=False',
            'subprocess.Popen': 'Validate and sanitize commands. Use subprocess.run() with shell=False',
            'os.system': 'Use subprocess module with proper input validation',
            'pickle.loads': 'Use JSON or other safe serialization formats. Never unpickle untrusted data',
            'yaml.load': 'Use yaml.safe_load() instead of yaml.load()',
            'input': 'Validate and sanitize all user input before processing',
            'marshal.loads': 'Use safer serialization formats like JSON',
            'sqlite3.execute': 'Use parameterized queries with ? placeholder and query parameters',
            'bash_command': 'Avoid shell commands. Use subprocess with proper validation',
            'shell_exec': 'Avoid shell commands. Use subprocess with proper validation',
            'system': 'Use subprocess module with proper input validation',
            'passthru': 'Avoid shell commands. Use subprocess with proper validation',
            'popen': 'Use subprocess.run() with shell=False and input validation',
            'proc_open': 'Use subprocess module with proper validation',
            'pcntl_exec': 'Use subprocess module with proper validation',
            'assert': 'Avoid using assert for security. Use proper validation',
            'unserialize': 'Use safe serialization like JSON',
            'import_module': 'Validate module names before importing',
            'importlib.import_module': 'Validate module names before importing',
            '__import__': 'Validate module names before importing',
            'globals': 'Avoid modifying global namespace',
            'locals': 'Avoid modifying local namespace',
            'getattr': 'Validate attribute names',
            'setattr': 'Validate attribute names and values',
            'delattr': 'Validate attribute names',
            'hasattr': 'Validate attribute names',
            'compile': 'Avoid dynamic code compilation',
            'execfile': 'Use proper module imports instead',
            'shelve.open': 'Validate file paths and data',
            'tempfile.mktemp': 'Use tempfile.mkstemp() instead',
            'commands.getoutput': 'Use subprocess module with validation',
            'commands.getstatusoutput': 'Use subprocess module with validation',
            'commands.getstatus': 'Use subprocess module with validation',
            'pdb.run': 'Avoid running debugger in production',
            'code.interact': 'Avoid interactive shells in production',
            'code.compile_command': 'Avoid dynamic code compilation',
            'cgi.escape': 'Use html.escape() instead',
            'urllib.urlopen': 'Use requests library with proper validation',
            'urllib2.urlopen': 'Use requests library with proper validation',
            'urllib.request.urlopen': 'Use requests library with proper validation',
            'urllib.parse.parse_qs': 'Validate query parameters',
            'urlparse.parse_qs': 'Validate query parameters',
            'cPickle.loads': 'Use JSON or other safe serialization',
            'dill.loads': 'Use JSON or other safe serialization',
            'shelve.loads': 'Use JSON or other safe serialization',
            'sqlite3.connect': 'Use connection pooling and validate paths',
            'mysql.connector.connect': 'Use connection pooling and validate credentials',
            'psycopg2.connect': 'Use connection pooling and validate credentials',
            'pymongo.MongoClient': 'Use connection pooling and validate credentials',
            'redis.Redis': 'Use connection pooling and validate credentials',
            'paramiko.SSHClient': 'Validate credentials and host keys',
            'ftplib.FTP': 'Use SFTP instead with proper validation',
            'telnetlib.Telnet': 'Use SSH instead with proper validation',
            'smtplib.SMTP': 'Validate credentials and use TLS',
            'poplib.POP3': 'Validate credentials and use TLS',
            'imaplib.IMAP4': 'Validate credentials and use TLS',
            'serial.Serial': 'Validate port settings',
            'socket.socket': 'Use high-level networking libraries',
            'ssl.wrap_socket': 'Use modern SSL context instead',
            'subprocess.getoutput': 'Use subprocess.run with proper validation',
            'subprocess.getstatusoutput': 'Use subprocess.run with proper validation',
            'subprocess.check_output': 'Use subprocess.run with proper validation',
            'subprocess.check_call': 'Use subprocess.run with proper validation',
            'subprocess.run': 'Use shell=False and validate inputs',
            'os.popen': 'Use subprocess module with validation',
            'os.spawn': 'Use subprocess module with validation',
            'os.fork': 'Use multiprocessing module instead',
            'os.execl': 'Use subprocess module with validation',
            'os.execle': 'Use subprocess module with validation',
            'os.execlp': 'Use subprocess module with validation',
            'os.execlpe': 'Use subprocess module with validation',
            'os.execv': 'Use subprocess module with validation',
            'os.execve': 'Use subprocess module with validation',
            'os.execvp': 'Use subprocess module with validation',
            'os.execvpe': 'Use subprocess module with validation',
            
            # SQL Injection remediations
            'raw_sql_concat': 'Use parameterized queries with placeholders instead of string concatenation',
            'raw_sql_format': 'Use parameterized queries with placeholders instead of string formatting',
            'raw_sql_f_string': 'Use parameterized queries with placeholders instead of f-strings',
            'raw_sql_insert': 'Use parameterized queries with placeholders for INSERT statements',
            'raw_sql_update': 'Use parameterized queries with placeholders for UPDATE statements',
            'string_concat_sql': 'Use parameterized queries with placeholders instead of string concatenation',
            'string_format_sql': 'Use parameterized queries with placeholders instead of string formatting',
            'string_f_string_sql': 'Use parameterized queries with placeholders instead of f-strings',
            'executescript': 'Use parameterized queries instead of executescript which runs multiple SQL statements',
            'cursor.executemany': 'Ensure all parameters are properly sanitized',
            'raw_connection.cursor': 'Use ORM or parameterized queries instead of raw SQL',
            'raw_connection.execute': 'Use parameterized queries with placeholders instead of raw SQL execution',
            
            # NoSQL Injection remediations
            'mongodb_no_filter': 'Avoid using $where operators with user input',
            'mongodb_js_eval': 'Avoid using JavaScript evaluation in MongoDB queries',
            'mongoose_query': 'Use strict matching instead of dynamic queries with user input',
            'pymongo_eval': 'Avoid using eval() in MongoDB',
            'pymongo_command': 'Validate and sanitize all inputs before using in commands',
            
            # LDAP Injection remediations
            'ldap_search': 'Sanitize and escape all inputs for LDAP queries',
            'ldapconnection_search': 'Sanitize and escape all inputs for LDAP queries',
            'ldap_filter_raw': 'Use safe filter construction methods',
            
            # OS Command Injection remediations
            'command_with_vars': 'Avoid using variables in command strings, use array form instead',
            'backtick_exec': 'Avoid using backticks for command execution',
            
            # Template Injection remediations
            'jinja2_template': 'Use sandboxed environment for Jinja2 and disable risky features',
            'render_template_string': 'Don\'t render user-provided templates',
            'template_from_string': 'Don\'t render user-provided templates',
            'from_string': 'Don\'t render user-provided templates',
            'flask_render_template': 'Keep templates in a secure location and don\'t render user inputs as templates',
            'mako_template': 'Don\'t render user-provided templates',
            'template_render': 'Don\'t render user-provided templates',
            
            # Deserialization remediations
            'pyyaml_load': 'Use yaml.safe_load() instead',
            'json_loads': 'Ensure JSON data is validated against a schema',
            
            # Path traversal remediations
            'open_file': 'Use os.path.abspath and path validation to prevent directory traversal',
            'read_file': 'Validate paths and never use user input directly in file operations',
            'file_operations': 'Validate paths and never use user input directly in file operations',
            'path_join_with_var': 'Sanitize all path components to prevent directory traversal',
            
            # SSRF remediations
            'requests_get': 'Validate URLs against whitelist and avoid internal hostnames/IPs',
            'requests_post': 'Validate URLs against whitelist and avoid internal hostnames/IPs',
            'urllib_request': 'Validate URLs against whitelist and avoid internal hostnames/IPs',
            'httplib_request': 'Validate URLs against whitelist and avoid internal hostnames/IPs',
            'http_client_request': 'Validate URLs against whitelist and avoid internal hostnames/IPs',
            'aiohttp_request': 'Validate URLs against whitelist and avoid internal hostnames/IPs',
            
            # Code/Expression Injection remediations
            'string_as_code': 'Avoid evaluating dynamic code, use safer alternatives',
            'expression_eval': 'Ensure expressions are validated against a whitelist',
            
            # Format String remediations
            'format_string': 'Use named parameters for string formatting',
            'string_format': 'Validate all format arguments',
            
            # Buffer Overflow remediations
            'strcpy': 'Use strncpy with proper buffer size limits',
            'strcat': 'Use strncat with proper buffer size limits',
            'gets': 'Use fgets with proper buffer size limits',
            
            # Regex Injection remediations
            're_compile_from_var': 'Validate regex patterns against a whitelist to prevent ReDoS',
            're_search_from_var': 'Validate regex patterns against a whitelist to prevent ReDoS',
            
            # HTTP Response Splitting remediations
            'set_header': 'Sanitize header values to prevent CRLF injection',
            'add_header': 'Sanitize header values to prevent CRLF injection',
        }

    def analyze_file(self, file_path: str) -> List[Dict]:
        vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

            for line_no, line in enumerate(lines, start=1):
                for vuln_type, pattern in self.suspicious_patterns.items():
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'line': line_no,
                            'code': line.strip(),
                            'remediation': self.remediations.get(vuln_type, 'Validate and sanitize all inputs')
                        })

            return vulnerabilities

        except Exception as e:
            print(f"Error analyzing file: {e}")
            return []

    def display_results(self, vulnerabilities: List[Dict]) -> None:
        if not vulnerabilities:
            print("No code injection vulnerabilities found.")
            return

        print("\n=== Code Injection Detection Results ===\n")
        for vuln in sorted(vulnerabilities, key=lambda x: x["line"]):
            print(f"Type: {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['code']}")
            print(f"Remediation: {vuln['remediation']}")
            print("-" * 50 + "\n")

    def group_results_by_category(self, vulnerabilities: List[Dict]) -> None:
        """Display results grouped by vulnerability categories"""
        if not vulnerabilities:
            print("No code injection vulnerabilities found.")
            return
            
        categories = {
            'SQL Injection': ['raw_sql_concat', 'raw_sql_format', 'raw_sql_f_string', 'raw_sql_insert', 
                             'raw_sql_update', 'string_concat_sql', 'string_format_sql', 'string_f_string_sql',
                             'executescript', 'cursor.executemany', 'raw_connection.cursor', 'raw_connection.execute',
                             'sqlite3.execute'],
            'Command Injection': ['eval', 'exec', 'subprocess.call', 'subprocess.Popen', 'os.system', 'command_with_vars',
                                 'backtick_exec', 'bash_command', 'shell_exec', 'system', 'passthru', 'popen', 
                                 'proc_open', 'pcntl_exec', 'os.popen', 'os.spawn', 'os.fork', 'os.execl', 
                                 'os.execle', 'os.execlp', 'os.execlpe', 'os.execv', 'os.execve', 'os.execvp', 
                                 'os.execvpe', 'subprocess.getoutput', 'subprocess.getstatusoutput', 
                                 'subprocess.check_output', 'subprocess.check_call', 'subprocess.run'],
            'NoSQL Injection': ['mongodb_no_filter', 'mongodb_js_eval', 'mongoose_query', 'pymongo_eval', 'pymongo_command'],
            'LDAP Injection': ['ldap_search', 'ldapconnection_search', 'ldap_filter_raw'],
            'Template Injection': ['jinja2_template', 'render_template_string', 'template_from_string', 'from_string',
                                  'flask_render_template', 'mako_template', 'template_render'],
            'Deserialization': ['pickle.loads', 'yaml.load', 'marshal.loads', 'pyyaml_load', 'json_loads', 'cPickle.loads',
                               'dill.loads', 'shelve.loads', 'unserialize'],
            'Path Traversal': ['open_file', 'read_file', 'file_operations', 'path_join_with_var'],
            'SSRF': ['requests_get', 'requests_post', 'urllib_request', 'httplib_request', 'http_client_request', 
                    'aiohttp_request', 'urllib.urlopen', 'urllib2.urlopen', 'urllib.request.urlopen'],
            'Code/Expression Injection': ['string_as_code', 'expression_eval', 'compile', 'execfile', 'assert',
                                         'import_module', 'importlib.import_module', '__import__', 'code.compile_command'],
            'Format String': ['format_string', 'string_format'],
            'Buffer Overflow': ['strcpy', 'strcat', 'gets'],
            'Regex Injection': ['re_compile_from_var', 're_search_from_var'],
            'HTTP Response Splitting': ['set_header', 'add_header'],
            'Other': []  # Catch-all for anything not in a specific category
        }
        
        print("\n=== Code Injection Detection Results by Category ===\n")
        
        for category, types in categories.items():
            category_vulns = [v for v in vulnerabilities if v['type'] in types]
            
            # Add any vulnerability types not explicitly categorized to "Other"
            if category == 'Other':
                all_categorized_types = [t for cat_types in categories.values() for t in cat_types if cat_types]
                category_vulns = [v for v in vulnerabilities if v['type'] not in all_categorized_types]
            
            if category_vulns:
                print(f"\n## {category} ({len(category_vulns)} findings) ##")
                for vuln in sorted(category_vulns, key=lambda x: x["line"]):
                    print(f"Type: {vuln['type']}")
                    print(f"Line {vuln['line']}: {vuln['code']}")
                    print(f"Remediation: {vuln['remediation']}")
                    print("-" * 50)