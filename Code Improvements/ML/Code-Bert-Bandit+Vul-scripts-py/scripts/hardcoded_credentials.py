import re
from typing import List, Dict
from pathlib import Path

class VulnerabilityResult:
    def __init__(self, line_no: int, line: str, vulnerability: str, remediation: str):
        self.line_no = line_no
        self.line = line
        self.vulnerability = vulnerability
        self.remediation = remediation

class HardcodedCredentialsScanner:
    def __init__(self):
        self.vulnerable_patterns = {
            'password': r'(?i)(password|passwd|pwd|secret)',
            'api_key': r'(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)',
            'token': r'(?i)(token|bearer|jwt)',
            'auth': r'(?i)(auth[_-]?token|authorization)',
            'database': r'(?i)(database|db)[_-]?(password|passwd|pwd|secret)',
            'credentials': r'(?i)(credentials|creds)',
            'artifactory': r'(?i)(artifactory[_-]?(key|token|secret|password|apikey))',
            'aws': r'(?i)(aws[_-]?(secret[_-]?access[_-]?key|access[_-]?key[_-]?id|account[_-]?id|key|token))',  # Fixed regex
            'azure_storage': r'(?i)(azure[_-]?storage[_-]?(account|key|connection[_-]?string))',
            'basic_auth': r'(?i)(basic[_-]?auth[_-]?(password|token|credential))',
            'cloudant': r'(?i)(cloudant[_-]?(password|key|token|secret))',
            'discord': r'(?i)(discord[_-]?(bot[_-]?token|client[_-]?secret|api[_-]?key))',
            'github': r'(?i)(github[_-]?(token|key|secret|pat|access[_-]?token))',
            'gitlab': r'(?i)(gitlab[_-]?(token|key|secret|pat|access[_-]?token))',
            'base64_entropy': r'(?i)(base64[_-]?string|base64[_-]?encoded)',
            'hex_entropy': r'(?i)(hex[_-]?string|hex[_-]?encoded)',
            'ibm_cloud': r'(?i)(ibm[_-]?cloud[_-]?(api[_-]?key|iam[_-]?key|token))',
            'ibm_cos': r'(?i)(ibm[_-]?cos[_-]?(hmac|key|secret))',
            'ip_public': r'(?i)(ip[_-]?address|public[_-]?ip)',
            'jwt': r'(?i)(jwt[_-]?token|json[_-]?web[_-]?token)',
            'mailchimp': r'(?i)(mailchimp[_-]?(api[_-]?key|token|secret))',
            'npm': r'(?i)(npm[_-]?(token|key|secret|auth[_-]?token))',
            'openai': r'(?i)(openai[_-]?(api[_-]?key|secret[_-]?key|token))',
            'private_key': r'(?i)(private[_-]?key|rsa[_-]?private|ec[_-]?private)',
            'pypi': r'(?i)(pypi[_-]?(token|api[_-]?token|upload[_-]?token))',
            'sendgrid': r'(?i)(sendgrid[_-]?(api[_-]?key|token|secret))',
            'slack': r'(?i)(slack[_-]?(token|api[_-]?token|bot[_-]?token|webhook))',
            'softlayer': r'(?i)(softlayer[_-]?(api[_-]?key|username|secret))',
            'square': r'(?i)(square[_-]?(access[_-]?token|oauth[_-]?token|api[_-]?key))',
            'stripe': r'(?i)(stripe[_-]?(api[_-]?key|secret[_-]?key|publishable[_-]?key))',
            'telegram': r'(?i)(telegram[_-]?bot[_-]?token)',
            'twilio': r'(?i)(twilio[_-]?(auth[_-]?token|api[_-]?key|account[_-]?sid))'
        }

    def _get_remediation(self, vuln_type: str) -> str:
        remediation_tips = {
            'password': """
- Use environment variables (os.environ['PASSWORD'])
- Use secure configuration management tools
- Consider using a secrets management service
- Never hardcode passwords in source code""",

            'api_key': """
- Store API keys in environment variables
- Use a configuration file that is not in version control
- Consider using a secrets management service
- Implement API key rotation""",

            'token': """
- Use environment variables for tokens
- Implement token refresh mechanisms
- Store tokens securely using a secrets manager
- Never commit tokens to version control""",

            'auth': """
- Use environment variables for authentication credentials
- Implement proper authentication workflows
- Consider using OAuth or similar protocols
- Use secure credential storage""",

            'database': """
- Use environment variables for database credentials
- Consider using connection pooling
- Use a secrets management service
- Implement database credential rotation""",

            'credentials': """
- Use environment variables
- Implement secure credential management
- Use encryption for sensitive data
- Consider using a secrets management service""",

            'artifactory': """
- Store Artifactory credentials in environment variables
- Use credential plugins for CI/CD systems
- Implement regular key rotation
- Use a secrets management service""",

            'aws': """
- Use AWS Secrets Manager or Parameter Store
- Implement IAM roles instead of static credentials
- Enable key rotation
- Never hardcode AWS credentials""",

            'azure_storage': """
- Use Azure Key Vault for credential storage
- Implement Managed Identities where possible
- Enable key rotation
- Use connection strings from environment variables""",

            'basic_auth': """
- Avoid using Basic Auth when possible
- Use token-based authentication instead
- If required, store credentials in environment variables
- Consider using OAuth 2.0""",

            'cloudant': """
- Use IAM authentication when possible
- Store credentials in environment variables
- Implement regular key rotation
- Use a secrets management service""",

            'discord': """
- Store bot tokens in environment variables
- Implement token rotation
- Use a secrets management service
- Never commit tokens to version control""",

            'github': """
- Use GITHUB_TOKEN in GitHub Actions
- Store PATs in environment variables
- Implement regular token rotation
- Use limited-scope tokens""",

            'gitlab': """
- Use CI/CD variables for GitLab pipelines
- Store tokens in environment variables
- Implement regular token rotation
- Use project-specific tokens""",

            'base64_entropy': """
- Avoid storing encoded secrets in code
- Use environment variables
- Implement proper encryption
- Use a secrets management service""",

            'hex_entropy': """
- Avoid storing encoded secrets in code
- Use environment variables
- Implement proper encryption
- Use a secrets management service""",

            'ibm_cloud': """
- Use IBM Cloud Secrets Manager
- Implement IAM authentication
- Enable key rotation
- Use environment variables""",

            'ibm_cos': """
- Use IBM Cloud Object Storage credentials properly
- Implement HMAC authentication correctly
- Store credentials in environment variables
- Enable key rotation""",

            'ip_public': """
- Avoid hardcoding IP addresses
- Use DNS names where possible
- Implement proper network security
- Use configuration management""",

            'jwt': """
- Store JWT secrets in environment variables
- Implement proper token validation
- Use short expiration times
- Rotate signing keys regularly""",

            'mailchimp': """
- Store API keys in environment variables
- Implement API key rotation
- Use minimal-access API keys
- Use a secrets management service""",

            'npm': """
- Use .npmrc for token storage
- Store tokens in environment variables
- Use scoped tokens when possible
- Implement regular token rotation""",

            'openai': """
- Store API keys in environment variables
- Use organization-specific API keys
- Implement key rotation
- Monitor API key usage""",

            'private_key': """
- Never store private keys in code
- Use secure key storage solutions
- Implement key rotation
- Use environment variables""",

            'pypi': """
- Use environment variables for PyPI tokens
- Implement token rotation
- Use scoped tokens when possible
- Never commit tokens to source code""",

            'sendgrid': """
- Store API keys in environment variables
- Use restricted access API keys
- Implement key rotation
- Monitor API key usage""",

            'slack': """
- Store bot tokens in environment variables
- Use workspace-specific tokens
- Implement token rotation
- Use minimal required scopes""",

            'softlayer': """
- Store API credentials in environment variables
- Implement credential rotation
- Use a secrets management service
- Monitor API usage""",

            'square': """
- Use environment variables for tokens
- Implement OAuth flows properly
- Store refresh tokens securely
- Use sandbox credentials for testing""",

            'stripe': """
- Use environment variables for API keys
- Separate test and production keys
- Implement key rotation
- Use restricted API keys""",

            'telegram': """
- Store bot tokens in environment variables
- Implement token rotation
- Use a secrets management service
- Never commit tokens to code""",

            'twilio': """
- Store credentials in environment variables
- Use restricted API keys
- Implement key rotation
- Monitor API usage"""
        }

        return remediation_tips.get(vuln_type, "- Use secure credential management practices\n- Never hardcode sensitive information")

    def analyze_file(self, file_path: str) -> List[Dict]:
        vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                lines = content.splitlines()

                for line_no, line in enumerate(lines, start=1):
                    for vuln_type, pattern in self.vulnerable_patterns.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            remediation = self._get_remediation(vuln_type)
                            vulnerabilities.append({
                                'line_no': line_no,
                                'line': line.strip(),
                                'type': vuln_type,
                                'remediation': remediation
                            })
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
        return vulnerabilities

    def _display_results(self, vulnerabilities: List[VulnerabilityResult]) -> None:
        if not vulnerabilities:
            print("No hardcoded credentials found.")
            return

        print("\n=== Hardcoded Credentials Detection Results ===\n")
        for result in vulnerabilities:
            print(f"Line {result.line_no}: {result.line}")
            print(f"Vulnerability Type: {result.vulnerability}")
            print("Remediation:")
            print(result.remediation)
            print("-" * 50 + "\n")