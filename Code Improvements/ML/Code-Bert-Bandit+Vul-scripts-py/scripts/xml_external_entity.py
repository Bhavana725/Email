import re
import os
from typing import List, Dict, Set

class XXEDetector:
    def __init__(self):
        # Comprehensive patterns that might indicate XXE vulnerability
        self.xxe_patterns = {
            # Standard XML Processing
            r'xml\.etree\.ElementTree\.parse',
            r'xml\.etree\.ElementTree\.iterparse',
            r'xml\.etree\.ElementTree\.XMLParser',
            r'xml\.etree\.ElementTree\.fromstring',
            r'xml\.dom\.minidom\.parse',
            r'xml\.dom\.minidom\.parseString',
            r'xml\.sax\.parse',
            r'xml\.sax\.parseString',
            r'xml\.sax\.make_parser',
            r'xml\.dom\.pulldom\.parse',
            r'xml\.dom\.pulldom\.parseString',
            
            # LXML Library
            r'lxml\.etree\.parse',
            r'lxml\.etree\.fromstring',
            r'lxml\.etree\.XML',
            r'lxml\.etree\.XMLParser',
            r'lxml\.etree\.iterparse',
            r'lxml\.html\.fromstring',
            r'lxml\.html\.parse',
            
            # xmltodict
            r'xmltodict\.parse',
            r'xmltodict\.unparse',
            
            # BeautifulSoup XML Parser
            r'BeautifulSoup',
            r'xml\.parser',
            
            # Common XML-RPC
            r'xmlrpc\.client\.ServerProxy',
            r'xmlrpc\.client\.Transport',
            r'xmlrpclib\.ServerProxy',
            
            # Other Common XML Operations
            r'ElementTree\.parse',
            r'ElementTree\.fromstring',
            r'minidom\.parse',
            r'parsexml',
            r'parseString',
            r'fromstring',
            r'parse',
            r'parseFile',
            r'parseXML',
            r'loadXML',
            r'parseDOM',
            r'parseDocument',
            
            # SAX Parser related
            r'SAXParser',
            r'SAXReader',
            r'createXMLReader',
            
            # DOM Parser related
            r'DOMParser',
            r'DocumentBuilder',
            r'XMLReader',
            
            # Database XML Processing
            r'executeXMLQuery',
            r'xml\.xpath',
            r'xpath\.eval',
            
            # Custom XML Processing
            r'processXML',
            r'readXML',
            r'loadXMLFile',
            r'parseXMLFile',
            r'parseXMLString'
        }

        # Detailed remediation messages for different XXE patterns
        self.remediation_messages = {
            'general': (
                "1. Use defusedxml library instead of standard XML parsers\n"
                "2. Disable XML external entity processing:\n"
                "   - parser.setFeature(feature.EXTERNAL_GENERAL_ENTITIES, False)\n"
                "   - parser.setFeature(feature.EXTERNAL_PARAMETER_ENTITIES, False)\n"
                "3. Implement XML parsing in a sandbox environment\n"
                "4. Validate and sanitize XML input before processing\n"
                "5. Use XML Schema validation\n"
                "6. Consider using JSON or other formats instead of XML"
            ),
            
            'lxml': (
                "1. Use secure parser settings:\n"
                "   parser = etree.XMLParser(\n"
                "       resolve_entities=False,\n"
                "       no_network=True,\n"
                "       collect_ids=False\n"
                "   )\n"
                "2. Use defusedxml.lxml instead\n"
                "3. Implement content security policy\n"
                "4. Add input validation for XML content"
            ),
            
            'elementtree': (
                "1. Replace with defusedxml.ElementTree\n"
                "2. Configure secure parser:\n"
                "   parser = XMLParser(\n"
                "       resolve_entities=False,\n"
                "       load_dtd=False\n"
                "   )\n"
                "3. Implement proper error handling\n"
                "4. Validate XML against schema before parsing"
            ),
            
            'sax': (
                "1. Use defusedxml.sax instead\n"
                "2. Configure parser features:\n"
                "   parser.setFeature(handler.feature_external_ges, False)\n"
                "   parser.setFeature(handler.feature_external_pes, False)\n"
                "3. Implement custom EntityResolver\n"
                "4. Add proper exception handling"
            ),
            
            'dom': (
                "1. Use defusedxml.minidom\n"
                "2. Disable entity resolution:\n"
                "   parser = xml.dom.minidom.parse(source, parser=custom_secure_parser)\n"
                "3. Implement secure parsing wrapper\n"
                "4. Validate document size before parsing"
            ),
            
            'beautifulsoup': (
                "1. Use lxml parser with secure settings\n"
                "2. Specify parser explicitly:\n"
                "   BeautifulSoup(markup, 'lxml-xml', parser=secure_parser)\n"
                "3. Implement input sanitization\n"
                "4. Add size restrictions for parsed documents"
            ),
            
            'xmlrpc': (
                "1. Use alternative transport methods (REST/JSON)\n"
                "2. Implement custom transport class with security measures\n"
                "3. Add input validation layer\n"
                "4. Use HTTPS for transport\n"
                "5. Implement request signing"
            )
        }

    def analyze_file(self, file_path: str) -> List[Dict]:
        """
        Analyze a Python file for XXE vulnerabilities.
        :param file_path: Path to the file to analyze
        :return: List of vulnerabilities found
        """
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return []

        vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

            for line_no, line in enumerate(lines, start=1):
                for pattern in self.xxe_patterns:
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            'type': 'XML External Entity (XXE)',
                            'location': file_path,
                            'line_number': line_no,
                            'vulnerability_type': pattern,
                            'remediation': self._get_remediation(pattern)
                        })

            return vulnerabilities
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return []

    def _get_remediation(self, pattern: str) -> str:
        """
        Get remediation message based on the pattern.
        :param pattern: The pattern that triggered the vulnerability
        :return: Remediation message
        """
        pattern_lower = pattern.lower()
        if 'lxml' in pattern_lower:
            return self.remediation_messages['lxml']
        elif 'elementtree' in pattern_lower:
            return self.remediation_messages['elementtree']
        elif 'sax' in pattern_lower:
            return self.remediation_messages['sax']
        elif 'dom' in pattern_lower:
            return self.remediation_messages['dom']
        elif 'beautifulsoup' in pattern_lower:
            return self.remediation_messages['beautifulsoup']
        elif 'xmlrpc' in pattern_lower:
            return self.remediation_messages['xmlrpc']
        return self.remediation_messages['general']

    def display_results(self, vulnerabilities: List[Dict]) -> None:
        """
        Display the results of the vulnerability scan.
        :param vulnerabilities: List of vulnerabilities found
        """
        if not vulnerabilities:
            print("No XXE vulnerabilities found.")
            return

        print("\n=== XXE Vulnerability Report ===\n")
        for vuln in vulnerabilities:
            print(f"File: {vuln['location']}")
            print(f"Line Number: {vuln['line_number']}")
            print(f"Vulnerable Function: {vuln['vulnerability_type']}")
            print("\nRemediation:")
            print(vuln['remediation'])
            print("-" * 50)