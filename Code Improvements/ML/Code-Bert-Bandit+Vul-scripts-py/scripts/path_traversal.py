import os
import re
from typing import List, Dict

class PathTraversalDetector:
    def __init__(self):
        # Define patterns for dangerous file and path operations
        self.patterns = [
            ("open", r"open\("),
            ("file", r"file\("),
            ("read", r"\.read\("),
            ("write", r"\.write\("),
            ("join", r"os\.path\.join\("),
            ("mkdir", r"os\.mkdir\("),
            ("rmdir", r"os\.rmdir\("),
            ("unlink", r"os\.unlink\("),
            ("symlink", r"os\.symlink\("),
            ("chmod", r"os\.chmod\("),
            ("chown", r"os\.chown\("),
            ("rename", r"os\.rename\("),
            ("remove", r"os\.remove\("),
            ("copy", r"shutil\.copy\("),
            ("copytree", r"shutil\.copytree\("),
            ("move", r"shutil\.move\("),
            ("glob", r"glob\.glob\("),
            ("walk", r"os\.walk\("),
            ("listdir", r"os\.listdir\("),
            ("scandir", r"os\.scandir\("),
            ("access", r"os\.access\("),
            ("stat", r"os\.stat\("),
            ("readlink", r"os\.readlink\("),
            ("truncate", r"os\.truncate\("),
            ("utime", r"os\.utime\("),
            ("exists", r"os\.path\.exists\("),
            ("lexists", r"os\.path\.lexists\("),
            ("isfile", r"os\.path\.isfile\("),
            ("isdir", r"os\.path\.isdir\("),
            ("islink", r"os\.path\.islink\("),
            ("ismount", r"os\.path\.ismount\("),
            ("expanduser", r"os\.path\.expanduser\("),
            ("expandvars", r"os\.path\.expandvars\("),
            ("normcase", r"os\.path\.normcase\("),
            ("normpath", r"os\.path\.normpath\("),
            ("abspath", r"os\.path\.abspath\("),
            ("realpath", r"os\.path\.realpath\("),
            ("relpath", r"os\.path\.relpath\("),
            ("samefile", r"os\.path\.samefile\("),
            ("getcwd", r"os\.getcwd\("),
            ("chdir", r"os\.chdir\("),
            ("fchdir", r"os\.fchdir\("),
            ("splitdrive", r"os\.path\.splitdrive\("),
            ("basename", r"os\.path\.basename\("),
            ("dirname", r"os\.path\.dirname\("),
            ("split", r"os\.path\.split\("),
            ("splitext", r"os\.path\.splitext\("),
            ("commonprefix", r"os\.path\.commonprefix\("),
            ("commonpath", r"os\.path\.commonpath\("),
            ("loads", r"json\.loads\("),
            ("dumps", r"json\.dumps\("),
            ("load", r"json\.load\("),
            ("dump", r"json\.dump\("),
            ("pickle_loads", r"pickle\.loads\("),
            ("pickle_dumps", r"pickle\.dumps\("),
            ("pickle_load", r"pickle\.load\("),
            ("pickle_dump", r"pickle\.dump\("),
            ("marshal", r"marshal\.dumps\("),
            ("unmarshal", r"marshal\.loads\("),
            ("shelve", r"shelve\.open\("),
            ("dbm", r"dbm\.open\("),
            ("gzip", r"gzip\.open\("),
            ("bz2", r"bz2\.open\("),
            ("zipfile", r"zipfile\.ZipFile\("),
            ("tarfile", r"tarfile\.open\("),
            ("mkstemp", r"tempfile\.mkstemp\("),
            ("mkdtemp", r"tempfile\.mkdtemp\("),
            ("template", r"string\.Template\("),
            ("fileinput", r"fileinput\.input\("),
            ("stringio", r"io\.StringIO\("),
            ("bytesio", r"io\.BytesIO\("),
            ("textiowrapper", r"io\.TextIOWrapper\("),
            ("rawiobase", r"io\.RawIOBase\("),
            ("bufferediobase", r"io\.BufferedIOBase\("),
            ("textiobase", r"io\.TextIOBase\("),
            ("seek", r"\.seek\("),
            ("tell", r"\.tell\("),
            ("truncate", r"\.truncate\("),
            ("flush", r"\.flush\("),
            ("close", r"\.close\("),
            ("readable", r"\.readable\("),
            ("writable", r"\.writable\("),
            ("seekable", r"\.seekable\("),
            ("fileno", r"\.fileno\("),
            ("isatty", r"\.isatty\("),
            ("readline", r"\.readline\("),
            ("readlines", r"\.readlines\("),
            ("writelines", r"\.writelines\("),
            ("encoding", r"\.encoding"),
            ("errors", r"\.errors"),
            ("newlines", r"\.newlines"),
            ("next", r"\.next\("),
            ("readinto", r"\.readinto\("),
            ("write_eof", r"\.write_eof\("),
            ("getvalue", r"\.getvalue\("),
            ("getbuffer", r"\.getbuffer\("),
            ("detach", r"\.detach\("),
            ("reconfigure", r"\.reconfigure\("),
            ("seek_end", r"\.seek_end\("),
            ("peek", r"\.peek\(")
        ]

        # Remediation messages for each vulnerability type
        self.remediations = {
            "open": "Validate and sanitize file paths before opening files. Use os.path.abspath() and os.path.normpath() to resolve paths safely.",
            "file": "Ensure file paths are within allowed directories. Use allowlists and path validation.",
            "read": "Implement strict input validation and proper path sanitization before reading files.",
            "write": "Restrict file write operations to specific allowed directories. Validate paths thoroughly.",
            "join": "Use os.path.join() safely and validate path components before joining.",
            "mkdir": "Validate directory creation paths and permissions. Use secure default umask.",
            "rmdir": "Carefully validate paths before directory removal. Check for traversal attempts.",
            "unlink": "Verify file paths before deletion. Implement proper access controls.",
            "symlink": "Validate both target and link paths. Resolve symlinks safely.",
            "chmod": "Restrict chmod operations to specific directories. Validate paths and permissions.",
            "chown": "Carefully validate ownership changes. Implement proper access controls.",
            "rename": "Validate source and destination paths. Check for directory traversal.",
            "remove": "Implement secure file removal. Validate paths thoroughly.",
            "copy": "Validate source and destination paths for copy operations.",
            "copytree": "Secure recursive directory copying. Validate all paths.",
            "move": "Validate move operations. Check source and destination paths.",
            "glob": "Restrict glob patterns. Validate paths before expansion.",
            "walk": "Validate directory traversal in walk operations.",
            "listdir": "Secure directory listing. Validate path inputs.",
            "scandir": "Implement secure directory scanning. Validate paths.",
            "access": "Validate paths before checking permissions.",
            "stat": "Secure file status checks. Validate file paths.",
            "readlink": "Safely resolve symbolic links. Validate paths.",
            "truncate": "Validate paths before file truncation.",
            "utime": "Secure timestamp modifications. Validate paths.",
            "exists": "Validate paths before existence checks.",
            "lexists": "Safely check path existence. Validate inputs.",
            "isfile": "Validate paths for file checks.",
            "isdir": "Secure directory validation. Check paths.",
            "islink": "Safely validate symbolic links.",
            "ismount": "Validate mount point checks.",
            "expanduser": "Safely expand user paths.",
            "expandvars": "Validate environment variable expansion.",
            "normcase": "Normalize paths securely.",
            "normpath": "Implement secure path normalization.",
            "abspath": "Use absolute paths safely.",
            "realpath": "Resolve real paths securely.",
            "relpath": "Validate relative path calculations.",
            "samefile": "Secure file comparison. Validate paths.",
            "getcwd": "Validate current working directory.",
            "chdir": "Secure directory changes. Validate paths.",
            "fchdir": "Validate directory changes by fd.",
            "splitdrive": "Validate drive splitting.",
            "basename": "Validate path components.",
            "dirname": "Secure directory name handling.",
            "split": "Validate path splitting.",
            "splitext": "Secure extension splitting.",
            "commonprefix": "Validate common prefix calculations.",
            "commonpath": "Secure common path resolution.",
            "loads": "Validate deserialization inputs.",
            "dumps": "Secure serialization handling.",
            "load": "Validate file loading operations.",
            "dump": "Secure file dumping operations.",
            "pickle_loads": "Implement secure pickling.",
            "pickle_dumps": "Secure pickling operations.",
            "pickle_load": "Validate unpickling operations.",
            "pickle_dump": "Secure pickling operations.",
            "marshal": "Secure data marshalling.",
            "unmarshal": "Validate unmarshalling inputs.",
            "shelve": "Secure shelf file operations.",
            "dbm": "Validate database operations.",
            "gzip": "Secure gzip compression.",
            "bz2": "Validate bzip2 operations.",
            "zipfile": "Secure zip file handling.",
            "tarfile": "Validate tar operations.",
            "mkstemp": "Validate temp file creation.",
            "mkdtemp": "Secure temp directory creation.",
            "template": "Validate template operations.",
            "fileinput": "Secure file input handling.",
            "stringio": "Secure string I/O operations.",
            "bytesio": "Validate bytes I/O handling.",
            "textiowrapper": "Secure text I/O operations.",
            "rawiobase": "Validate raw I/O handling.",
            "bufferediobase": "Secure buffered I/O.",
            "textiobase": "Validate text I/O base operations.",
            "seek": "Secure seek operations.",
            "tell": "Validate file position.",
            "truncate": "Secure file truncation.",
            "flush": "Validate buffer flushing.",
            "close": "Secure file closing.",
            "readable": "Secure read operations.",
            "writable": "Validate write operations.",
            "seekable": "Secure seek operations.",
            "fileno": "Validate file descriptors.",
            "isatty": "Secure terminal checks.",
            "readline": "Validate line reading.",
            "readlines": "Secure multiple line reads.",
            "writelines": "Validate line writing.",
            "encoding": "Secure encoding handling.",
            "errors": "Validate error handling.",
            "newlines": "Secure newline handling."
        }

    def analyze_code(self, code: str) -> List[Dict[str, str]]:
        found_vulnerabilities = []
        code_lines = code.splitlines()
        for line_number, line in enumerate(code_lines, start=1):
            for pattern_type, pattern in self.patterns:
                if re.search(pattern, line):
                    found_vulnerabilities.append({
                        'line': line_number,
                        'code': line.strip(),
                        'type': pattern_type
                    })
        return found_vulnerabilities

    def analyze_file(self, file_path: str) -> List[Dict[str, str]]:
        try:
            with open(file_path, 'r') as file:
                code = file.read()
                return self.analyze_code(code)
        except FileNotFoundError:
            print(f"File {file_path} not found.")
            return []
        except Exception as e:
            print(f"Error reading file: {e}")
            return []

    def display_results(self, vulnerabilities: List[Dict[str, str]]) -> None:
        if not vulnerabilities:
            print("No path traversal vulnerabilities found.")
            return

        print("\n=== Path Traversal Vulnerability Detection Results ===\n")
        for vuln in sorted(vulnerabilities, key=lambda x: x["line"]):
            print(f"Type: {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['code']}")
            print("Remediation:")
            print(self.remediations.get(vuln['type'], "No specific remediation available."))
            print("-" * 50 + "\n")