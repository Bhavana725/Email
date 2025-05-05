import os
import sys
from typing import List

class MemoryFlawResult:
    def __init__(self, line_no: int, line: str, flaw: str, remediation: str):
        self.line_no = line_no
        self.line = line
        self.flaw = flaw
        self.remediation = remediation

    def __getitem__(self, key):
        if key == 'line_no':
            return self.line_no
        elif key == 'line':
            return self.line
        elif key == 'flaw':
            return self.flaw
        elif key == 'remediation':
            return self.remediation
        else:
            raise KeyError(f"'{key}' is not a valid attribute")

    def __str__(self):
        return f"Line {self.line_no}: {self.flaw} - {self.line}"

    def __repr__(self):
        return self.__str__()

class MemoryFlawScanner:
    def __init__(self):
        self.memory_flaws = {
            'del ': 'Manual memory deallocation (may not be needed in Python)',
            'gc.collect()': 'Forced garbage collection (can be inefficient)',
            'ctypes.create_string_buffer': 'Unsafe manual memory allocation (potential memory corruption)',
            'ctypes.memmove': 'Unsafe direct memory modification (may cause corruption)',
            'pickle.load': 'Untrusted deserialization (possible memory corruption)',
            'pickle.loads': 'Untrusted deserialization (potential RCE & memory corruption)',
            'shelve.open': 'Persistent object storage (can lead to memory bloat)',
            'json.loads': 'Large JSON object loading (potential memory exhaustion)',
            'numpy.zeros': 'Large zero-initialized NumPy array (can waste memory)',
            'numpy.empty': 'Uninitialized NumPy array (may contain garbage values)',
            'bytearray(': 'Large bytearray allocation (high memory usage risk)',
            'multiprocessing.Queue': 'Large inter-process data sharing (memory bloat risk)',
            'PIL.Image.open': 'Large image loading (ensure proper closing)',
            'open(': 'File not closed properly (resource leak risk)',
            'socket.socket': 'Socket created without closing (potential memory leak)',
            'sqlite3.connect': 'Database connection not closed (can lead to resource exhaustion)',
            'threading.Thread': 'Threads created without proper cleanup (memory leak risk)',
            'append(': 'Appending in loops without pre-allocation (may cause memory fragmentation)',
            '+= ': 'String concatenation in loops (inefficient memory usage)',
            'os.popen': 'Use of os.popen (can cause memory leaks if not closed)',
            'subprocess.Popen': 'Subprocess opened without closing (resource leakage risk)',
        }

        self.remediations = {
            'Manual memory deallocation (may not be needed in Python)': 'Avoid unnecessary "del" statements; Python’s garbage collector handles memory cleanup.',
            'Forced garbage collection (can be inefficient)': 'Avoid calling gc.collect() unless necessary; let Python handle memory management automatically.',
            'Unsafe manual memory allocation (potential memory corruption)': 'Use Python-native memory management instead of ctypes unless absolutely required.',
            'Unsafe direct memory modification (may cause corruption)': 'Avoid direct memory modification unless necessary; prefer safe high-level APIs.',
            'Untrusted deserialization (possible memory corruption)': 'Use safe deserialization methods such as `json.loads()` instead of `pickle.load()` for untrusted data.',
            'Untrusted deserialization (potential RCE & memory corruption)': 'Avoid pickle for untrusted data; prefer safer alternatives like `json` or `marshal`.',
            'Persistent object storage (can lead to memory bloat)': 'Periodically clean up unnecessary objects from shelve storage.',
            'Large JSON object loading (potential memory exhaustion)': 'Use streaming JSON parsers like `ijson` for large files.',
            'Large zero-initialized NumPy array (can waste memory)': 'Consider using sparse matrices if most values are zeros.',
            'Uninitialized NumPy array (may contain garbage values)': 'Use `numpy.zeros()` instead of `numpy.empty()` if values need initialization.',
            'Large bytearray allocation (high memory usage risk)': 'Consider using memory-mapped files (`mmap`) instead of large bytearrays.',
            'Large inter-process data sharing (memory bloat risk)': 'Use shared memory (`multiprocessing.shared_memory`) for large data exchange.',
            'Large image loading (ensure proper closing)': 'Always call `.close()` after opening an image to prevent memory leaks.',
            'File not closed properly (resource leak risk)': 'Use `with open()` instead of manually managing file opening and closing.',
            'Socket created without closing (potential memory leak)': 'Ensure sockets are closed using `.close()` after use.',
            'Database connection not closed (can lead to resource exhaustion)': 'Always close database connections using `.close()` or use context managers.',
            'Threads created without proper cleanup (memory leak risk)': 'Ensure threads are joined using `.join()` to prevent memory buildup.',
            'Appending in loops without pre-allocation (may cause memory fragmentation)': 'Pre-allocate lists when possible to avoid repeated memory reallocations.',
            'String concatenation in loops (inefficient memory usage)': 'Use `str.join()` instead of `+=` for efficient string handling.',
            'Use of os.popen (can cause memory leaks if not closed)': 'Use `subprocess.run()` instead of `os.popen()`.',
            'Subprocess opened without closing (resource leakage risk)': 'Always close subprocesses using `.terminate()` or `.communicate()` after execution.',
        }

    def scan_file(self, file_path: str) -> List[MemoryFlawResult]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        results = []
        seen_flaws = set()
        inside_multiline_comment = False  

        with open(file_path, 'r', encoding="utf-8") as file:
            for line_no, line in enumerate(file, 1):
                stripped_line = line.strip()

                # Detect multi-line comments
                if stripped_line.startswith(("'''", '"""')) and not inside_multiline_comment:
                    inside_multiline_comment = True
                    continue
                elif stripped_line.endswith(("'''", '"""')) and inside_multiline_comment:
                    inside_multiline_comment = False
                    continue

                # Ignore lines inside multi-line comments or starting with "#"
                if inside_multiline_comment or stripped_line.startswith("#"):
                    continue

                # Check for memory flaws
                for pattern, flaw in self.memory_flaws.items():
                    if pattern in stripped_line:
                        unique_key = f"{line_no}:{flaw}"
                        if unique_key not in seen_flaws:
                            seen_flaws.add(unique_key)
                            results.append(MemoryFlawResult(
                                line_no=line_no,
                                line=stripped_line,
                                flaw=flaw,
                                remediation=self.remediations.get(flaw, 'Apply proper memory management techniques')
                            ))
        return results

    def analyze_file(self, file_path: str) -> List[MemoryFlawResult]:
        try:
            return self.scan_file(file_path)
        except Exception as e:
            print(f"Error analyzing file: {str(e)}")
            return []

if __name__ == "__main__":
    scanner = MemoryFlawScanner()
    file_path = sys.argv[1] if len(sys.argv) > 1 else "test_memory.py"

    try:
        results = scanner.analyze_file(file_path)
        if results:
            print(f"Found {len(results)} potential memory flaws:")
            for i, result in enumerate(results, 1):
                print(f"{i}. Line {result.line_no}: {result.flaw}")
                print(f"   Code: {result.line}")
                print(f"   Remediation: {result.remediation}\n")
        else:
            print("No memory flaws detected.")
    except Exception as e:
        print(f"Error: {str(e)}")
