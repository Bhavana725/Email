import re
from typing import List, Dict

class VulnerabilityResult:
    def __init__(self, line_no: int, line: str, vulnerability: str, remediation: str):
        self.line_no = line_no
        self.line = line
        self.vulnerability = vulnerability
        self.remediation = remediation

class WeakCryptoScanner:
    def __init__(self):
        # Known weak crypto patterns
        self.weak_patterns = {
            'md5': r'hashlib\.md5|MD5|md5|MessageDigest5',
            'sha1': r'hashlib\.sha1|SHA1|sha1|SHA-1',
            'des': r'Crypto\.Cipher\.DES|DES\.|des\.|DATA_ENCRYPTION_STANDARD',
            'rc4': r'Crypto\.Cipher\.ARC4|RC4|rc4|ARCFOUR|ARC4|RC4_DROP',
            'blowfish': r'Crypto\.Cipher\.Blowfish|Blowfish|blowfish|BLOWFISH',
            'simple_des': r'pyDes\.des|simple_des|SimpleDES|BasicDES',
            'weak_random': r'random\.|Random\.|randint|randrange|choice|shuffle',
            'base64': r'base64\.b64encode|base64\.b64decode|base64\.standard_b64encode|base64\.standard_b64decode|base64\.urlsafe_b64encode|base64\.urlsafe_b64decode',
            'urandom': r'os\.urandom|random\.SystemRandom',
            'weak_key_size': r'key_size=(?:40|56|64|80|96|112|128)|keysize=(?:40|56|64|80|96|112|128)',
            'ecb_mode': r'MODE_ECB|ECB|electronic_codebook|ECB_MODE',
            'weak_pbkdf': r'PBKDF1|pbkdf1|PBKDF|pbkdf|single_round_pbkdf',
            'basic_cesar': r'chr\(\w+\s*[+\-]\s*\d+\)|rot13|caesar_cipher|shift_cipher',
            'custom_crypto': r'my_encrypt|my_decrypt|custom_encrypt|custom_decrypt|simple_encrypt|simple_decrypt|basic_encrypt|basic_decrypt|home_encrypt|home_decrypt',
            'weak_hash': r'adler32|crc32|fletcher|luhn|weak_hash|simple_hash',
            'rc2': r'RC2|rc2|RC2Cipher|RC2_decrypt|RC2_encrypt',
            'rc5': r'RC5|rc5|RC5Cipher|RC5_decrypt|RC5_encrypt',
            'rc6': r'RC6|rc6|RC6Cipher|RC6_decrypt|RC6_encrypt',
            'tea': r'TEA|tea|TinyEncryption|tiny_encrypt|XTEA|xTEA',
            'skipjack': r'SKIPJACK|skipjack|SkipjackCipher|skipjack_decrypt',
            'weakaes': r'AES128|aes128|AES_128|weak_aes|simple_aes',
            'null_cipher': r'NullCipher|null_cipher|pass_through|no_encryption',
            'xor_cipher': r'xor_encrypt|xor_decrypt|simple_xor|basic_xor',
            'broken_hash': r'broken_hash|quick_hash|fast_hash|unsafe_hash',
            'single_des': r'single_des|SingleDES|basic_des|simple_des_encrypt',
            'double_des': r'double_des|DoubleDES|2des|DOUBLE_DES',
            'triple_des_2key': r'triple_des_2key|TripleDES2Key|3des_2key|weak_triple_des',
            'gost': r'GOST|gost|GOST89|gost89|GOST_89',
            'idea': r'IDEA|idea|IDEACipher|idea_decrypt|idea_encrypt',
            'cast5': r'CAST5|cast5|CAST_5|cast_5|CAST128',
            'safer': r'SAFER|safer|SAFER_K|SAFER_SK|safer_encrypt',
            'panama': r'PANAMA|panama|PanamaCipher|panama_hash',
            'weak_ecc': r'weak_ecc|small_curve|unsafe_curve|p192|secp192',
            'md2': r'MD2|md2|MESSAGE_DIGEST_2|Md2|mD2',
            'md4': r'MD4|md4|MESSAGE_DIGEST_4|Md4|mD4',
            'haval': r'HAVAL|haval|Haval|HAVAL_HASH|haval_digest',
            'panama_hash': r'PANAMA_HASH|panama_hash|PanamaHash|panama_digest',
            'tiger': r'TIGER|tiger|Tiger|tiger_hash|tiger_digest',
            'whirlpool': r'WHIRLPOOL|whirlpool|Whirlpool|whirl_hash',
            'snefru': r'SNEFRU|snefru|Snefru|snefru_hash',
            'ripemd': r'RIPEMD|ripemd|ripemd128|ripemd256|ripemd320',
            'weak_dsa': r'DSA_512|dsa_512|DSA512|weak_dsa|small_dsa',
            'weak_rsa': r'RSA_512|rsa_512|RSA512|weak_rsa|small_rsa',
            'seed': r'SEED|seed|SEEDCipher|seed_encrypt|seed_decrypt',
            'anubis': r'ANUBIS|anubis|AnubisCipher|anubis_encrypt',
            'khazad': r'KHAZAD|khazad|KhazadCipher|khazad_encrypt',
            'noekeon': r'NOEKEON|noekeon|NoekeonCipher|noekeon_encrypt',
            'weak_curve25519': r'weak_curve25519|unsafe_curve25519|small_curve25519',
            'weak_ed25519': r'weak_ed25519|unsafe_ed25519|small_ed25519',
            'magma': r'MAGMA|magma|MagmaCipher|magma_encrypt',
            'misty1': r'MISTY1|misty1|Misty1Cipher|misty1_encrypt',
            'square': r'SQUARE|square|SquareCipher|square_encrypt',
            'mars': r'MARS|mars|MarsCipher|mars_encrypt',
            'present': r'PRESENT|present|PresentCipher|present_encrypt',
            'shacal': r'SHACAL|shacal|ShacalCipher|shacal_encrypt',
            'shark': r'SHARK|shark|SharkCipher|shark_encrypt',
            'kasumi': r'KASUMI|kasumi|KasumiCipher|kasumi_encrypt',
            'multi2': r'MULTI2|multi2|Multi2Cipher|multi2_encrypt',
            'weak_camellia': r'CAMELLIA128|camellia128|weak_camellia|small_camellia',
            'null_hash': r'NullHash|null_hash|pass_through_hash|no_hash',
            'custom_hash': r'my_hash|custom_hash|home_hash|simple_hash',
            'weak_hmac': r'weak_hmac|small_hmac|fast_hmac|quick_hmac',
            'broken_mac': r'broken_mac|weak_mac|simple_mac|basic_mac',
            'linear_prng': r'LinearPRNG|linear_prng|simple_prng|basic_rng',
            'mersenne': r'MersenneTwister|mersenne|MT19937|random_mt',
            'dual_ec': r'DualEC|dual_ec|DualECDRBG|dual_ec_prng',
            'broken_oaep': r'broken_oaep|weak_oaep|simple_oaep|basic_oaep',
            'broken_pss': r'broken_pss|weak_pss|simple_pss|basic_pss',
            'custom_kdf': r'custom_kdf|my_kdf|simple_kdf|basic_kdf',
            'weak_scrypt': r'weak_scrypt|fast_scrypt|quick_scrypt|simple_scrypt',
            'weak_bcrypt': r'weak_bcrypt|fast_bcrypt|quick_bcrypt|simple_bcrypt',
            'weak_argon2': r'weak_argon2|fast_argon2|quick_argon2|simple_argon2',
            'broken_srp': r'broken_srp|weak_srp|simple_srp|basic_srp',
            'insecure_dh': r'weak_dh|small_dh|unsafe_dh|simple_dh',
            'custom_prng': r'custom_prng|my_prng|home_prng|basic_prng',
            'linear_congruential': r'LinearCongruential|linear_congruential|lcg|LCG',
            'weak_elgamal': r'weak_elgamal|small_elgamal|unsafe_elgamal|simple_elgamal',
            'broken_pake': r'broken_pake|weak_pake|simple_pake|basic_pake',
            'custom_signature': r'custom_signature|my_signature|home_signature|basic_signature'
        }

        # Remediation suggestions for each pattern
        self.remediations = {
            'md5': ' Use SHA-256 or better hash functions. Consider SHA-3 for future-proof security',
            'sha1': 'Use SHA-256 or SHA-3. SHA-1 is cryptographically broken',
            'des': 'Use AES-256 in CBC/GCM mode. DES is considered cryptographically broken',
            'rc4': 'Use AES in CBC/GCM mode. RC4 has known vulnerabilities',
            'blowfish': 'Use AES-256 in CBC/GCM mode. Blowfish has known weaknesses',
            'simple_des': 'Use AES with proper mode. Simple DES implementations are insecure',
            'weak_random': 'Use secrets module for cryptographic operations. Standard random is not cryptographically secure',
            'base64': 'Base64 is encoding not encryption. Use proper encryption like AES',
            'urandom': 'Use secrets.token_bytes() for cryptographic operations instead of os.urandom',
            'weak_key_size': 'Use minimum 256-bit keys for symmetric encryption. Smaller keys are vulnerable',
            'ecb_mode': 'Use CBC/GCM mode instead of ECB. ECB mode reveals patterns in data',
            'weak_pbkdf': 'Use PBKDF2 with high iterations (100k+) or better KDFs like Argon2',
            'basic_cesar': 'Use standard crypto libraries instead of custom ciphers. Caesar ciphers are trivially broken',
            'custom_crypto': 'Avoid custom crypto implementations, use standard libraries and algorithms',
            'weak_hash': 'Use cryptographically secure hash functions like SHA-256 or SHA-3',
            'rc2': 'Use AES-256. RC2 is obsolete and cryptographically broken',
            'rc5': 'Use AES-256. RC5 has known vulnerabilities',
            'rc6': 'Use AES-256. RC6 is not widely validated',
            'tea': 'Use AES-256. TEA has known weaknesses',
            'skipjack': 'Use AES-256. Skipjack is obsolete and weak',
            'weakaes': 'Use AES-256 with proper mode of operation and key size',
            'null_cipher': 'Use proper encryption. Null ciphers provide no security',
            'xor_cipher': 'Use standard encryption. XOR ciphers are trivially broken',
            'broken_hash': 'Use cryptographically secure hash functions like SHA-256/SHA-3',
            'single_des': 'Use AES-256. Single DES is broken',
            'double_des': 'Use AES-256. Double DES is vulnerable to meet-in-the-middle attacks',
            'triple_des_2key': 'Use AES-256. 2-key Triple DES has known weaknesses',
            'gost': 'Use modern standard algorithms like AES-256',
            'idea': 'Use AES-256. IDEA is dated and has patents',
            'cast5': 'Use AES-256. CAST5 is dated',
            'safer': 'Use AES-256. SAFER is dated',
            'panama': 'Use modern standard hash functions',
            'weak_ecc': 'Use strong elliptic curves like Curve25519',
            'md2': 'Use SHA-256/SHA-3. MD2 is cryptographically broken',
            'md4': 'Use SHA-256/SHA-3. MD4 is cryptographically broken',
            'haval': 'Use modern hash functions like SHA-256/SHA-3',
            'panama_hash': 'Use standard cryptographic hash functions',
            'tiger': 'Use SHA-256/SHA-3. Tiger is dated',
            'whirlpool': 'Use SHA-256/SHA-3 for better compatibility',
            'snefru': 'Use modern standard hash functions',
            'ripemd': 'Use SHA-256/SHA-3. RIPEMD variants are dated',
            'weak_dsa': 'Use 3072-bit DSA keys or better, or switch to EdDSA',
            'weak_rsa': 'Use minimum 3072-bit RSA keys',
            'seed': 'Use AES-256 for better compatibility and security',
            'anubis': 'Use standard algorithms like AES-256',
            'khazad': 'Use well-analyzed algorithms like AES-256',
            'noekeon': 'Use standard algorithms like AES-256',
            'weak_curve25519': 'Use proper Curve25519 implementation with correct key validation',
            'weak_ed25519': 'Use proper Ed25519 implementation with secure key generation',
            'magma': 'Use AES-256 for better security and compatibility',
            'misty1': 'Use standard algorithms like AES-256',
            'square': 'Use well-analyzed algorithms like AES-256',
            'mars': 'Use AES-256, a more widely validated algorithm',
            'present': 'Use AES-256 instead of lightweight ciphers',
            'shacal': 'Use standard encryption algorithms like AES-256',
            'shark': 'Use modern standard algorithms like AES-256',
            'kasumi': 'Use AES-256 for better security',
            'multi2': 'Use standard algorithms like AES-256',
            'weak_camellia': 'Use Camellia-256 or AES-256',
            'null_hash': 'Use proper cryptographic hash functions',
            'custom_hash': 'Use standard cryptographic hash functions, avoid custom implementations',
            'weak_hmac': 'Use HMAC with strong hash functions like SHA-256/SHA-3',
            'broken_mac': 'Use standard MAC algorithms like HMAC-SHA256',
            'linear_prng': 'Use cryptographically secure random number generators',
            'mersenne': 'Use cryptographically secure random number generators like secrets module',
            'dual_ec': 'Avoid Dual_EC_DRBG, use platform crypto RNG',
            'broken_oaep': 'Use standard OAEP padding with proper parameters',
            'broken_pss': 'Use standard PSS padding with proper parameters',
            'custom_kdf': 'Use standard KDFs like PBKDF2, Argon2, or scrypt',
            'weak_scrypt': 'Use proper scrypt parameters (N>16384, r>8, p>1)',
            'weak_bcrypt': 'Use bcrypt with work factor >12',
            'weak_argon2': 'Use Argon2id with proper memory, iterations and parallelism parameters',
            'broken_srp': 'Use standard SRP implementation with proper parameters',
            'insecure_dh': 'Use minimum 3072-bit DH groups or elliptic curve DH',
            'custom_prng': 'Use platform crypto RNG or secrets module',
            'linear_congruential': 'Use cryptographically secure RNG, not LCG',
            'weak_elgamal': 'Use minimum 3072-bit keys or switch to modern algorithms',
            'broken_pake': 'Use standard PAKE protocols like SRP or OPAQUE',
            'custom_signature': 'Use standard digital signature algorithms like Ed25519 or RSA-PSS'
        }

    def analyze_file(self, file_path: str) -> List[VulnerabilityResult]:
        """Analyze file for weak cryptography patterns"""
        vulnerabilities = []
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                vulnerabilities = self._check_patterns(content)
            return vulnerabilities
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return []

    def _check_patterns(self, content: str) -> List[VulnerabilityResult]:
        """Check content for weak crypto patterns"""
        lines = content.split('\n')
        found_vulnerabilities = []

        for idx, line in enumerate(lines, 1):
            for pattern_name, pattern in self.weak_patterns.items():
                if re.search(pattern, line):
                    found_vulnerabilities.append(VulnerabilityResult(
                        line_no=idx,
                        line=line.strip(),
                        vulnerability=pattern_name,
                        remediation=self.remediations.get(pattern_name, "No remediation available.")
                    ))

        return found_vulnerabilities

    def display_results(self, vulnerabilities: List[VulnerabilityResult]) -> None:
        """Display found vulnerabilities and remediations"""
        if not vulnerabilities:
            print("No weak cryptography patterns found.")
            return

        print("\n=== Weak Cryptography Detection Results ===\n")
        for result in vulnerabilities:
            print(f"Vulnerability: {result.vulnerability}")
            print(f"Line {result.line_no}: {result.line}")
            print(f"Remediation: {result.remediation}")
            print("-" * 50 + "\n")