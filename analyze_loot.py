#!/usr/bin/env python3

import os
import zipfile
import tempfile
import re
import json
import csv
import shutil
import sys
import subprocess
from pathlib import Path
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed

import base64
import hashlib
import re
import os
from Crypto.Cipher import DES

init(autoreset=True)

SENSITIVE_PATTERNS = [
    r'password\s*[:=]\s*.*',
    r'username\s*[:=]\s*.*',
    r'user\s*=\s*.*',
    r'secret\s*=\s*.*',
    r'token\s*=\s*.*',
    r'api[-_]?key\s*=\s*.*',
    r'jdbc[:=].*',
    r'\b(datasource|db)\.url\s*=\s*.*',
    r'\b(hibernate|spring)\..*url\s*=\s*.*',
    r'aws.*key.*=.*',
    r'bearer\s+[a-z0-9\-_\.=]+',
    #r'(http|https)://[^\s]+',
    r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}'
]

IGNORED_URL_PATTERNS = [
    r'^https?://(www\.)?springframework\.org/schema(?:/.*)?',
    r'^https?://(www\.)?springframework\.org/.*\.xsd',
    r'^https?://(www\.)?w3\.org/.*',
    r'^https?://(www\.)?maven\.apache\.org/(POM|xsd)/.*',
    r'^https?://(www\.)?apache\.org/licenses/.*',
    r'^https?://(www\.)?eclipse\.org/(jetty|legal)/.*',
    r'^https?://(www\.)?osgi\.org/xmlns/.*',
    r'^https?://(www\.)?cxf\.apache\.org/.*',
    r'^https?://(www\.)?camel\.apache\.org/schema(?:/.*)?',
    r'^https?://(www\.)?aries\.apache\.org/blueprint/xmlns/.*',
    r'^https?://(www\.)?github\.com/FasterXML/.*',
    r'^https?://(www\.)?issues\.jboss\.org/.*',
    r'^https?://(www\.)?cxf\.apache\.org$',
    r'^https?://(www\.)?xmlns\.jcp\.org/.*',
    r'^http://java\.sun\.com/.*',
]

IGNORED_URL_REGEX = re.compile('|'.join(IGNORED_URL_PATTERNS), re.IGNORECASE)

KEYWORDS = re.compile('|'.join(SENSITIVE_PATTERNS), re.IGNORECASE)

findings = []

CFR_JAR_PATH = "cfr.jar"  # adjust if you use a different path

def check_requirements(use_trufflehog_requested=False):
    if shutil.which("java") is None:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Java runtime not found in PATH. Please install Java and try again.")
        print("You can download Java from https://adoptium.net/ or https://www.oracle.com/java/technologies/javase-downloads.html")
        sys.exit(1)
    if not os.path.isfile(CFR_JAR_PATH):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} CFR decompiler JAR not found at '{CFR_JAR_PATH}'.")
        print("Download CFR from https://www.benf.org/other/cfr/ and place it in the script directory.")
        sys.exit(1)

    if use_trufflehog_requested:
        if shutil.which("trufflehog") is None:
            print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} TruffleHog not found in PATH. Falling back to regex-based scan.")
            return False
    return True

def has_class_files(jar_path):
    """
    Returns True if the JAR file contains any .class files, False otherwise.
    """
    try:
        with zipfile.ZipFile(jar_path, 'r') as jar:
            return any(name.endswith('.class') for name in jar.namelist())
    except zipfile.BadZipFile:
        print(f"[ERROR] {jar_path} is not a valid ZIP/JAR file.")
        return False

'''
def check_requirements():
    if shutil.which("java") is None:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Java runtime not found in PATH. Please install Java and try again.")
        print("You can download Java from https://adoptium.net/ or https://www.oracle.com/java/technologies/javase-downloads.html")
        sys.exit(1)
    if not os.path.isfile(CFR_JAR_PATH):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} CFR decompiler JAR not found at '{CFR_JAR_PATH}'.")
        print("Download CFR from https://www.benf.org/other/cfr/ and place it in the script directory.")
        sys.exit(1)
'''

def get_relative_path(file_path, temp_root):
    try:
        return str(Path(file_path).relative_to(temp_root))
    except ValueError:
        return str(file_path)

def get_derived_key(password: bytes, salt: bytes, count: int):
    key = password + salt
    for _ in range(count):
        m = hashlib.md5(key)
        key = m.digest()
    return key[:8], key[8:16]

def decrypt(msg: str, password: str) -> str:
    msg_bytes = base64.b64decode(msg)
    salt = msg_bytes[:8]
    enc_text = msg_bytes[8:]
    dk, iv = get_derived_key(password.encode(), salt, 1000)
    crypter = DES.new(dk, DES.MODE_CBC, iv)
    decrypted = crypter.decrypt(enc_text)
    # Remove PKCS5/7 padding (padding byte value = padding length)
    pad_len = decrypted[-1]
    if pad_len < 1 or pad_len > 8:
        # Bad padding length, fallback to no padding removal
        return decrypted.decode('utf-8', errors='ignore')
    return decrypted[:-pad_len].decode('utf-8', errors='ignore')

def encrypt(msg: str, password: str) -> str:
    salt = os.urandom(8)
    msg_bytes = msg.encode()
    pad_num = 8 - (len(msg_bytes) % 8)
    padding = bytes([pad_num] * pad_num)
    padded_msg = msg_bytes + padding
    dk, iv = get_derived_key(password.encode(), salt, 1000)
    crypter = DES.new(dk, DES.MODE_CBC, iv)
    enc_text = crypter.encrypt(padded_msg)
    result = salt + enc_text
    return base64.b64encode(result).decode('utf-8')

def decompile_single_class(class_path, output_dir, cfr_path):
    try:
        subprocess.run([
            "java", "-jar", cfr_path,
            "--outputdir", output_dir,
            class_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except Exception as e:
        return f"[WARN] Failed to decompile {class_path}: {e}"
    return None

def decompile_class_files(root_dir, cfr_path="cfr.jar", max_workers=4):
    if not os.path.isfile(cfr_path):
        print(f"{Fore.RED}[ERROR] CFR not found at {cfr_path}. Skipping decompilation.{Style.RESET_ALL}")
        return

    class_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".class"):
                class_files.append(os.path.join(root, file))

    if not class_files:
        return

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(decompile_single_class, path, os.path.dirname(path), cfr_path): path
            for path in class_files
        }
        for future in as_completed(futures):
            error = future.result()
            if error:
                print(f"{Fore.YELLOW}{error}{Style.RESET_ALL}")

def scan_with_trufflehog(path, source_package, temp_root):
    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", "--json", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        #print(result)
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                raw_line = data.get("Raw", "").split('\n')[0]

                # ✅ Skip known benign URLs
                if IGNORED_URL_REGEX.search(raw_line.strip()):
                    continue

                match = {
                    #'file': data.get("SourceMetadata", {}).get("Data", "unknown"),
                    'file': data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown"),
                    'line': raw_line,
                    'content': data.get("Raw", "N/A"),
                    'source_package': source_package
                }
                findings.append(match)

                highlighted_line = KEYWORDS.sub(
                    lambda m: f"{Fore.GREEN}{m.group(0)}{Style.RESET_ALL}", raw_line
                )
                match_file = get_relative_path(match['file'], temp_root)
                print(f"[{source_package}] /{match_file} → {highlighted_line}")
            except json.JSONDecodeError:
                continue
    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] TruffleHog failed: {e}{Style.RESET_ALL}")

def scan_file(file_path, source_package, temp_root):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for lineno, line in enumerate(f, start=1):
                if KEYWORDS.search(line):
                    # Extract URLs from the line
                    urls = re.findall(r'https?://[^\s"\'<>]+', line)
                    skip_line = False
                    for url in urls:
                        if IGNORED_URL_REGEX.match(url):
                            skip_line = True
                            break
                    if skip_line:
                        continue  # Skip this line because it only contains ignored URLs

                    # Your existing code continues here...
                    enc_match = re.search(r'password\s*=\s*ENC\(([^)]+)\)', line, re.IGNORECASE)
                    decrypted_value = None
                    if enc_match:
                        encrypted_value = enc_match.group(1)
                        try:
                            decrypted_value = decrypt(encrypted_value, "secret")
                        except Exception as e:
                            decrypted_value = f"[Decryption failed: {e}]"

                    match = {
                        'file': str(file_path),
                        'line': lineno,
                        'content': line.strip(),
                        'source_package': source_package
                    }
                    findings.append(match)

                    highlighted = KEYWORDS.sub(
                        lambda m: f"{Fore.GREEN}{m.group(0)}{Style.RESET_ALL}", line.strip())

                    relative_path = get_relative_path(file_path, temp_root)

                    print(f"[{source_package}] /{relative_path}:{lineno} → {highlighted}")

                    if decrypted_value is not None:
                        print(f"    {Fore.YELLOW}[Decrypted password using key='secret']: {decrypted_value}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] Failed to read {file_path}: {e}{Style.RESET_ALL}")

def scan_extracted_dir(root_dir, use_trufflehog, source_package, temp_root):
    if use_trufflehog:
        scan_with_trufflehog(root_dir, source_package, temp_root)
    else:
        for root, _, files in os.walk(root_dir):
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(('.properties', '.conf', '.txt', '.xml', '.yml', '.env', '.ini')):
                    scan_file(full_path, source_package, temp_root)

def extract_archive(archive_path, temp_root):
    try:
        with zipfile.ZipFile(archive_path, 'r') as z:
            extract_path = tempfile.mkdtemp(dir=temp_root)
            z.extractall(extract_path)
            return extract_path
    except zipfile.BadZipFile:
        print(f"{Fore.YELLOW}[WARN] Corrupt archive: {archive_path}{Style.RESET_ALL}")
        return None

def process_zip(zip_path, temp_root, use_trufflehog):
    extract_path = extract_archive(zip_path, temp_root)
    if extract_path:
        scan_extracted_dir(extract_path, use_trufflehog, source_package=str(zip_path.name), temp_root=temp_root)

def process_jar(jar_path, temp_root, use_trufflehog):
    if not quiet:
        print(f"[*] Processing .jar: {jar_path}")
    extract_path = extract_archive(jar_path, temp_root)
    if extract_path:
        if has_class_files(jar_path) == True:
            decompile_class_files(extract_path)  
        scan_extracted_dir(extract_path, use_trufflehog, source_package=str(jar_path.name), temp_root=temp_root)

def process_war(war_path, temp_root, use_trufflehog):
    if not quiet:
        print(f"[*] Processing .war: {war_path}")
    extract_path = extract_archive(war_path, temp_root)
    if extract_path:
        scan_extracted_dir(extract_path, use_trufflehog, source_package=str(war_path.name), temp_root=temp_root)

def save_output(path, format_type):
    if not findings:
        print(f"{Fore.YELLOW}[!] No sensitive matches found.{Style.RESET_ALL}")
        return

    ext_map = {"txt": ".txt", "json": ".json", "csv": ".csv"}
    expected_ext = ext_map[format_type]
    if not path.endswith(expected_ext):
        path += expected_ext

    with open(path, 'w', encoding='utf-8', newline='') as f:
        if format_type == "txt":
            for item in findings:
                f.write(f"{item['file']}:{item['line']} → {item['content']}\n")
        elif format_type == "json":
            json.dump(findings, f, indent=2)
        elif format_type == "csv":
            writer = csv.DictWriter(f, fieldnames=['file', 'line', 'content'])
            writer.writeheader()
            writer.writerows(findings)

    print(f"{Fore.CYAN}[*] Output written to {path} ({format_type}){Style.RESET_ALL}")

def main(loot_dir, output, format_type, keep_temp, analyze_types, use_trufflehog):
    print(f"[*] Scanning {', '.join(analyze_types)} files in {loot_dir}...")

    shared_temp_path = None
    if keep_temp:
        shared_temp_path = tempfile.mkdtemp()
        print(f"{Fore.YELLOW}[!] Temp files will be kept at: {shared_temp_path}{Style.RESET_ALL}")

    for file_path in Path(loot_dir).rglob("*"):
        suffix = file_path.suffix.lower().lstrip('.')
        if suffix not in analyze_types:
            continue

        if keep_temp:
            current_temp_root = shared_temp_path
        else:
            temp_dir = tempfile.TemporaryDirectory()
            current_temp_root = temp_dir.name

        try:
            if suffix == "zip":
                if not quiet:
                    print(f"[*] Processing .zip: {file_path}")
                process_zip(file_path, current_temp_root, use_trufflehog)
            elif suffix == "jar":
                process_jar(file_path, current_temp_root, use_trufflehog)
            elif suffix == "war":
                process_war(file_path, current_temp_root, use_trufflehog)
        finally:
            if not keep_temp:
                temp_dir.cleanup()
            else:
                print(f"{Fore.YELLOW}[!] Kept temp for {file_path} in: {current_temp_root}{Style.RESET_ALL}")

    if output:
        save_output(output, format_type)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan .zip/.jar/.war files for sensitive data.")
    parser.add_argument("-d", "--directory", required=True, help="Directory containing archive files")
    parser.add_argument("-o", "--output", help="Path to save output (extension auto-added)")
    parser.add_argument("-f", "--format", choices=["txt", "json", "csv"], default="txt", help="Output format")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress status output; only show sensitive results")
    parser.add_argument("--keep-temp", action="store_true", help="Keep temporary extracted files (for debugging)")
    parser.add_argument("--use-trufflehog", action="store_true", help="Use TruffleHog instead of regex scan")
    parser.add_argument(
        "-t", "--types",
        nargs="+",
        choices=["zip", "jar", "war", "all"],
        default=["zip", "jar", "war", "all"],
        help="Specify which file types to analyze (default: all)"
    )
    args = parser.parse_args()

    # Check requirements, including trufflehog availability
    use_trufflehog = args.use_trufflehog
    trufflehog_available = check_requirements(use_trufflehog_requested=use_trufflehog)
    if use_trufflehog and not trufflehog_available:
        use_trufflehog = False  # fallback if not installed

    quiet = args.quiet
    if "all" in args.types:
        analyze_types = ["zip", "jar", "war"]
    else:
        analyze_types = args.types

    main(args.directory, args.output, args.format, args.keep_temp, analyze_types, args.use_trufflehog)
