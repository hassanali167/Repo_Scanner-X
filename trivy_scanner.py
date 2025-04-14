# trivy_scanner.py
import subprocess
import re
import uuid

def scan_with_trivy(repo_path):
    cmd = [
        "trivy", "fs",
        "--scanners", "vuln,secret,config,license",
        "--quiet",
        "--format", "table",
        repo_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in [0, 5]:
        raise RuntimeError(result.stderr)
    return result.stdout

def extract_vulnerable_files(scan_output):
    return sorted(set(re.findall(r"(/.*?):", scan_output)))

def save_report(repo_name, content, suffix):
    filename = f"{repo_name}_{uuid.uuid4().hex[:6]}_{suffix}"
    with open(filename, "w") as f:
        f.write(content)
    return filename
