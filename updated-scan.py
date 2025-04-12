import os
import subprocess
import argparse
import tempfile
import re
import shutil



def get_repo_name(repo_url):
    repo_name_match = re.search(r"/([^/]+?)(?:\.git)?$", repo_url)
    return repo_name_match.group(1) if repo_name_match else "scanned_repo"

def clone_repository(repo_url, token=None):
    if token:
        if repo_url.startswith("https://github.com/"):
            repo_url = repo_url.replace("https://", f"https://{token}@")
        else:
            raise ValueError("Only HTTPS URLs are supported for private repositories with token.")
    
    temp_dir = tempfile.mkdtemp()
    print(f"[+] Cloning repo into: {temp_dir}")
    
    result = subprocess.run(["git", "clone", repo_url], cwd=temp_dir, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed:\n{result.stderr}")
    
    repo_name = get_repo_name(repo_url)
    repo_path = os.path.join(temp_dir, repo_name)
    return repo_path, repo_name, temp_dir

def scan_with_trivy(repo_path):
    """
    Trivy full scan: dependencies, secrets, code configs, and licenses.
    """
    print("[+] Running full Trivy scan on code and dependencies...")
    command = [
        "trivy", "fs",
        "--scanners", "vuln,secret,config,license",
        "--quiet",
        "--format", "table",
        repo_path
    ]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode not in [0, 5]:  # 5 = issues found
        raise RuntimeError(f"Trivy scan failed:\n{result.stderr}")
    
    return result.stdout

def save_scan_report(repo_name, report_data):
    filename = f"{repo_name}_full_scan_report.txt"
    with open(filename, "w") as f:
        f.write(report_data)
    print(f"[✓] Report saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Scan GitHub repo for vulnerabilities, secrets, and insecure code using Trivy.")
    parser.add_argument("--repo", required=True, help="GitHub repository URL")
    parser.add_argument("--token", help="GitHub token (for private repos)", default=None)
    args = parser.parse_args()

    try:
        repo_path, repo_name, temp_dir = clone_repository(args.repo, args.token)
        scan_result = scan_with_trivy(repo_path)
        save_scan_report(repo_name, scan_result)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
    finally:
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
