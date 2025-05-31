# Core scanning logic for Repo Scanner-X.
# Performs Trivy scans and AI-based vulnerability analysis.
# Generates and saves Trivy and AI recommendation reports.


import subprocess
import requests
import datetime
import shutil
import os  # Added import
from typing import Tuple, Dict, Optional
from config import GROQ_API_KEY, GROQ_ENDPOINT, GROQ_MODEL, SCAN_HISTORY
from utils import clone_repository, extract_vulnerable_files, save_report, fetch_repo_metadata, get_repo_name

def scan_with_trivy(repo_path: str) -> str:
    print(f"Running Trivy scan on: {repo_path}")  # Debug
    cmd = [
        "trivy", "fs",
        "--scanners", "vuln,secret,config,license",
        "--quiet",
        "--format", "table",
        repo_path
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"Trivy return code: {result.returncode}")  # Debug
        if result.returncode not in [0, 5]:
            raise RuntimeError(result.stderr)
        return result.stdout
    except Exception as e:
        print(f"Trivy scan failed: {str(e)}")  # Debug
        raise

def summarize_findings(scan_output: str) -> str:
    vuln_count = scan_output.lower().count("vulnerability")
    secret_count = scan_output.lower().count("secret")
    misconfig_count = scan_output.lower().count("misconfiguration")
    license_count = scan_output.lower().count("license")
    summary = (f"**Summary:**\n"
               f"- Vulnerabilities: {vuln_count}\n"
               f"- Secrets: {secret_count}\n"
               f"- Misconfigurations: {misconfig_count}\n"
               f"- License Issues: {license_count}\n")
    print(f"Scan summary: {summary}")  # Debug
    return summary

def analyze_with_ai(scan_report: str, repo_url: str, repo_name: str, repo_meta: Dict) -> str:
    vulnerable_files = extract_vulnerable_files(scan_report)
    file_list = "\n".join(f"- `{file}`" for file in vulnerable_files)
    print(f"Vulnerable files detected: {file_list}")  # Debug

    prompt = f"""
You are a cybersecurity assistant. Read this vulnerability scan and respond **professionally**.
Skip introductions like \"As an AI expert...\" and jump straight to the point.

✨ GitHub Repository Metadata:
- Repo Name: {repo_name}
- URL: {repo_url}
- Created: {repo_meta.get('created_at')}
- Updated: {repo_meta.get('updated_at')}
- Stars: {repo_meta.get('stargazers_count')}
- Forks: {repo_meta.get('forks_count')}
- Language: {repo_meta.get('language')}
- Owner: {repo_meta.get('owner', {}).get('login')}

☑️ Files with vulnerabilities:
{file_list}

⏰ Scan:
{scan_report}

Respond with:
1. ⚡ Top 3 Critical Vulnerabilities (include CVE links if possible)
2. 🛠️ Remediation Steps
3. 🧠 Known Exploits / Attack Techniques
"""

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3
    }

    print("Sending request to Groq API...")  # Debug
    response = requests.post(GROQ_ENDPOINT, headers=headers, json=data, timeout=10)
    print(f"Groq API response status: {response.status_code}")  # Debug
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]

def run_scan(project_name: str, repo_url: str, token: str) -> Tuple[str, Optional[str], Optional[str], str, str, str]:
    from utils import sanitize_project_name, verify_github_repo  # Moved here to avoid circular import
    print(f"Starting scan for project: {project_name}, repo: {repo_url}")  # Debug
    project_name = sanitize_project_name(project_name)
    status = verify_github_repo(repo_url, token)
    print(f"Repo verification status: {status}")  # Debug
    if "❌" in status or "⛔" in status or "🔐" in status:
        return status, None, None, "", "", ""

    try:
        repo_meta = fetch_repo_metadata(repo_url, token)
        print(f"Repo metadata: {repo_meta}")  # Debug
        repo_path, repo_name, temp_dir = clone_repository(repo_url, token)
        print(f"Cloned repo to: {repo_path}")  # Debug
        scan_data = scan_with_trivy(repo_path)

        summary = summarize_findings(scan_data)
        header = (
            f"\n\n✨ GitHub Repository Metadata:\n"
            f"- Repo Name: {repo_name}\n"
            f"- URL: {repo_url}\n"
            f"- Created: {repo_meta.get('created_at')}\n"
            f"- Updated: {repo_meta.get('updated_at')}\n"
            f"- Stars: {repo_meta.get('stargazers_count')}\n"
            f"- Forks: {repo_meta.get('forks_count')}\n"
            f"- Language: {repo_meta.get('language')}\n"
            f"- Owner: {repo_meta.get('owner', {}).get('login')}\n"
            f"- Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        trivy_report = summary + header + scan_data
        ai_recommendation = analyze_with_ai(scan_data, repo_url, repo_name, repo_meta)
        ai_report = summary + header + ai_recommendation

        trivy_file = save_report(repo_name, trivy_report, "trivy.txt")
        ai_file = save_report(repo_name, ai_report, "ai.md")

        SCAN_HISTORY[project_name] = SCAN_HISTORY.get(project_name, 0) + 1
        print(f"Scan completed, reports saved: {trivy_file}, {ai_file}")  # Debug

        return f"✅ Scan + AI Analysis Complete", trivy_file, ai_file, trivy_report, ai_recommendation, f"📊 Scans: {SCAN_HISTORY[project_name]}"
    except Exception as e:
        err = str(e).replace(token, '[MASKED]') if token else str(e)
        print(f"Scan error: {err}")  # Debug
        return f"❌ Error: {err}", None, None, "", "", ""
    finally:
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            print(f"Cleaned up temp directory: {temp_dir}")  # Debug