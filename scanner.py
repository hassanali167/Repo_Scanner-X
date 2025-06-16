# Core scanning logic for Repo Scanner-X.
# Performs Trivy scans and AI-based vulnerability analysis.
# Generates and saves Trivy and AI recommendation reports.

import subprocess
import requests
import datetime
import shutil
import os
import logging
from typing import Tuple, Dict, Optional
from config import GROQ_API_KEY, GROQ_ENDPOINT, GROQ_MODEL, SCAN_HISTORY
from utils import clone_repository, extract_vulnerable_files, save_report, fetch_repo_metadata, get_repo_name

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_trivy_installation() -> bool:
    """Check if Trivy is installed and accessible."""
    try:
        subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def scan_with_trivy(repo_path: str) -> str:
    """Run Trivy scan on the repository."""
    if not check_trivy_installation():
        raise RuntimeError("Trivy is not installed. Please install it first using setup.sh")
    
    logger.info(f"Running Trivy scan on: {repo_path}")
    cmd = [
        "trivy", "fs",
        "--scanners", "vuln,secret,config,license",
        "--quiet",
        "--format", "table",
        repo_path
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5-minute timeout
        logger.info(f"Trivy return code: {result.returncode}")
        if result.returncode not in [0, 5]:
            raise RuntimeError(f"Trivy scan failed: {result.stderr}")
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError("Trivy scan timed out after 5 minutes")
    except Exception as e:
        logger.error(f"Trivy scan failed: {str(e)}")
        raise

def summarize_findings(scan_output: str) -> str:
    """Summarize the scan findings."""
    vuln_count = scan_output.lower().count("vulnerability")
    secret_count = scan_output.lower().count("secret")
    misconfig_count = scan_output.lower().count("misconfiguration")
    license_count = scan_output.lower().count("license")
    summary = (f"**Summary:**\n"
               f"- Vulnerabilities: {vuln_count}\n"
               f"- Secrets: {secret_count}\n"
               f"- Misconfigurations: {misconfig_count}\n"
               f"- License Issues: {license_count}\n")
    logger.info(f"Scan summary: {summary}")
    return summary

def analyze_with_ai(scan_report: str, repo_url: str, repo_name: str, repo_meta: Dict) -> str:
    """Analyze scan results using AI."""
    if not GROQ_API_KEY:
        raise ValueError("GROQ_API_KEY is not set in environment variables")
    
    vulnerable_files = extract_vulnerable_files(scan_report)
    file_list = "\n".join(f"- `{file}`" for file in vulnerable_files)
    logger.info(f"Vulnerable files detected: {file_list}")

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

    try:
        logger.info("Sending request to Groq API...")
        response = requests.post(GROQ_ENDPOINT, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        logger.info(f"Groq API response status: {response.status_code}")
        return response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.Timeout:
        raise RuntimeError("AI analysis timed out after 30 seconds")
    except requests.exceptions.RequestException as e:
        logger.error(f"AI analysis failed: {str(e)}")
        raise RuntimeError(f"AI analysis failed: {str(e)}")

def run_scan(project_name: str, repo_url: str, token: str) -> Tuple[str, Optional[str], Optional[str], str, str, str]:
    """Run the complete scanning process."""
    from utils import sanitize_project_name, verify_github_repo
    
    logger.info(f"Starting scan for project: {project_name}, repo: {repo_url}")
    project_name = sanitize_project_name(project_name)
    status = verify_github_repo(repo_url, token)
    logger.info(f"Repo verification status: {status}")
    
    if "❌" in status or "⛔" in status or "🔐" in status:
        return status, None, None, "", "", ""

    temp_dir = None
    try:
        repo_meta = fetch_repo_metadata(repo_url, token)
        logger.info(f"Repo metadata fetched successfully")
        repo_path, repo_name, temp_dir = clone_repository(repo_url, token)
        logger.info(f"Cloned repo to: {repo_path}")
        
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
        logger.info(f"Scan completed, reports saved: {trivy_file}, {ai_file}")

        return f"✅ Scan + AI Analysis Complete", trivy_file, ai_file, trivy_report, ai_recommendation, f"📊 Scans: {SCAN_HISTORY[project_name]}"
    except Exception as e:
        err = str(e).replace(token, '[MASKED]') if token else str(e)
        logger.error(f"Scan error: {err}")
        return f"❌ Error: {err}", None, None, "", "", ""
    finally:
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temp directory: {temp_dir}")
            except Exception as e:
                logger.error(f"Failed to clean up temp directory: {str(e)}")