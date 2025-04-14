# main.py
import os
import shutil
import datetime

from constants import SCAN_HISTORY
from git_verification import verify_github_repo
from repo_utils import clone_repository, fetch_repo_metadata
from trivy_scanner import scan_with_trivy, save_report
from ai_analyzer import analyze_with_ai

def run_scan(project_name, repo_url, token):
    status = verify_github_repo(repo_url, token)
    if "❌" in status or "⛔" in status or "🔐" in status:
        return status, None, None, "", "", ""

    try:
        repo_meta = fetch_repo_metadata(repo_url, token)
        repo_path, repo_name, temp_dir = clone_repository(repo_url, token)
        scan_data = scan_with_trivy(repo_path)

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

        trivy_report = header + scan_data
        ai_recommendation = analyze_with_ai(scan_data, repo_url, repo_name, repo_meta)
        ai_report = header + ai_recommendation

        trivy_file = save_report(repo_name, trivy_report, "trivy.txt")
        ai_file = save_report(repo_name, ai_report, "ai.md")

        SCAN_HISTORY[project_name] = SCAN_HISTORY.get(project_name, 0) + 1

        return f"✅ Scan + AI Analysis Complete", trivy_file, ai_file, trivy_report, ai_recommendation, f"📊 Scans: {SCAN_HISTORY[project_name]}"
    except Exception as e:
        return f"❌ Error: {e}", None, None, "", "", ""
    finally:
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
