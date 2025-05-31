# Utility functions for repository operations in Repo Scanner-X.
# Handles GitHub repo verification, cloning, and report generation.
# Includes helper functions for URL parsing and file management.


import re
import requests
import subprocess
import tempfile
import shutil
import uuid
import os
from typing import Tuple, List, Optional
from config import is_valid_github_url, is_valid_token

def get_repo_name(repo_url: str) -> str:
    match = re.search(r"/([^/]+?)(?:\.git)?$", repo_url)
    return match.group(1) if match else "scanned_repo"

def sanitize_project_name(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_\-]', '', name.strip())

def verify_github_repo(repo_url: str, oauth_token: str = None) -> str:
    if not is_valid_github_url(repo_url):
        return "❌ Invalid GitHub URL. Use: https://github.com/user/repo or .git"
    if oauth_token and not is_valid_token(oauth_token):
        return "❌ Invalid GitHub token format."
    
    headers = {"Authorization": f"Bearer {oauth_token}"} if oauth_token else {}
    api_url = repo_url.replace("https://github.com/", "https://api.github.com/repos/").rstrip(".git")
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            repo_data = response.json()
            visibility = repo_data.get("visibility", "unknown")
            return f"✅ Repository accessible! ({visibility} repository)"
        elif response.status_code == 404:
            if oauth_token:
                return "❌ Private repository not found or token lacks access. Ensure PAT has 'repo' scope."
            return "❌ Repository not found or private. Provide a valid PAT for private repositories."
        elif response.status_code == 403:
            return "⛔ Access denied. Check PAT permissions (requires 'repo' scope for private repos) or API rate limit."
        elif response.status_code == 401:
            return "🔐 Unauthorized: Invalid or expired PAT."
        return f"⚠️ Unexpected error: HTTP {response.status_code}"
    except requests.RequestException as e:
        return f"❌ Network error: {str(e)}"

def clone_repository(repo_url: str, token: Optional[str] = None) -> Tuple[str, str, str]:
    if not is_valid_github_url(repo_url):
        raise ValueError("Invalid GitHub URL format.")
    if token and not is_valid_token(token):
        raise ValueError("Invalid GitHub token format.")
    safe_url = repo_url
    if token:
        safe_url = repo_url.replace("https://", f"https://{token}@")
    temp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(["git", "clone", safe_url], cwd=temp_dir, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        err = e.stderr.replace(token, '[MASKED]') if token else e.stderr
        raise RuntimeError(f"Git clone failed: {err}")
    repo_name = get_repo_name(repo_url)
    return os.path.join(temp_dir, repo_name), repo_name, temp_dir

def extract_vulnerable_files(scan_output: str) -> List[str]:
    return sorted(set(re.findall(r"(/.*?):", scan_output)))

def save_report(repo_name: str, content: str, suffix: str) -> str:
    filename = f"{repo_name}_{uuid.uuid4().hex[:6]}_{suffix}"
    with open(filename, "w") as f:
        f.write(content)
    return filename

def fetch_repo_metadata(repo_url: str, token: Optional[str] = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    api_url = repo_url.replace("https://github.com/", "https://api.github.com/repos/").rstrip(".git")
    return requests.get(api_url, headers=headers, timeout=10).json()