# repo_utils.py
import os
import re
import tempfile
import subprocess
import requests

def get_repo_name(repo_url):
    match = re.search(r"/([^/]+?)(?:\.git)?$", repo_url)
    return match.group(1) if match else "scanned_repo"

def clone_repository(repo_url, token=None):
    if token:
        repo_url = repo_url.replace("https://", f"https://{token}@")
    temp_dir = tempfile.mkdtemp()
    subprocess.run(["git", "clone", repo_url], cwd=temp_dir, capture_output=True, text=True, check=True)
    repo_name = get_repo_name(repo_url)
    return os.path.join(temp_dir, repo_name), repo_name, temp_dir

def fetch_repo_metadata(repo_url, token=None):
    headers = {"Authorization": f"token {token}"} if token else {}
    api_url = repo_url.replace("https://github.com/", "https://api.github.com/repos/")
    return requests.get(api_url, headers=headers).json()
