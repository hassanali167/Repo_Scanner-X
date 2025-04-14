# git_verification.py
import requests

def verify_github_repo(repo_url, oauth_token=None):
    if not repo_url.startswith("https://github.com/"):
        return "❌ Invalid GitHub URL. Use: https://github.com/user/repo"

    headers = {"Authorization": f"token {oauth_token}"} if oauth_token else {}
    api_url = repo_url.replace("https://github.com/", "https://api.github.com/repos/")
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return "✅ Repository accessible!"
    elif response.status_code == 404:
        return "❌ Repo not found!"
    elif response.status_code == 403:
        return "⛔️ Access denied or API rate limit exceeded."
    elif response.status_code == 401:
        return "🔐 Unauthorized: Invalid token?"
    return f"⚠️ Unexpected error: {response.status_code}"
