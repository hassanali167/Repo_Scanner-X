# ai_analyzer.py
import requests
from trivy_scanner import extract_vulnerable_files
from constants import GROQ_API_KEY, GROQ_ENDPOINT, GROQ_MODEL

def analyze_with_ai(scan_report, repo_url, repo_name, repo_meta):
    vulnerable_files = extract_vulnerable_files(scan_report)
    file_list = "\n".join(f"- `{file}`" for file in vulnerable_files)

    prompt = f"""
You are a cybersecurity assistant. Read this vulnerability scan and respond **professionally**.

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
1. ⚡ Top 3 Critical Vulnerabilities
2. 🛠️ Remediation Steps
3. 🧠 Known Exploits / Attack Techniques
"""

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3
    }

    response = requests.post(GROQ_ENDPOINT, headers=headers, json=data)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]
