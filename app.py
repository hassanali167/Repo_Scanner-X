
import gradio as gr
import requests
import os
import subprocess
import tempfile
import re
import shutil
import uuid
import json
import datetime

# ------------------- CONFIG -------------------
SCAN_HISTORY = {}
PROJECT_TITLE = "Repo Scanner-X"
HEADING = "# Repo Scanner-X"
HEADING_ALT = "# 🛡️ Git Vulnerability Scanner and AI-based Recommendation System"
GROQ_API_KEY = "YOur Groq Api"
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama3-70b-8192"

# ------------------- Repo Utilities -------------------
def get_repo_name(repo_url):
    match = re.search(r"/([^/]+?)(?:\.git)?$", repo_url)
    return match.group(1) if match else "scanned_repo"

def verify_github_repo(repo_url, oauth_token=None):
    if not repo_url.startswith("https://github.com/"):
        return "❌ Invalid GitHub URL. Use: https://github.com/user/repo"

    headers = {"Authorization": f"token {oauth_token}"} if oauth_token else {}
    response = requests.get(repo_url.replace("https://github.com/", "https://api.github.com/repos/"), headers=headers)

    if response.status_code == 200:
        return "✅ Repository accessible!"
    elif response.status_code == 404:
        return "❌ Repo not found!"
    elif response.status_code == 403:
        return "⛔️ Access denied or API rate limit exceeded."
    elif response.status_code == 401:
        return "🔐 Unauthorized: Invalid token?"
    return f"⚠️ Unexpected error: {response.status_code}"

def clone_repository(repo_url, token=None):
    if token:
        repo_url = repo_url.replace("https://", f"https://{token}@")

    temp_dir = tempfile.mkdtemp()
    subprocess.run(["git", "clone", repo_url], cwd=temp_dir, capture_output=True, text=True, check=True)
    repo_name = get_repo_name(repo_url)
    return os.path.join(temp_dir, repo_name), repo_name, temp_dir

# ------------------- Trivy Scanner -------------------
def scan_with_trivy(repo_path):
    cmd = [
        "trivy", "fs",
        "--scanners", "vuln,secret,config,license",
        "--quiet",
        "--format", "table",
        repo_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in [0, 5]:  # 5 means vulnerabilities found
        raise RuntimeError(result.stderr)
    return result.stdout

def extract_vulnerable_files(scan_output):
    return sorted(set(re.findall(r"(/.*?):", scan_output)))

def save_report(repo_name, content, suffix):
    filename = f"{repo_name}_{uuid.uuid4().hex[:6]}_{suffix}"
    with open(filename, "w") as f:
        f.write(content)
    return filename

# ------------------- AI ANALYSIS -------------------
def analyze_with_ai(scan_report, repo_url, repo_name, repo_meta):
    vulnerable_files = extract_vulnerable_files(scan_report)
    file_list = "\n".join(f"- `{file}`" for file in vulnerable_files)

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

def fetch_repo_metadata(repo_url, token=None):
    headers = {"Authorization": f"token {token}"} if token else {}
    api_url = repo_url.replace("https://github.com/", "https://api.github.com/repos/")
    return requests.get(api_url, headers=headers).json()

# ------------------- Main Function -------------------
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

# ------------------- Gradio UI -------------------
with gr.Blocks(theme=gr.themes.Soft(), css="""
    .gr-button { 
        border-radius: 12px; 
        font-weight: bold; 
        padding: 12px;
        font-size: 18px;
        outline: none; /* Remove outline/focus border */
    }
    .gr-button-primary {
        background-color: #444444; /* Neutral Dark Gray */
        color: white;
    }
    .gr-button-secondary {
        background-color: #D3D3D3; /* Light Gray */
        color: black;
    }
    .gr-button:focus,
    .gr-button:active {
        outline: none; /* Remove the default blue outline/focus */
        box-shadow: none; /* Remove the blue blur around buttons when focused/active */
    }
    .gr-markdown { 
        color: #4A4A4A; 
        font-family: 'Arial', sans-serif; 
        font-size: 24px;
        font-weight: bold;
        text-align: center;
    }
    .gr-textbox { 
        background-color: #F9F9F9; /* Off-white */
        color: #333; /* Dark Text */
        font-family: 'Arial', sans-serif;
        font-size: 16px;
        padding: 10px;
    }
    .gr-file { 
        background-color: #032d3e; 
        color: white; 
        padding: 12px;
        font-size: 16px;
    }
    .gr-row { 
        justify-content: center; 
    }
    .gr-textbox, .gr-button { 
        margin-bottom: 15px;
    }

    .gr-markdown h1 {
        color: #444444;  /* Neutral title color */
        font-size: 28px;
        font-weight: bold;
        text-align: center;
    }
    .gr-markdown h3 {
        color: #777777;
        font-size: 22px;
        font-weight: normal;
        text-align: center;
    }
    """) as ui:

    gr.Markdown(f"{HEADING}\n{HEADING_ALT}")

    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="e.g., MyApp-V1")
        repo_url = gr.Textbox(label="GitHub Repo URL", placeholder="https://github.com/user/repo.git")
    token = gr.Textbox(label="OAuth Token (Optional)", type="password")

    verify_btn = gr.Button("🔍 Verify Repo", variant="secondary")
    repo_status = gr.Textbox(label="Repository Status", interactive=False)

    scan_btn = gr.Button("🛠️ Run Scan + AI Recommendation", variant="primary")
    output_msg = gr.Textbox(label="Status")

    gr.Markdown("### 📊 Trivy Scan Output")
    trivy_text = gr.Textbox(label="Trivy Report (Raw)", lines=10, interactive=False)

    gr.Markdown("### 🧠 AI Recommendation")
    ai_text = gr.Textbox(label="AI Analysis", lines=10, interactive=False)

    gr.Markdown("### 📁 Download Reports")
    with gr.Row():
        download_trivy = gr.Button("📄 Download Trivy Report")
        download_ai = gr.Button("📄 Download AI Report")

    scan_stats = gr.Textbox(label="Project Scan Stats", interactive=False)

    verify_btn.click(verify_github_repo, inputs=[repo_url, token], outputs=repo_status)

    scan_btn.click(run_scan,
                   inputs=[project_name, repo_url, token],
                   outputs=[output_msg, download_trivy, download_ai, trivy_text, ai_text, scan_stats])

ui.launch()
