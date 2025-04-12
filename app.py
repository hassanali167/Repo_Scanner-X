import gradio as gr
import requests
import os
import subprocess
import tempfile
import re
import shutil

# ------------------- GitHub Utilities -------------------

def verify_github_repo(repo_url, oauth_token=None):
    if not repo_url.startswith("https://github.com/"):
        return "❌ Invalid GitHub URL. Please enter a valid GitHub repository URL."
    
    repo_api_url = repo_url.replace("https://github.com/", "https://api.github.com/repos/")
    headers = {"Authorization": f"token {oauth_token}"} if oauth_token else {}

    response = requests.get(repo_api_url, headers=headers)
    
    if response.status_code == 200:
        return "✅ Repository is accessible."
    elif response.status_code == 404:
        return "❌ Repository not found. Check the URL."
    elif response.status_code == 401:
        return "🔑 Unauthorized! Check your OAuth token permissions."
    elif response.status_code == 403:
        return "🔒 Access Denied! You may have exceeded GitHub API rate limits."
    else:
        return f"⚠️ Error: {response.status_code} - {response.json().get('message', 'Unknown error')}"

# ------------------- Trivy Scan Logic -------------------

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
    print("[+] Running full Trivy scan...")
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
    return filename

# ------------------- Gradio Integration -------------------

def run_scan_interface(project_name, repo_url, oauth_token):
    status_msg = verify_github_repo(repo_url, oauth_token)
    if "❌" in status_msg or "🔒" in status_msg or "🔑" in status_msg:
        return status_msg, None
    
    try:
        repo_path, repo_name, temp_dir = clone_repository(repo_url, oauth_token)
        scan_result = scan_with_trivy(repo_path)
        report_file = save_scan_report(repo_name, scan_result)
        return f"📝 Project: {project_name}\n🔗 Repo: {repo_url}\n{status_msg}\n\n✅ Scan Completed!", report_file
    except Exception as e:
        return f"[!] Error during scan: {str(e)}", None
    finally:
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

# ------------------- Gradio UI -------------------


with gr.Blocks() as ui:
    gr.Markdown("# 🛡️ Git Vulnerability Scanner & AI Based Recommendation System")

    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="Enter project name")
        repo_url = gr.Textbox(label="GitHub Repository URL", placeholder="https://github.com/user/repo.git")

    oauth_token = gr.Textbox(label="OAuth Token (if private)", placeholder="Enter GitHub OAuth Token", type="password")

    verify_button = gr.Button("🔍 Verify Repository")
    repo_status_output = gr.Textbox(label="Repository Status", interactive=False)

    scan_button = gr.Button("🛠️ Run Scan")
    output = gr.Textbox(label="Scan Output", interactive=False)

    download_button = gr.File(label="Download Report", interactive=False)

    verify_button.click(verify_github_repo, inputs=[repo_url, oauth_token], outputs=repo_status_output)

    scan_button.click(run_scan_interface,
                      inputs=[project_name, repo_url, oauth_token],
                      outputs=[output, download_button])

ui.launch()
