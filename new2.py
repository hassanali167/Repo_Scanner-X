import gradio as gr
import requests
import subprocess
import os
import shutil
import tempfile

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

def clone_repo(repo_url, token=None):
    tmp_dir = tempfile.mkdtemp()
    clone_url = repo_url
    if token:
        clone_url = repo_url.replace("https://", f"https://{token}@")
    
    result = subprocess.run(f"git clone {clone_url} {tmp_dir}", shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        shutil.rmtree(tmp_dir)
        return None, f"❌ Failed to clone repository: {result.stderr.strip()}"
    return tmp_dir, ""

def run_scanner(scanner, local_path, repo_name):
    report = ""
    
    if scanner == "Trivy":
        command = f"docker run --rm -v {local_path}:/repo aquasec/trivy fs /repo"
    elif scanner == "SonarQube":
        project_key = repo_name.replace("/", "_").lower()
        command = (
            f"docker run --rm -v {local_path}:/usr/src sonarsource/sonar-scanner-cli "
            f"-Dsonar.projectKey={project_key} -Dsonar.sources=/usr/src -Dsonar.host.url=http://localhost:9000 "
            f"-Dsonar.login=admin -Dsonar.password=admin"
        )
    elif scanner == "OWASP Dependency-Track":
        command = f"echo 'Simulated OWASP Dependency-Track scan for {local_path}'"
    else:
        return "❌ Unknown scanner selected."

    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    if process.returncode == 0:
        report += f"✅ {scanner} Scan completed successfully.\n"
        report += process.stdout.strip()
    else:
        report += f"❌ {scanner} Scan failed: {process.stderr.strip()}"
    return report

def process_input(project_name, repo_url, oauth_token, scanners):
    repo_status = verify_github_repo(repo_url, oauth_token)
    if "❌" in repo_status or "🔒" in repo_status or "🔑" in repo_status:
        return repo_status, ""

    full_report = f"📝 Project: {project_name}\n🔗 Repo: {repo_url}\n{repo_status}\n\n"
    
    local_path, clone_error = clone_repo(repo_url, oauth_token)
    if clone_error:
        return clone_error, ""

    try:
        repo_name = repo_url.split("github.com/")[-1].replace(".git", "")
        
        for scanner in scanners:
            full_report += f"\n--- {scanner} Scan ---\n"
            full_report += run_scanner(scanner, local_path, repo_name)
    finally:
        shutil.rmtree(local_path)

    report_path = "vulnerability_report.txt"
    with open(report_path, "w") as f:
        f.write(full_report)

    return full_report, report_path

# Gradio UI
with gr.Blocks() as ui:
    gr.Markdown("# 🔐 GitHub Vulnerability Scanner")
    
    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="Enter project name")
        repo_url = gr.Textbox(label="GitHub Repository URL", placeholder="https://github.com/user/repo.git")
    
    oauth_token = gr.Textbox(label="OAuth Token (if private)", placeholder="Enter GitHub OAuth Token", type="password")

    verify_button = gr.Button("🔍 Verify Repository")
    repo_status_output = gr.Textbox(label="Repository Status", interactive=False)

    scanners = gr.CheckboxGroup(["Trivy", "SonarQube", "OWASP Dependency-Track"], label="Select Scanners")

    scan_button = gr.Button("🚀 Run Scan")
    output = gr.Textbox(label="Scan Output", lines=20, interactive=False)
    download_button = gr.File(label="Download Report", interactive=False)

    verify_button.click(verify_github_repo, inputs=[repo_url, oauth_token], outputs=repo_status_output)
    scan_button.click(process_input, inputs=[project_name, repo_url, oauth_token, scanners], outputs=[output, download_button])

ui.launch()
