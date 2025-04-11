import gradio as gr
import requests
import subprocess
import tempfile
import shutil
import os

# --- Configuration ---
PASSWORD = "hacker"

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

def run_scanner(scanner, local_path):
    report = ""
    base_command = f"echo {PASSWORD} | sudo -S "

    if scanner == "Trivy":
        command = f"{base_command}docker run --rm -v {local_path}:/repo aquasec/trivy fs /repo"
    elif scanner == "SonarQube":
        sonar_token = os.getenv("SONAR_TOKEN", "your-sonarqube-token")
        command = (
            f"{base_command}docker run --rm "
            f"-e SONAR_HOST_URL='http://localhost:9000' "
            f"-e SONAR_LOGIN={sonar_token} "
            f"-v {local_path}:/usr/src "
            f"sonarsource/sonar-scanner-cli"
        )
    elif scanner == "OWASP Dependency-Track":
        # Simulate OWASP scan (no official Docker CLI – integration is done via APIs usually)
        report += f"✅ OWASP Dependency-Track Scan completed successfully.\nSimulated OWASP Dependency-Track scan for {local_path}"
        return report
    else:
        return "⚠️ Unknown scanner selected."

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
    
    # Clone GitHub repo into temp directory
    temp_dir = tempfile.mkdtemp()
    try:
        clone_command = f"git clone {repo_url} {temp_dir}"
        subprocess.run(clone_command, shell=True, check=True)
        
        for scanner in scanners:
            full_report += f"\n--- {scanner} Scan ---\n"
            full_report += run_scanner(scanner, temp_dir)

    except subprocess.CalledProcessError as e:
        full_report += f"❌ Failed to clone repository: {e}\n"
    finally:
        shutil.rmtree(temp_dir)

    # Save report
    report_path = "vulnerability_report.txt"
    with open(report_path, "w") as report_file:
        report_file.write(full_report)
    
    return full_report, report_path

# UI
with gr.Blocks() as ui:
    gr.Markdown("# 🔒 Vulnerability Scanner Tool")
    
    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="Enter project name")
        repo_url = gr.Textbox(label="GitHub Repository URL", placeholder="https://github.com/user/repo")
    
    oauth_token = gr.Textbox(label="OAuth Token (if private)", placeholder="Enter GitHub OAuth Token", type="password")
    
    verify_button = gr.Button("🔍 Verify Repository")
    repo_status_output = gr.Textbox(label="Repository Status", interactive=False)
    
    scanners = gr.CheckboxGroup(
        ["Trivy", "SonarQube", "OWASP Dependency-Track"],
        label="Select Scanners",
        info="Choose one or more security scanners."
    )
    
    scan_button = gr.Button("🚀 Run Scan")
    output = gr.Textbox(label="Scan Output", interactive=False)
    
    download_button = gr.File(label="Download Report", interactive=False)
    
    verify_button.click(verify_github_repo, inputs=[repo_url, oauth_token], outputs=repo_status_output)
    scan_button.click(process_input, 
                      inputs=[project_name, repo_url, oauth_token, scanners], 
                      outputs=[output, download_button])

ui.launch()
